//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    collections::VecDeque,
    fmt,
    sync::{atomic::AtomicBool, Arc, Mutex, OnceLock},
    task::{Context, Poll, Waker},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use tokio::sync::oneshot;

use crate::{
    config::Settings,
    error::internal_error::ErrorOrigin,
    qpack::{self, Decoded, DecoderError},
};

struct QpackDecoderState {
    decoder: qpack::Decoder,
    pending_instructions: BytesMut,
}

#[derive(Debug)]
struct QpackWaiterEntry {
    required: usize,
    waker: Option<Waker>,
}

#[derive(Debug)]
pub(crate) struct PendingPriorityUpdate {
    pub(crate) element_id: u64,
    pub(crate) bytes: Bytes,
    pub(crate) completed: oneshot::Sender<()>,
}

#[derive(Debug, Default)]
struct PriorityUpdateQueue {
    pending: VecDeque<PendingPriorityUpdate>,
    closed: bool,
}

impl fmt::Debug for QpackDecoderState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QpackDecoderState")
            .field("total_inserted", &self.decoder.total_inserted())
            .field("pending_instructions", &self.pending_instructions.len())
            .finish()
    }
}

#[derive(Debug)]
/// This struct represents the shared state of the h3 connection and the stream structs
pub struct SharedState {
    /// The settings, sent by the peer
    settings: OnceLock<Settings>,
    /// The connection error
    connection_error: OnceLock<ErrorOrigin>,
    /// The connection is closing
    closing: AtomicBool,
    /// Waker for the connection
    waker: AtomicWaker,
    /// Stateful QPACK decoder shared by the connection driver and request streams.
    qpack_decoder: Mutex<QpackDecoderState>,
    /// Request streams waiting for encoder instructions that have not arrived yet.
    qpack_waiters: Mutex<Vec<Option<QpackWaiterEntry>>>,
    /// Cancellable response readers waiting for the connection's terminal error.
    close_waiters: Mutex<Vec<Option<Waker>>>,
    #[cfg(test)]
    qpack_poll_gate: Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
    #[cfg(test)]
    close_poll_gate: Mutex<Option<std::sync::Arc<std::sync::Barrier>>>,
    priority_updates: Mutex<PriorityUpdateQueue>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SharedState {
    #[cfg(test)]
    pub(crate) fn close_waiters_unlocked(&self) -> bool {
        self.close_waiters.try_lock().is_ok()
    }

    #[cfg(test)]
    pub(crate) fn close_waiter_count(&self) -> usize {
        self.close_waiters
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }

    #[cfg(test)]
    pub(crate) fn qpack_waiter_count(&self) -> usize {
        self.qpack_waiters
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }

    pub(crate) fn new(qpack_max_table_capacity: u64) -> Self {
        Self {
            settings: OnceLock::new(),
            connection_error: OnceLock::new(),
            closing: AtomicBool::new(false),
            waker: AtomicWaker::new(),
            qpack_decoder: Mutex::new(QpackDecoderState {
                decoder: qpack::Decoder::new(
                    usize::try_from(qpack_max_table_capacity).unwrap_or(usize::MAX),
                ),
                pending_instructions: BytesMut::new(),
            }),
            qpack_waiters: Mutex::new(Vec::new()),
            close_waiters: Mutex::new(Vec::new()),
            #[cfg(test)]
            qpack_poll_gate: Mutex::new(None),
            #[cfg(test)]
            close_poll_gate: Mutex::new(None),
            priority_updates: Mutex::new(PriorityUpdateQueue::default()),
        }
    }

    pub(crate) fn process_qpack_encoder(
        &self,
        incoming: &mut BytesMut,
    ) -> Result<(), DecoderError> {
        let (inserted_before, inserted_after) = {
            let mut state = self
                .qpack_decoder
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let QpackDecoderState {
                decoder,
                pending_instructions,
            } = &mut *state;
            let inserted_before = decoder.total_inserted();
            let inserted_after = decoder.on_encoder_recv(incoming, pending_instructions)?;
            (inserted_before, inserted_after)
        };
        if inserted_after > inserted_before {
            self.wake_qpack_waiters(Some(inserted_after));
            self.waker.wake();
        }
        Ok(())
    }

    pub(crate) fn decode_qpack(
        &self,
        encoded: &mut Bytes,
        max_field_section_size: u64,
    ) -> Result<Decoded, DecoderError> {
        let state = self
            .qpack_decoder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let decoded = state.decoder.decode_header(encoded)?;
        if decoded.mem_size > max_field_section_size {
            return Err(DecoderError::HeaderTooLong(decoded.mem_size));
        }
        Ok(decoded)
    }

    pub(crate) fn poll_qpack_insert_count(
        self: &Arc<Self>,
        required: usize,
        cx: &mut Context<'_>,
        registration: &mut Option<QpackWaiter>,
    ) -> Poll<Result<(), ErrorOrigin>> {
        if let Some(error) = self.connection_error.get() {
            *registration = None;
            return Poll::Ready(Err(error.clone()));
        }

        if self.qpack_total_inserted() >= required {
            *registration = None;
            return Poll::Ready(Ok(()));
        }

        #[cfg(test)]
        if let Some(gate) = self.qpack_poll_gate.lock().unwrap().take() {
            gate.wait();
            gate.wait();
        }

        let next_waker = cx.waker().clone();
        let mut waiters = self
            .qpack_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(error) = self.connection_error.get() {
            drop(waiters);
            *registration = None;
            return Poll::Ready(Err(error.clone()));
        }
        if self.qpack_total_inserted() >= required {
            drop(waiters);
            *registration = None;
            return Poll::Ready(Ok(()));
        }
        let previous = if let Some(registration) = registration {
            let entry = waiters[registration.slot].as_mut().unwrap();
            entry.required = required;
            entry.waker.replace(next_waker)
        } else {
            let slot = waiters
                .iter()
                .position(Option::is_none)
                .unwrap_or(waiters.len());
            let entry = Some(QpackWaiterEntry {
                required,
                waker: Some(next_waker),
            });
            if slot == waiters.len() {
                waiters.push(entry);
            } else {
                waiters[slot] = entry;
            }
            *registration = Some(QpackWaiter {
                state: self.clone(),
                slot,
            });
            None
        };
        drop(waiters);
        drop(previous);
        Poll::Pending
    }

    pub(crate) fn queue_qpack_header_ack(&self, stream_id: u64) {
        let mut state = self
            .qpack_decoder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        qpack::ack_header(stream_id, &mut state.pending_instructions);
        self.waker.wake();
    }

    pub(crate) fn take_qpack_decoder_instructions(&self) -> Bytes {
        self.qpack_decoder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending_instructions
            .split()
            .freeze()
    }

    pub(crate) fn queue_priority_update(
        &self,
        element_id: u64,
        bytes: Bytes,
    ) -> oneshot::Receiver<()> {
        let (completed, receiver) = oneshot::channel();
        let mut queue = self
            .priority_updates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !queue.closed {
            queue.pending.push_back(PendingPriorityUpdate {
                element_id,
                bytes,
                completed,
            });
        }
        drop(queue);
        self.waker.wake();
        receiver
    }

    pub(crate) fn take_priority_update(&self) -> Option<PendingPriorityUpdate> {
        let mut queue = self
            .priority_updates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some(update) = queue.pending.pop_front() {
            if !update.completed.is_closed() {
                return Some(update);
            }
        }
        None
    }

    pub(crate) fn cancel_priority_updates(&self) {
        let mut queue = self
            .priority_updates
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queue.closed = true;
        queue.pending.clear();
    }

    fn qpack_total_inserted(&self) -> usize {
        self.qpack_decoder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .decoder
            .total_inserted()
    }

    fn wake_qpack_waiters(&self, inserted: Option<usize>) {
        let waiters: Vec<_> = self
            .qpack_waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
            .flatten()
            .filter(|entry| inserted.map_or(true, |count| entry.required <= count))
            .filter_map(|entry| entry.waker.take())
            .collect();
        for waker in waiters {
            waker.wake();
        }
    }

    pub(crate) fn poll_closed(
        self: &Arc<Self>,
        cx: &mut Context<'_>,
        registration: &mut Option<ConnectionCloseWaiter>,
    ) -> Poll<ErrorOrigin> {
        let next_waker = cx.waker().clone();
        let mut waiters = self.close_waiters.lock().unwrap_or_else(|e| e.into_inner());
        // Publication takes this same lock to drain registrations. Checking here
        // covers both close-before-register and close-during-register.
        if let Some(error) = self.connection_error.get() {
            return Poll::Ready(error.clone());
        }
        #[cfg(test)]
        if let Some(gate) = self.close_poll_gate.lock().unwrap().take() {
            gate.wait();
            gate.wait();
        }
        let previous = if let Some(registration) = registration {
            waiters[registration.slot].replace(next_waker)
        } else {
            let slot = waiters
                .iter()
                .position(Option::is_none)
                .unwrap_or(waiters.len());
            if slot == waiters.len() {
                waiters.push(Some(next_waker));
            } else {
                waiters[slot] = Some(next_waker);
            }
            *registration = Some(ConnectionCloseWaiter {
                state: self.clone(),
                slot,
            });
            None
        };
        drop(waiters);
        drop(previous);
        Poll::Pending
    }

    fn wake_close_waiters(&self) {
        let waiters: Vec<_> = self
            .close_waiters
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter_mut()
            .filter_map(Option::take)
            .collect();
        for waker in waiters {
            waker.wake();
        }
    }
}

/// Waking a QPACK reader leaves its slot reserved until the reader completes or
/// is cancelled. Insert notifications can recur, unlike terminal close events.
#[derive(Debug)]
pub(crate) struct QpackWaiter {
    state: Arc<SharedState>,
    slot: usize,
}

impl Drop for QpackWaiter {
    fn drop(&mut self) {
        let removed = {
            let mut waiters = self
                .state
                .qpack_waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let removed = waiters[self.slot].take();
            while waiters.last().is_some_and(Option::is_none) {
                waiters.pop();
            }
            removed
        };
        drop(removed);
    }
}

/// Owned by the current async receive operation, or by a raw polling stream.
/// Dropping a cancelled operation releases its task even if the stream survives.
#[derive(Debug)]
pub(crate) struct ConnectionCloseWaiter {
    state: Arc<SharedState>,
    slot: usize,
}

impl Drop for ConnectionCloseWaiter {
    fn drop(&mut self) {
        let removed = {
            let mut waiters = self
                .state
                .close_waiters
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let removed = waiters.get_mut(self.slot).and_then(Option::take);
            while waiters.last().is_some_and(Option::is_none) {
                waiters.pop();
            }
            removed
        };
        drop(removed);
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
    }
}

#[cfg(test)]
mod qpack_waiter_tests {
    use super::*;
    use crate::error::{internal_error::InternalConnectionError, Code};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct WakeCount(AtomicUsize);
    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn insert(state: &SharedState) {
        let mut headers = http::HeaderMap::new();
        headers.insert("x-dynamic", "retained".parse().unwrap());
        let (_, instructions) = qpack::encode_dynamic_for_test(
            0,
            crate::proto::headers::Header::response(http::StatusCode::OK, headers),
        );
        state
            .process_qpack_encoder(&mut BytesMut::from(instructions.as_ref()))
            .unwrap();
    }

    #[test]
    fn qpack_insert_wake_reserves_slot_until_its_token_is_dropped() {
        let state = Arc::new(SharedState::new(4096));
        let first_wakes = Arc::new(WakeCount::default());
        let second_wakes = Arc::new(WakeCount::default());
        let first_waker = Waker::from(first_wakes.clone());
        let second_waker = Waker::from(second_wakes.clone());
        let mut first = None;
        let mut second = None;
        assert!(state
            .poll_qpack_insert_count(1, &mut Context::from_waker(&first_waker), &mut first)
            .is_pending());
        insert(&state);
        assert_eq!(first_wakes.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.qpack_waiter_count(),
            1,
            "the notified token still owns its slot"
        );
        assert!(state
            .poll_qpack_insert_count(2, &mut Context::from_waker(&second_waker), &mut second)
            .is_pending());
        assert_eq!(state.qpack_waiter_count(), 2);
        drop(first);
        assert_eq!(state.qpack_waiter_count(), 1);
        insert(&state);
        assert_eq!(state.qpack_total_inserted(), 2);
        assert_eq!(second_wakes.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            state.poll_qpack_insert_count(2, &mut Context::from_waker(&second_waker), &mut second),
            Poll::Ready(Ok(()))
        ));
        assert!(second.is_none());
        assert_eq!(state.qpack_waiter_count(), 0);
    }

    #[test]
    fn qpack_terminal_error_wakes_all_counts_and_unregisters() {
        let state = Arc::new(SharedState::new(4096));
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let mut first = None;
        let mut second = None;
        assert!(state
            .poll_qpack_insert_count(1, &mut Context::from_waker(&waker), &mut first)
            .is_pending());
        assert!(state
            .poll_qpack_insert_count(10, &mut Context::from_waker(&waker), &mut second)
            .is_pending());
        state.set_conn_error(
            InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "terminal QPACK wait".to_string(),
            )
            .into(),
        );
        assert_eq!(wakes.0.load(Ordering::SeqCst), 2);
        assert!(matches!(
            state.poll_qpack_insert_count(1, &mut Context::from_waker(&waker), &mut first),
            Poll::Ready(Err(_))
        ));
        assert!(matches!(
            state.poll_qpack_insert_count(10, &mut Context::from_waker(&waker), &mut second),
            Poll::Ready(Err(_))
        ));
        let mut late = None;
        assert!(matches!(
            state.poll_qpack_insert_count(1, &mut Context::from_waker(&waker), &mut late),
            Poll::Ready(Err(_))
        ));
        assert!(late.is_none());
        assert_eq!(state.qpack_waiter_count(), 0);
    }

    struct ReentrantDrop {
        state: std::sync::Weak<SharedState>,
        observed: Arc<AtomicUsize>,
    }
    impl std::task::Wake for ReentrantDrop {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for ReentrantDrop {
        fn drop(&mut self) {
            let state = self.state.upgrade().unwrap();
            self.observed.store(
                if state.qpack_waiters.try_lock().is_ok() {
                    1
                } else {
                    2
                },
                Ordering::SeqCst,
            );
        }
    }

    #[test]
    fn qpack_replacement_and_cancellation_drop_wakers_outside_lock() {
        for replace in [false, true] {
            let state = Arc::new(SharedState::new(4096));
            let observed = Arc::new(AtomicUsize::new(0));
            let waker = Waker::from(Arc::new(ReentrantDrop {
                state: Arc::downgrade(&state),
                observed: observed.clone(),
            }));
            let mut registration = None;
            assert!(state
                .poll_qpack_insert_count(1, &mut Context::from_waker(&waker), &mut registration)
                .is_pending());
            drop(waker);
            if replace {
                assert!(state
                    .poll_qpack_insert_count(
                        1,
                        &mut Context::from_waker(futures_util::task::noop_waker_ref()),
                        &mut registration
                    )
                    .is_pending());
            }
            drop(registration);
            assert_eq!(
                observed.load(Ordering::SeqCst),
                1,
                "custom waker destructor must run with an unlocked registry"
            );
            assert_eq!(state.qpack_waiter_count(), 0);
        }
    }

    #[test]
    fn qpack_insert_between_check_and_registration_is_observed() {
        let state = Arc::new(SharedState::new(4096));
        let gate = Arc::new(std::sync::Barrier::new(2));
        *state.qpack_poll_gate.lock().unwrap() = Some(gate.clone());
        let reader = state.clone();
        let polled = std::thread::spawn(move || {
            reader.poll_qpack_insert_count(
                1,
                &mut Context::from_waker(futures_util::task::noop_waker_ref()),
                &mut None,
            )
        });
        gate.wait();
        insert(&state);
        gate.wait();
        assert!(matches!(polled.join().unwrap(), Poll::Ready(Ok(()))));
        assert_eq!(state.qpack_waiter_count(), 0);
    }
}

#[cfg(test)]
mod close_wait_tests {
    use super::*;
    use crate::error::{internal_error::InternalConnectionError, Code};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier,
    };

    #[derive(Default)]
    struct WakeCount(AtomicUsize);

    impl std::task::Wake for WakeCount {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn terminal_error() -> ErrorOrigin {
        InternalConnectionError::new(Code::H3_INTERNAL_ERROR, "closed".to_string()).into()
    }

    struct ReentrantWakerDrop {
        state: std::sync::Weak<SharedState>,
        locked: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl std::task::Wake for ReentrantWakerDrop {
        fn wake(self: Arc<Self>) {}
    }

    impl Drop for ReentrantWakerDrop {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
            if let Some(state) = self.state.upgrade() {
                self.locked
                    .store(state.close_waiters.try_lock().is_err(), Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn replacing_close_waker_drops_previous_outside_registry_lock() {
        let state = Arc::new(SharedState::default());
        let locked = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let old = Waker::from(Arc::new(ReentrantWakerDrop {
            state: Arc::downgrade(&state),
            locked: locked.clone(),
            dropped: dropped.clone(),
        }));
        let mut registration = None;
        assert!(state
            .poll_closed(&mut Context::from_waker(&old), &mut registration)
            .is_pending());
        drop(old);
        assert!(state
            .poll_closed(
                &mut Context::from_waker(futures_util::task::noop_waker_ref()),
                &mut registration
            )
            .is_pending());
        assert!(!locked.load(Ordering::SeqCst));
        assert!(dropped.load(Ordering::SeqCst));
        drop(registration);
        assert!(state.close_waiters.lock().unwrap().is_empty());
    }

    #[test]
    fn cancelled_close_wait_releases_waker_and_live_waiters_all_wake() {
        let state = Arc::new(SharedState::default());
        let mut first = None;
        let mut second = None;
        let cancelled = Arc::new(WakeCount::default());
        let live = Arc::new(WakeCount::default());
        let cancelled_waker = Waker::from(cancelled.clone());
        let live_waker = Waker::from(live.clone());
        assert!(state
            .poll_closed(&mut Context::from_waker(&cancelled_waker), &mut first)
            .is_pending());
        assert!(state
            .poll_closed(&mut Context::from_waker(&live_waker), &mut second)
            .is_pending());
        drop(cancelled_waker);
        assert_eq!(Arc::strong_count(&cancelled), 2);
        drop(first.take());
        assert_eq!(Arc::strong_count(&cancelled), 1);
        let resumed = Arc::new(WakeCount::default());
        let resumed_waker = Waker::from(resumed.clone());
        assert!(state
            .poll_closed(&mut Context::from_waker(&resumed_waker), &mut first)
            .is_pending());
        state.set_conn_error(terminal_error());
        assert_eq!(cancelled.0.load(Ordering::SeqCst), 0);
        assert_eq!(live.0.load(Ordering::SeqCst), 1);
        assert_eq!(resumed.0.load(Ordering::SeqCst), 1);
        assert!(state
            .poll_closed(&mut Context::from_waker(&live_waker), &mut second)
            .is_ready());
        let mut after_close = None;
        assert!(state
            .poll_closed(&mut Context::from_waker(&live_waker), &mut after_close)
            .is_ready());
        assert!(after_close.is_none());
        drop(first);
        drop(second);
        assert!(state.close_waiters.lock().unwrap().is_empty());
    }

    #[test]
    fn close_during_registration_wakes_and_preserves_first_error() {
        let state = Arc::new(SharedState::default());
        let gate = Arc::new(Barrier::new(2));
        *state.close_poll_gate.lock().unwrap() = Some(gate.clone());
        let wakes = Arc::new(WakeCount::default());
        let waker = Waker::from(wakes.clone());
        let reader = state.clone();
        let polled = std::thread::spawn(move || {
            let mut registration = None;
            assert!(reader
                .poll_closed(&mut Context::from_waker(&waker), &mut registration)
                .is_pending());
            registration
        });
        gate.wait();
        let closer = state.clone();
        let (published, observed) = std::sync::mpsc::channel();
        let closed = std::thread::spawn(move || {
            assert!(closer.connection_error.set(terminal_error()).is_ok());
            published.send(()).unwrap();
            closer.wake_close_waiters();
        });
        observed.recv().unwrap();
        gate.wait();
        let registration = polled.join().unwrap();
        closed.join().unwrap();
        assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
        let error = state.set_conn_error(
            InternalConnectionError::new(Code::H3_NO_ERROR, "later".to_string()).into(),
        );
        assert!(matches!(error, ErrorOrigin::Internal(error) if error.message == "closed"));
        drop(registration);
        assert!(state.close_waiters.lock().unwrap().is_empty());
    }

    #[test]
    fn qpack_close_between_initial_check_and_registration_is_not_lost() {
        let state = Arc::new(SharedState::default());
        let gate = Arc::new(Barrier::new(2));
        *state.qpack_poll_gate.lock().unwrap() = Some(gate.clone());
        let reader = state.clone();
        let polled = std::thread::spawn(move || {
            reader.poll_qpack_insert_count(
                1,
                &mut Context::from_waker(futures_util::task::noop_waker_ref()),
                &mut None,
            )
        });
        gate.wait();
        state.set_conn_error(
            InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "gated connection close".to_string(),
            )
            .into(),
        );
        gate.wait();
        assert!(matches!(polled.join().unwrap(), Poll::Ready(Err(_))));
        assert!(state.qpack_waiters.lock().unwrap().is_empty());
    }
}

#[cfg(test)]
mod priority_update_tests {
    use super::*;

    #[tokio::test]
    async fn priority_update_queue_preserves_order_and_flush_acknowledgements() {
        let state = SharedState::default();
        let first = state.queue_priority_update(0, Bytes::from_static(b"first"));
        let second = state.queue_priority_update(4, Bytes::from_static(b"second"));
        let pending = state.take_priority_update().unwrap();
        assert_eq!(pending.bytes, b"first"[..]);
        assert_eq!(pending.element_id, 0);
        pending.completed.send(()).unwrap();
        assert_eq!(first.await, Ok(()));
        let pending = state.take_priority_update().unwrap();
        assert_eq!(pending.bytes, b"second"[..]);
        assert_eq!(pending.element_id, 4);
        pending.completed.send(()).unwrap();
        assert_eq!(second.await, Ok(()));
        assert!(state.take_priority_update().is_none());
    }

    #[tokio::test]
    async fn priority_update_queue_releases_cancelled_and_closed_waiters() {
        let state = SharedState::default();
        drop(state.queue_priority_update(0, Bytes::from_static(b"cancelled")));
        assert!(state.take_priority_update().is_none());
        let queued = state.queue_priority_update(4, Bytes::from_static(b"queued"));
        state.cancel_priority_updates();
        assert!(queued.await.is_err());
        let after_close = state.queue_priority_update(8, Bytes::from_static(b"late"));
        assert!(
            after_close.await.is_err(),
            "driver-drop/queue race must not hang"
        );
        assert!(state.take_priority_update().is_none());
    }
}

/// This trait can be implemented for all types which have a shared state
pub trait ConnectionState {
    /// Get the shared state
    fn shared_state(&self) -> &SharedState;
    /// Get the connection error if the connection is in error state because of another task
    ///
    /// Return the error as an Err variant if it is set in order to allow using ? in the calling function
    fn get_conn_error(&self) -> Option<ErrorOrigin> {
        self.shared_state().connection_error.get().cloned()
    }

    /// tries to set the connection error
    fn set_conn_error(&self, error: ErrorOrigin) -> ErrorOrigin {
        let err = self
            .shared_state()
            .connection_error
            .get_or_init(move || error);
        self.shared_state().wake_qpack_waiters(None);
        self.shared_state().wake_close_waiters();
        err.clone()
    }

    /// set the connection error and wake the connection
    fn set_conn_error_and_wake<T: Into<ErrorOrigin>>(&self, error: T) -> ErrorOrigin {
        let err = self.set_conn_error(error.into());
        self.waker().wake();
        err
    }

    /// Get the settings
    fn settings(&self) -> Cow<'_, Settings> {
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# Each endpoint SHOULD use
        //# these initial values to send messages before the peer's SETTINGS
        //# frame has arrived, as packets carrying the settings can be lost or
        //# delayed.
        self.shared_state()
            .settings
            .get()
            .map(Cow::Borrowed)
            .unwrap_or_default()
    }
    /// Set the connection to closing
    fn set_closing(&self) {
        self.shared_state()
            .closing
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Check if the connection is closing
    fn is_closing(&self) -> bool {
        self.shared_state()
            .closing
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    /// Set the settings
    fn set_settings(&self, settings: Settings) {
        let _ = self.shared_state().settings.set(settings);
    }

    /// Returns the waker for the connection
    fn waker(&self) -> &AtomicWaker {
        &self.shared_state().waker
    }
}
