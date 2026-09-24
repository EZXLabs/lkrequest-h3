//! This module represents the shared state of the h3 connection

use std::{
    borrow::Cow,
    fmt,
    sync::{atomic::AtomicBool, Mutex, OnceLock},
    task::{Context, Poll, Waker},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;

use crate::{
    config::Settings,
    error::internal_error::ErrorOrigin,
    qpack::{self, Decoded, DecoderError},
};

struct QpackDecoderState {
    decoder: qpack::Decoder,
    pending_instructions: BytesMut,
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
    qpack_waiters: Mutex<Vec<Waker>>,
}

impl Default for SharedState {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SharedState {
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
            self.wake_qpack_waiters();
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
        &self,
        required: usize,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), ErrorOrigin>> {
        if let Some(error) = self.connection_error.get() {
            return Poll::Ready(Err(error.clone()));
        }

        if self.qpack_total_inserted() >= required {
            return Poll::Ready(Ok(()));
        }

        let mut waiters = self
            .qpack_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.qpack_total_inserted() >= required {
            return Poll::Ready(Ok(()));
        }
        if !waiters.iter().any(|waker| waker.will_wake(cx.waker())) {
            waiters.push(cx.waker().clone());
        }
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

    fn qpack_total_inserted(&self) -> usize {
        self.qpack_decoder
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .decoder
            .total_inserted()
    }

    fn wake_qpack_waiters(&self) {
        let waiters = std::mem::take(
            &mut *self
                .qpack_waiters
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for waker in waiters {
            waker.wake();
        }
    }
}

impl ConnectionState for SharedState {
    fn shared_state(&self) -> &SharedState {
        self
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
        self.shared_state().wake_qpack_waiters();
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
