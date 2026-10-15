use bytes::Buf;
use futures_util::{future, ready, task::AtomicWaker};
use http::{HeaderMap, Response};
use quic::StreamId;
#[cfg(feature = "tracing")]
use tracing::instrument;

use crate::{
    connection::{self},
    error::{
        connection_error_creators::{convert_to_connection_error, CloseStream},
        internal_error::InternalConnectionError,
        Code, StreamError,
    },
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::{self},
    shared_state::{ConnectionCloseWaiter, ConnectionState, QpackWaiter, SharedState},
};
use std::{
    convert::TryFrom,
    sync::{Arc, Weak},
    task::{Context, Poll, Wake, Waker},
};

struct WeakTerminalWake(Weak<AtomicWaker>);

impl Wake for WeakTerminalWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if let Some(task) = self.0.upgrade() {
            task.wake();
        }
    }
}

struct TerminalWake {
    task: Arc<AtomicWaker>,
    observer: Waker,
}

impl TerminalWake {
    fn new() -> Self {
        let task = Arc::new(AtomicWaker::new());
        let observer = Waker::from(Arc::new(WeakTerminalWake(Arc::downgrade(&task))));
        Self { task, observer }
    }
}

/// Manage request bodies transfer, response and trailers.
///
/// Once a request has been sent via [`crate::client::SendRequest::send_request()`], a response can be awaited by calling
/// [`RequestStream::recv_response()`]. A body for this request can be sent with [`RequestStream::send_data()`], then the request
/// shall be completed by either sending trailers with  [`RequestStream::finish()`].
///
/// After receiving the response's headers, it's body can be read by [`RequestStream::recv_data()`] until it returns
/// `None`. Then the trailers will eventually be available via [`RequestStream::recv_trailers()`].
///
/// TODO: If data is polled before the response has been received, an error will be thrown.
///
/// TODO: If trailers are polled but the body hasn't been fully received, an UNEXPECT_FRAME error will be
/// thrown
///
/// Whenever the client wants to cancel this request, it can call [`RequestStream::stop_sending()`], which will
/// put an end to any transfer concerning it.
///
/// # Examples
///
/// ```rust
/// # use h3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # use tokio::io::AsyncWriteExt;
/// # async fn doc<T,B>(mut req_stream: RequestStream<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::RecvStream,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Receive the response
/// let response = req_stream.recv_response().await?;
/// // Receive the body
/// while let Some(mut chunk) = req_stream.recv_data().await? {
///     let mut out = tokio::io::stdout();
///     out.write_all_buf(&mut chunk).await?;
///     out.flush().await?;
/// }
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`recv_response()`]: #method.recv_response
/// [`recv_data()`]: #method.recv_data
/// [`send_data()`]: #method.send_data
/// [`send_trailers()`]: #method.send_trailers
/// [`recv_trailers()`]: #method.recv_trailers
/// [`finish()`]: #method.finish
/// [`stop_sending()`]: #method.stop_sending
pub struct RequestStream<S, B> {
    pub(super) inner: connection::RequestStream<S, B>,
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.inner.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Receive the HTTP/3 response
    ///
    /// This should be called before trying to receive any data with [`recv_data()`].
    ///
    /// [`recv_data()`]: #method.recv_data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_response(&mut self) -> Result<Response<()>, StreamError> {
        let mut registration = self.inner.take_close_waiter();
        let mut qpack_registration = self.inner.take_qpack_waiter();
        future::poll_fn(|cx| {
            self.poll_recv_response_with_waiters(cx, &mut registration, &mut qpack_registration)
        })
        .await
    }

    fn poll_recv_response_with_waiters(
        &mut self,
        cx: &mut Context<'_>,
        registration: &mut Option<ConnectionCloseWaiter>,
        qpack_registration: &mut Option<QpackWaiter>,
    ) -> Poll<Result<Response<()>, StreamError>> {
        let frame = if let Some(encoded) = &self.inner.pending_response_headers {
            Frame::Headers(encoded.clone())
        } else {
            ready!(self.inner.poll_next_response_frame(cx, false, registration))?.ok_or_else(
                || {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Receipt of an invalid sequence of frames MUST be treated as a
                    //# connection error of type H3_FRAME_UNEXPECTED.
                    self.handle_connection_error_on_stream(InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        "Stream finished without receiving response headers".to_string(),
                    ))
                },
            )?
        };

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# A client MUST treat
        //# receipt of a PUSH_PROMISE frame that contains a larger push ID than
        //# the client has advertised as a connection error of H3_ID_ERROR.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# If a client
        //# receives a push ID that has already been promised and detects a
        //# mismatch, it MUST respond with a connection error of type
        //# H3_GENERAL_PROTOCOL_ERROR.

        let encoded = if let Frame::Headers(encoded) = frame {
            encoded
        } else {
            //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
            //# Receipt of an invalid sequence of frames MUST be treated as a
            //# connection error of type H3_FRAME_UNEXPECTED.

            return Poll::Ready(Err(self.handle_connection_error_on_stream(
                InternalConnectionError::new(
                    Code::H3_FRAME_UNEXPECTED,
                    "First response frame is not headers".to_string(),
                ),
            )));
        };

        // The stream owns a blocked field section so dropping this receive
        // future cannot consume a response that has not been decoded yet.
        self.inner.pending_response_headers = Some(encoded.clone());
        let stream_id = self.inner.stream.id().into_inner();
        let decoded = loop {
            let mut candidate = encoded.clone();
            match self
                .inner
                .conn_state
                .decode_qpack(&mut candidate, self.inner.max_field_section_size)
            {
                //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
                //# An HTTP/3 implementation MAY impose a limit on the maximum size of
                //# the message header it will accept on an individual HTTP message.
                Err(qpack::DecoderError::HeaderTooLong(cancel_size)) => {
                    self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                    *qpack_registration = None;
                    return Poll::Ready(Err(StreamError::HeaderTooBig {
                        actual_size: cancel_size,
                        max_size: self.inner.max_field_section_size,
                    }));
                }
                Err(qpack::DecoderError::MissingRefs(required)) => {
                    match self.inner.conn_state.poll_qpack_insert_count(
                        required,
                        cx,
                        qpack_registration,
                    ) {
                        Poll::Ready(Ok(())) => continue,
                        Poll::Ready(Err(error)) => {
                            self.inner.pending_response_headers = None;
                            return Poll::Ready(Err(StreamError::ConnectionError(
                                convert_to_connection_error(error),
                            )));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Ok(decoded) => {
                    if decoded.dyn_ref {
                        self.inner.conn_state.queue_qpack_header_ack(stream_id);
                    }
                    break decoded;
                }
                Err(error) => {
                    self.inner.pending_response_headers = None;
                    *qpack_registration = None;
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError {
                            code: Code::QPACK_DECOMPRESSION_FAILED,
                            message: format!("Failed to decode headers: {error}"),
                        },
                    )));
                }
            }
        };
        self.inner.pending_response_headers = None;
        *qpack_registration = None;

        let qpack::Decoded { fields, .. } = decoded;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        //# Malformed requests or responses that are
        //# detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        //# Clients MUST NOT
        //# accept a malformed response.
        let (status, headers) = Header::try_from(fields)
            .map_err(|_e| {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })?
            .into_response_parts()
            .map_err(|_e| {
                self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })?;
        let mut resp = Response::new(());
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        *resp.version_mut() = http::Version::HTTP_3;

        Poll::Ready(Ok(resp))
    }

    /// Receive some of the response body.
    ///
    /// This returns a chunk of the response body, or `None` if the response body is finished.
    // TODO what if called before recv_response ?
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf>, StreamError> {
        let mut registration = self.inner.take_close_waiter();
        future::poll_fn(|cx| self.inner.poll_recv_data_with_waiter(cx, &mut registration)).await
    }

    /// Receive some of the response body.
    ///
    /// This returns a chunk of the response body, or `None` if the response body is finished.
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        self.inner.poll_recv_data(cx)
    }

    /// Receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        let mut registration = self.inner.take_close_waiter();
        let mut qpack_registration = self.inner.take_qpack_waiter();
        let result = future::poll_fn(|cx| {
            self.inner.poll_recv_trailers_with_waiter(
                cx,
                &mut registration,
                &mut qpack_registration,
            )
        })
        .await;
        if matches!(result, Err(StreamError::HeaderTooBig { .. })) {
            self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        result
    }

    /// Poll receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let res = self.inner.poll_recv_trailers(cx);
        if let Poll::Ready(Err(StreamError::HeaderTooBig { .. })) = &res {
            self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        res
    }

    /// Tell the peer to stop sending into the underlying QUIC stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        // TODO take by value to prevent any further call as this request is cancelled
        // rename `cancel()` ?
        self.inner.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }

    /// Whether this stream was created in 0-RTT mode.
    ///
    /// This describes the stream's origin, not the connection's current packet
    /// encryption phase; it remains true after the handshake completes.
    pub fn is_0rtt(&self) -> bool
    where
        S: quic::Is0rtt,
    {
        self.inner.stream.is_0rtt()
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStreamReset,
{
    /// Wait for a peer reset or connection error without consuming response data.
    ///
    /// A completed reset observer (for example after FIN) continues waiting for
    /// connection termination. Cancelling this future preserves buffered data
    /// and releases its task references. The transport may retain a weak wake
    /// entry; cancellation does not cancel the QUIC stream.
    pub async fn recv_terminal_error(&mut self) -> StreamError {
        let wake = TerminalWake::new();
        let mut registration = self.inner.take_close_waiter();
        future::poll_fn(|cx| {
            wake.task.register(cx.waker());
            let mut observer_cx = Context::from_waker(&wake.observer);
            self.inner
                .poll_recv_terminal_error(cx, &mut observer_cx, &mut registration)
        })
        .await
    }

    /// Receive one response field section while also observing peer termination.
    ///
    /// Ready response headers take precedence over termination, so callers can
    /// preserve informational/final response ordering. QPACK and connection
    /// registrations remain live across polls. Response body bytes are retained.
    pub async fn recv_response_or_terminal(&mut self) -> Result<Response<()>, StreamError> {
        let wake = TerminalWake::new();
        let mut header_registration = self.inner.take_close_waiter();
        let mut qpack_registration = self.inner.take_qpack_waiter();
        let mut terminal_registration = None;
        future::poll_fn(|cx| {
            wake.task.register(cx.waker());
            if let Poll::Ready(result) = self.poll_recv_response_with_waiters(
                cx,
                &mut header_registration,
                &mut qpack_registration,
            ) {
                return Poll::Ready(result);
            }
            let mut observer_cx = Context::from_waker(&wake.observer);
            let error = ready!(self.inner.poll_recv_terminal_error(
                cx,
                &mut observer_cx,
                &mut terminal_registration
            ));
            self.inner.pending_response_headers = None;
            Poll::Ready(Err(error))
        })
        .await
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        self.inner.send_data(buf).await
    }

    /// Stop a stream with an error code
    ///
    /// The code can be [`Code::H3_NO_ERROR`].
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the request.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.inner.send_trailers(trailers).await
    }

    /// End the request without trailers.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().await
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
    //= type=TODO
    //# Implementations SHOULD cancel requests by abruptly terminating any
    //# directions of a stream that are still open.  To do so, an
    //# implementation resets the sending parts of streams and aborts reading
    //# on the receiving parts of streams; see Section 2.4 of
    //# [QUIC-TRANSPORT].
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Split this stream into two halves that can be driven independently.
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.inner.split();
        (RequestStream { inner: send }, RequestStream { inner: recv })
    }
}

#[cfg(test)]
mod response_terminal_tests {
    use super::*;
    use crate::{frame::FrameStream, stream::BufRecvStream};
    use bytes::{Bytes, BytesMut};
    use std::{
        collections::VecDeque,
        future::Future,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
    };

    #[derive(Clone, Copy)]
    enum Observation {
        Pending,
        End,
        Reset(u64),
    }

    struct ObserverState {
        mode: Observation,
        waker: Option<Waker>,
        polls: usize,
    }

    struct TestRecv {
        chunks: VecDeque<Bytes>,
        observer: Arc<Mutex<ObserverState>>,
        reads: Arc<AtomicUsize>,
    }

    impl quic::RecvStream for TestRecv {
        type Buf = Bytes;
        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(self.chunks.pop_front()))
        }
        fn stop_sending(&mut self, _: u64) {}
        fn recv_id(&self) -> StreamId {
            StreamId::try_from(0).unwrap()
        }
    }

    impl quic::RecvStreamReset for TestRecv {
        fn poll_received_reset(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Option<u64>, quic::StreamErrorIncoming>> {
            let mut observer = self.observer.lock().unwrap();
            observer.polls += 1;
            match observer.mode {
                Observation::Pending => {
                    observer.waker = Some(cx.waker().clone());
                    Poll::Pending
                }
                Observation::End => Poll::Ready(Ok(None)),
                Observation::Reset(code) => Poll::Ready(Ok(Some(code))),
            }
        }
    }

    struct Fixture {
        stream: RequestStream<TestRecv, Bytes>,
        state: Arc<SharedState>,
        observer: Arc<Mutex<ObserverState>>,
        reads: Arc<AtomicUsize>,
    }

    impl Fixture {
        fn new(wire: Bytes, mode: Observation) -> Self {
            let state = Arc::new(SharedState::new(4096));
            let observer = Arc::new(Mutex::new(ObserverState {
                mode,
                waker: None,
                polls: 0,
            }));
            let reads = Arc::new(AtomicUsize::new(0));
            let chunks = if wire.is_empty() {
                VecDeque::new()
            } else {
                VecDeque::from([wire])
            };
            let recv = TestRecv {
                chunks,
                observer: observer.clone(),
                reads: reads.clone(),
            };
            let stream = RequestStream {
                inner: connection::RequestStream::new(
                    FrameStream::new(BufRecvStream::new(recv)),
                    u64::MAX,
                    state.clone(),
                    false,
                ),
            };
            Self {
                stream,
                state,
                observer,
                reads,
            }
        }
    }

    fn signal(observer: &Mutex<ObserverState>, mode: Observation) {
        let waker = {
            let mut observer = observer.lock().unwrap();
            observer.mode = mode;
            observer.waker.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn close(state: &SharedState) {
        state.set_conn_error(
            InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "terminal fixture close".to_string(),
            )
            .into(),
        );
    }

    #[derive(Default)]
    struct CountWake(AtomicUsize);
    impl Wake for CountWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn response_terminal_none_waits_for_close_without_consuming_prefetched_body() {
        let mut fixture = Fixture::new(
            Bytes::from_static(b"\x01\x03\x00\x00\xd9\x00\x03abc"),
            Observation::End,
        );
        assert_eq!(fixture.stream.recv_response().await.unwrap().status(), 200);
        let reads = fixture.reads.load(Ordering::SeqCst);
        let mut pending = Box::pin(fixture.stream.recv_terminal_error());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        for _ in 0..3 {
            assert!(pending.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(fixture.observer.lock().unwrap().polls, 1);
        assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
        drop(pending);
        assert_eq!(fixture.state.close_waiter_count(), 0);
        let mut body = fixture.stream.recv_data().await.unwrap().unwrap();
        assert_eq!(body.copy_to_bytes(body.remaining()), "abc");
        assert!(fixture.stream.recv_data().await.unwrap().is_none());
        let mut pending = Box::pin(fixture.stream.recv_terminal_error());
        assert!(pending.as_mut().poll(&mut cx).is_pending());
        assert_eq!(fixture.observer.lock().unwrap().polls, 1);
        close(&fixture.state);
        assert!(matches!(pending.await, StreamError::ConnectionError(_)));
        assert_eq!(fixture.state.close_waiter_count(), 0);
    }

    #[test]
    fn response_terminal_cancel_releases_tasks_and_can_resume_multiple_readers() {
        let mut first = Fixture::new(Bytes::new(), Observation::Pending);
        let mut second = Fixture::new(Bytes::new(), Observation::Pending);
        second.stream.inner.conn_state = first.state.clone();
        second.state = first.state.clone();
        for fixture in [&mut first, &mut second] {
            for _ in 0..2 {
                let task = Arc::new(CountWake::default());
                let waker = Waker::from(task.clone());
                let mut pending = Box::pin(fixture.stream.recv_terminal_error());
                assert!(pending
                    .as_mut()
                    .poll(&mut Context::from_waker(&waker))
                    .is_pending());
                drop(pending);
                drop(waker);
                assert_eq!(
                    Arc::strong_count(&task),
                    1,
                    "backend may retain only the weak forwarding waker"
                );
                assert_eq!(fixture.state.close_waiter_count(), 0);
                let stale = fixture.observer.lock().unwrap().waker.take().unwrap();
                stale.wake();
                assert_eq!(task.0.load(Ordering::SeqCst), 0);
            }
        }
        let first_task = Arc::new(CountWake::default());
        let second_task = Arc::new(CountWake::default());
        let first_waker = Waker::from(first_task.clone());
        let second_waker = Waker::from(second_task.clone());
        let mut first_wait = Box::pin(first.stream.recv_terminal_error());
        let mut second_wait = Box::pin(second.stream.recv_terminal_error());
        assert!(first_wait
            .as_mut()
            .poll(&mut Context::from_waker(&first_waker))
            .is_pending());
        assert!(second_wait
            .as_mut()
            .poll(&mut Context::from_waker(&second_waker))
            .is_pending());
        assert_eq!(first.state.close_waiter_count(), 2);
        close(&first.state);
        assert_eq!(first_task.0.load(Ordering::SeqCst), 1);
        assert_eq!(second_task.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            first_wait
                .as_mut()
                .poll(&mut Context::from_waker(&first_waker)),
            Poll::Ready(StreamError::ConnectionError(_))
        ));
        assert!(matches!(
            second_wait
                .as_mut()
                .poll(&mut Context::from_waker(&second_waker)),
            Poll::Ready(StreamError::ConnectionError(_))
        ));
        assert_eq!(first.state.close_waiter_count(), 0);
        assert_eq!(first.reads.load(Ordering::SeqCst), 0);
        assert_eq!(second.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn response_terminal_retains_reset_code_and_observes_already_closed_connection() {
        for code in [0, 256, 267, 268] {
            let mut fixture = Fixture::new(Bytes::new(), Observation::Reset(code));
            for _ in 0..2 {
                assert!(
                    matches!(fixture.stream.recv_terminal_error().await, StreamError::RemoteTerminate { code: value } if value.value() == code)
                );
            }
            assert_eq!(fixture.reads.load(Ordering::SeqCst), 0);
        }
        let mut fixture = Fixture::new(Bytes::new(), Observation::End);
        close(&fixture.state);
        assert!(matches!(
            fixture.stream.recv_terminal_error().await,
            StreamError::ConnectionError(_)
        ));
        assert_eq!(fixture.state.close_waiter_count(), 0);
    }

    fn dynamic_fixture() -> (Fixture, Bytes) {
        let mut fields = HeaderMap::new();
        fields.insert("x-dynamic", "retained".parse().unwrap());
        let (block, instructions) =
            qpack::encode_dynamic_for_test(0, Header::response(http::StatusCode::OK, fields));
        let mut wire = BytesMut::new();
        Frame::<Bytes>::Headers(block).encode_with_payload(&mut wire);
        (
            Fixture::new(wire.freeze(), Observation::Pending),
            instructions,
        )
    }

    #[test]
    fn response_terminal_combined_preserves_qpack_wake_and_handles_reset_while_blocked() {
        for reset in [false, true] {
            let (mut fixture, instructions) = dynamic_fixture();
            let task = Arc::new(CountWake::default());
            let waker = Waker::from(task.clone());
            let mut cx = Context::from_waker(&waker);
            let mut pending = Box::pin(fixture.stream.recv_response_or_terminal());
            assert!(pending.as_mut().poll(&mut cx).is_pending());
            assert_eq!(fixture.state.qpack_waiter_count(), 1);
            assert_eq!(fixture.state.close_waiter_count(), 1);
            if reset {
                signal(&fixture.observer, Observation::Reset(267));
                assert_eq!(task.0.load(Ordering::SeqCst), 1);
                assert!(
                    matches!(pending.as_mut().poll(&mut cx), Poll::Ready(Err(StreamError::RemoteTerminate { code })) if code.value() == 267)
                );
                assert!(fixture.state.take_qpack_decoder_instructions().is_empty());
            } else {
                fixture
                    .state
                    .process_qpack_encoder(&mut BytesMut::from(instructions.as_ref()))
                    .unwrap();
                assert_eq!(task.0.load(Ordering::SeqCst), 1);
                let Poll::Ready(Ok(response)) = pending.as_mut().poll(&mut cx) else {
                    panic!("real QPACK insert must release response headers")
                };
                assert_eq!(response.status(), 200);
                assert_eq!(response.headers()["x-dynamic"], "retained");
                assert_eq!(
                    fixture.state.take_qpack_decoder_instructions().as_ref(),
                    b"\x01\x80"
                );
            }
            drop(pending);
            assert_eq!(fixture.state.qpack_waiter_count(), 0);
            assert_eq!(fixture.state.close_waiter_count(), 0);
            assert!(fixture.stream.inner.pending_response_headers.is_none());
        }
    }

    #[tokio::test]
    async fn response_terminal_ready_final_headers_precede_pending_reset() {
        let mut wire = BytesMut::new();
        for status in [100, 200] {
            let mut block = BytesMut::new();
            qpack::encode_stateless(
                &mut block,
                Header::response(
                    http::StatusCode::from_u16(status).unwrap(),
                    HeaderMap::new(),
                ),
            )
            .unwrap();
            Frame::<Bytes>::Headers(block.freeze()).encode_with_payload(&mut wire);
        }
        Frame::Data(Bytes::from_static(b"body")).encode_with_payload(&mut wire);
        let mut fixture = Fixture::new(wire.freeze(), Observation::Reset(267));
        assert_eq!(fixture.stream.recv_response().await.unwrap().status(), 100);
        let reads = fixture.reads.load(Ordering::SeqCst);
        assert_eq!(
            fixture
                .stream
                .recv_response_or_terminal()
                .await
                .unwrap()
                .status(),
            200
        );
        assert_eq!(fixture.observer.lock().unwrap().polls, 0);
        assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
        assert!(
            matches!(fixture.stream.recv_terminal_error().await, StreamError::RemoteTerminate { code } if code.value() == 267)
        );
        assert_eq!(fixture.reads.load(Ordering::SeqCst), reads);
    }

    struct ReentrantTaskDrop {
        state: Weak<SharedState>,
        observed: Arc<AtomicUsize>,
    }
    impl Wake for ReentrantTaskDrop {
        fn wake(self: Arc<Self>) {}
    }
    impl Drop for ReentrantTaskDrop {
        fn drop(&mut self) {
            self.observed.store(
                if self.state.upgrade().unwrap().close_waiters_unlocked() {
                    1
                } else {
                    2
                },
                Ordering::SeqCst,
            );
        }
    }

    #[test]
    fn response_terminal_cancellation_drops_reentrant_task_outside_registry_lock() {
        for combined in [false, true] {
            let (mut fixture, _) = dynamic_fixture();
            let observed = Arc::new(AtomicUsize::new(0));
            let waker = Waker::from(Arc::new(ReentrantTaskDrop {
                state: Arc::downgrade(&fixture.state),
                observed: observed.clone(),
            }));
            let mut pending = Box::pin(async {
                if combined {
                    let _ = fixture.stream.recv_response_or_terminal().await;
                } else {
                    let _ = fixture.stream.recv_terminal_error().await;
                }
            });
            assert!(pending
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
            drop(waker);
            drop(pending);
            assert_eq!(observed.load(Ordering::SeqCst), 1);
            assert_eq!(fixture.state.close_waiter_count(), 0);
            assert_eq!(fixture.state.qpack_waiter_count(), 0);
            assert!(
                fixture.observer.lock().unwrap().waker.is_some(),
                "only a weak backend registration may remain"
            );
        }
    }
}

#[cfg(test)]
mod response_eof_wait_tests {
    use super::*;
    use crate::{frame::FrameStream, stream::BufRecvStream};
    use bytes::Bytes;
    use std::{future::Future, pin::pin, sync::Arc};

    struct FinishedRecv(Option<Bytes>);

    impl quic::RecvStream for FinishedRecv {
        type Buf = Bytes;
        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
            Poll::Ready(Ok(self.0.take()))
        }
        fn stop_sending(&mut self, _: u64) {}
        fn recv_id(&self) -> StreamId {
            StreamId::try_from(0).unwrap()
        }
    }

    fn stream(bytes: &'static [u8], state: Arc<SharedState>) -> RequestStream<FinishedRecv, Bytes> {
        RequestStream {
            inner: connection::RequestStream::new(
                FrameStream::new(BufRecvStream::new(FinishedRecv(
                    (!bytes.is_empty()).then(|| Bytes::from_static(bytes)),
                )))
                .wait_for_incomplete_response_frame_headers(true),
                u64::MAX,
                state,
                false,
            ),
        }
    }

    async fn receive(
        stream: &mut RequestStream<FinishedRecv, Bytes>,
        phase: usize,
    ) -> Result<(), StreamError> {
        match phase {
            0 => stream.recv_response().await.map(|_| ()),
            1 => stream.recv_data().await.map(|_| ()),
            _ => stream.recv_trailers().await.map(|_| ()),
        }
    }

    #[test]
    fn response_eof_wait_async_cancel_resume_retains_header_and_trailers() {
        for phase in 0..3 {
            for bytes in [&b"\x40"[..], &b"\x01\x40"[..]] {
                let state = Arc::new(SharedState::default());
                let mut stream = stream(bytes, state.clone());
                if phase == 2 {
                    stream.inner.trailers = Some(Bytes::from_static(b"\x00\x00"));
                }
                for _ in 0..2 {
                    let mut receive = Box::pin(receive(&mut stream, phase));
                    assert!(receive
                        .as_mut()
                        .poll(&mut Context::from_waker(
                            futures_util::task::noop_waker_ref()
                        ))
                        .is_pending());
                    assert_eq!(state.close_waiter_count(), 1);
                    drop(receive);
                    assert_eq!(state.close_waiter_count(), 0);
                    if phase == 2 {
                        assert_eq!(stream.inner.trailers.as_deref(), Some(&b"\x00\x00"[..]));
                    }
                }
                state.set_conn_error(
                    InternalConnectionError::new(
                        Code::H3_INTERNAL_ERROR,
                        "close after cancellation".to_string(),
                    )
                    .into(),
                );
                let mut receive = pin!(receive(&mut stream, phase));
                assert!(matches!(
                    receive.as_mut().poll(&mut Context::from_waker(
                        futures_util::task::noop_waker_ref()
                    )),
                    Poll::Ready(Err(StreamError::ConnectionError(_)))
                ));
                assert_eq!(state.close_waiter_count(), 0);
            }
        }
    }

    #[test]
    fn response_eof_wait_raw_poll_registration_released_by_stop_or_drop() {
        let state = Arc::new(SharedState::default());
        let mut first = stream(b"\x40", state.clone());
        let mut second = stream(b"\x01\x40", state.clone());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(first.poll_recv_data(&mut cx).is_pending());
        assert!(second.poll_recv_data(&mut cx).is_pending());
        assert_eq!(state.close_waiter_count(), 2);
        first.stop_sending(Code::H3_REQUEST_CANCELLED);
        assert_eq!(state.close_waiter_count(), 1);
        drop(second);
        assert_eq!(state.close_waiter_count(), 0);
    }

    #[test]
    fn response_eof_wait_does_not_change_already_completed_body() {
        let state = Arc::new(SharedState::default());
        let mut stream = stream(b"", state.clone());
        let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(matches!(
            stream.poll_recv_data(&mut cx),
            Poll::Ready(Ok(None))
        ));
        state.set_conn_error(
            InternalConnectionError::new(Code::H3_INTERNAL_ERROR, "later close".to_string()).into(),
        );
        assert!(matches!(
            stream.poll_recv_data(&mut cx),
            Poll::Ready(Ok(None))
        ));
        assert_eq!(state.close_waiter_count(), 0);
    }
}

#[cfg(test)]
mod qpack_cancellation_tests {
    use super::*;
    use crate::{frame::FrameStream, stream::BufRecvStream};
    use bytes::{Bytes, BytesMut};
    use std::{future::Future, sync::Arc, task::Waker};

    struct MemoryRecv {
        bytes: Option<Bytes>,
        id: StreamId,
        created_in_0rtt: bool,
    }

    impl quic::RecvStream for MemoryRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, quic::StreamErrorIncoming>> {
            Poll::Ready(Ok(self.bytes.take()))
        }
        fn stop_sending(&mut self, _: u64) {}
        fn recv_id(&self) -> StreamId {
            self.id
        }
    }

    impl quic::SendStream<Bytes> for MemoryRecv {
        fn poll_ready(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<(), quic::StreamErrorIncoming>> {
            unreachable!("receive-only fixture")
        }
        fn send_data<T: Into<crate::stream::WriteBuf<Bytes>>>(
            &mut self,
            _: T,
        ) -> Result<(), quic::StreamErrorIncoming> {
            unreachable!("receive-only fixture")
        }
        fn poll_finish(
            &mut self,
            _: &mut Context<'_>,
        ) -> Poll<Result<(), quic::StreamErrorIncoming>> {
            unreachable!("receive-only fixture")
        }
        fn reset(&mut self, _: u64) {
            unreachable!("receive-only fixture")
        }
        fn send_id(&self) -> StreamId {
            self.id
        }
    }

    impl quic::BidiStream<Bytes> for MemoryRecv {
        type SendStream = Self;
        type RecvStream = Self;
        fn split(self) -> (Self, Self) {
            (
                Self {
                    bytes: None,
                    id: self.id,
                    created_in_0rtt: self.created_in_0rtt,
                },
                self,
            )
        }
    }

    impl quic::Is0rtt for MemoryRecv {
        fn is_0rtt(&self) -> bool {
            self.created_in_0rtt
        }
    }

    #[test]
    fn client_stream_is_0rtt_preserves_creation_state_through_split() {
        for created_in_0rtt in [false, true] {
            let stream: RequestStream<_, Bytes> = RequestStream {
                inner: connection::RequestStream::new(
                    FrameStream::new(BufRecvStream::new(MemoryRecv {
                        bytes: None,
                        id: StreamId::try_from(0).unwrap(),
                        created_in_0rtt,
                    })),
                    u64::MAX,
                    Arc::new(SharedState::default()),
                    false,
                ),
            };
            assert_eq!(stream.is_0rtt(), created_in_0rtt);
            let (send, recv) = stream.split();
            assert_eq!(send.is_0rtt(), created_in_0rtt);
            assert_eq!(recv.is_0rtt(), created_in_0rtt);
        }
    }

    fn stream(wire: Bytes, id: u64, state: Arc<SharedState>) -> RequestStream<MemoryRecv, Bytes> {
        RequestStream {
            inner: connection::RequestStream::new(
                FrameStream::new(BufRecvStream::new(MemoryRecv {
                    bytes: Some(wire),
                    id: StreamId::try_from(id).unwrap(),
                    created_in_0rtt: false,
                })),
                u64::MAX,
                state,
                false,
            ),
        }
    }

    fn dynamic_response(status: u16, id: u64) -> (Bytes, Bytes) {
        let (parts, ()) = Response::builder()
            .status(status)
            .header("x-dynamic", "retained")
            .body(())
            .unwrap()
            .into_parts();
        qpack::encode_dynamic_for_test(id, Header::response(parts.status, parts.headers))
    }

    fn static_response(status: u16) -> Bytes {
        let mut encoded = BytesMut::new();
        qpack::encode_stateless(
            &mut encoded,
            Header::response(
                http::StatusCode::from_u16(status).unwrap(),
                HeaderMap::new(),
            ),
        )
        .unwrap();
        encoded.freeze()
    }

    fn headers(wire: &mut BytesMut, encoded: Bytes) {
        Frame::<Bytes>::Headers(encoded).encode_with_payload(wire);
    }

    fn cancel_response(stream: &mut RequestStream<MemoryRecv, Bytes>) {
        let mut read = Box::pin(stream.recv_response());
        assert!(read
            .as_mut()
            .poll(&mut Context::from_waker(
                futures_util::task::noop_waker_ref()
            ))
            .is_pending());
    }

    fn feed_encoder(state: &SharedState, instructions: Bytes) {
        state
            .process_qpack_encoder(&mut BytesMut::from(instructions.as_ref()))
            .unwrap();
        assert_eq!(
            state.take_qpack_decoder_instructions().as_ref(),
            b"\x01",
            "one real insert must generate InsertCountIncrement before the header ACK"
        );
    }

    fn assert_single_ack(state: &SharedState, id: u64) {
        let mut expected = BytesMut::new();
        qpack::ack_header(id, &mut expected);
        assert_eq!(state.take_qpack_decoder_instructions(), expected.freeze());
    }

    #[tokio::test]
    async fn qpack_cancelled_final_response_retains_headers_before_data() {
        let state = Arc::new(SharedState::new(4096));
        let (block, instructions) = dynamic_response(200, 0);
        let mut wire = BytesMut::new();
        headers(&mut wire, block);
        Frame::Data(Bytes::from_static(b"body")).encode_with_payload(&mut wire);
        let mut stream = stream(wire.freeze(), 0, state.clone());
        cancel_response(&mut stream);
        feed_encoder(&state, instructions);
        let response = stream
            .recv_response()
            .await
            .expect("cancelled dynamic response headers must be retained before DATA");
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["x-dynamic"], "retained");
        assert_single_ack(&state, 0);
        let mut body = stream.recv_data().await.unwrap().unwrap();
        assert_eq!(body.copy_to_bytes(body.remaining()), "body");
        assert!(stream.recv_data().await.unwrap().is_none());
        assert!(stream.recv_trailers().await.unwrap().is_none());
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[tokio::test]
    async fn qpack_cancelled_initial_response_retains_headers_before_fin() {
        let state = Arc::new(SharedState::new(4096));
        let (block, instructions) = dynamic_response(200, 0);
        let mut wire = BytesMut::new();
        headers(&mut wire, block);
        let mut stream = stream(wire.freeze(), 0, state.clone());
        cancel_response(&mut stream);
        feed_encoder(&state, instructions);
        let response = stream
            .recv_response()
            .await
            .expect("cancelled dynamic response headers must be retained before FIN");
        assert_eq!(response.status(), 200);
        assert_single_ack(&state, 0);
        assert!(stream.recv_data().await.unwrap().is_none());
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[tokio::test]
    async fn qpack_cancelled_informational_response_is_not_skipped() {
        let state = Arc::new(SharedState::new(4096));
        let (block, instructions) = dynamic_response(103, 0);
        let mut wire = BytesMut::new();
        headers(&mut wire, block);
        headers(&mut wire, static_response(200));
        let mut stream = stream(wire.freeze(), 0, state.clone());
        cancel_response(&mut stream);
        feed_encoder(&state, instructions);
        let informational = stream.recv_response().await.unwrap();
        assert_eq!(
            informational.status(),
            103,
            "cancellation must not skip an informational field section"
        );
        assert_eq!(informational.headers()["x-dynamic"], "retained");
        assert_single_ack(&state, 0);
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[tokio::test]
    async fn qpack_cancelled_final_response_after_continue_is_not_lost() {
        let state = Arc::new(SharedState::new(4096));
        let (block, instructions) = dynamic_response(200, 0);
        let mut wire = BytesMut::new();
        headers(&mut wire, static_response(100));
        headers(&mut wire, block);
        let mut stream = stream(wire.freeze(), 0, state.clone());
        assert_eq!(stream.recv_response().await.unwrap().status(), 100);
        cancel_response(&mut stream);
        feed_encoder(&state, instructions);
        assert_eq!(
            stream
                .recv_response()
                .await
                .expect("final field section must survive cancellation after 100")
                .status(),
            200
        );
        assert_single_ack(&state, 0);
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[tokio::test]
    async fn qpack_cancelled_trailers_preserve_fields_and_single_ack() {
        let state = Arc::new(SharedState::new(4096));
        let mut trailers = HeaderMap::new();
        trailers.insert("x-dynamic", "retained".parse().unwrap());
        let (block, instructions) = qpack::encode_dynamic_for_test(0, Header::trailer(trailers));
        let mut wire = BytesMut::new();
        headers(&mut wire, static_response(200));
        headers(&mut wire, block);
        let mut stream = stream(wire.freeze(), 0, state.clone());
        assert_eq!(stream.recv_response().await.unwrap().status(), 200);
        assert!(stream.recv_data().await.unwrap().is_none());
        for _ in 0..2 {
            let mut read = Box::pin(stream.recv_trailers());
            assert!(read
                .as_mut()
                .poll(&mut Context::from_waker(
                    futures_util::task::noop_waker_ref()
                ))
                .is_pending());
        }
        feed_encoder(&state, instructions);
        assert_eq!(
            stream.recv_trailers().await.unwrap().unwrap()["x-dynamic"],
            "retained"
        );
        assert_single_ack(&state, 0);
        assert!(stream.recv_trailers().await.unwrap().is_none());
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[derive(Default)]
    struct TaskWake(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for TaskWake {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn qpack_cancelled_waiters_release_tasks_without_encoder_progress() {
        let state = Arc::new(SharedState::new(4096));
        let mut tasks = Vec::new();
        for id in [0, 4, 8, 12] {
            let (block, _) = dynamic_response(200, id);
            let mut wire = BytesMut::new();
            headers(&mut wire, block);
            let mut stream = stream(wire.freeze(), id, state.clone());
            let task = Arc::new(TaskWake::default());
            let waker = Waker::from(task.clone());
            let mut read = Box::pin(stream.recv_response());
            assert!(read
                .as_mut()
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
            drop(read);
            drop(waker);
            assert_eq!(
                Arc::strong_count(&task),
                1,
                "future cancellation must release its task while the stream is still alive"
            );
            assert_eq!(state.qpack_waiter_count(), 0);
            cancel_response(&mut stream);
            assert_eq!(state.qpack_waiter_count(), 0);
            tasks.push(task);
        }
        for task in tasks {
            assert_eq!(
                Arc::strong_count(&task),
                1,
                "cancelled QPACK read must release its task before any insertion or close"
            );
        }
        assert_eq!(state.qpack_waiter_count(), 0);
    }

    #[tokio::test]
    async fn qpack_cancelled_headers_survive_split_and_repeated_cancellation() {
        let state = Arc::new(SharedState::new(4096));
        let (block, instructions) = dynamic_response(200, 4);
        let mut wire = BytesMut::new();
        headers(&mut wire, block);
        let mut stream = stream(wire.freeze(), 4, state.clone());
        cancel_response(&mut stream);
        assert_eq!(state.qpack_waiter_count(), 0);
        let (send, mut recv) = stream.split();
        assert!(send.inner.pending_response_headers.is_none());
        assert!(recv.inner.pending_response_headers.is_some());
        drop(send);
        cancel_response(&mut recv);
        assert_eq!(state.qpack_waiter_count(), 0);
        feed_encoder(&state, instructions);
        assert_eq!(recv.recv_response().await.unwrap().status(), 200);
        assert!(recv.inner.pending_response_headers.is_none());
        assert_single_ack(&state, 4);
    }

    #[tokio::test]
    async fn qpack_one_insert_releases_multiple_responses_and_acks_each_stream_once() {
        let state = Arc::new(SharedState::new(4096));
        let (block, instructions) = dynamic_response(200, 0);
        let mut wire = BytesMut::new();
        headers(&mut wire, block);
        let wire = wire.freeze();
        let mut first = stream(wire.clone(), 0, state.clone());
        let mut second = stream(wire, 4, state.clone());
        let mut first_read = Box::pin(first.recv_response());
        let mut second_read = Box::pin(second.recv_response());
        let first_wakes = Arc::new(TaskWake::default());
        let second_wakes = Arc::new(TaskWake::default());
        let first_waker = Waker::from(first_wakes.clone());
        let second_waker = Waker::from(second_wakes.clone());
        assert!(first_read
            .as_mut()
            .poll(&mut Context::from_waker(&first_waker))
            .is_pending());
        assert!(second_read
            .as_mut()
            .poll(&mut Context::from_waker(&second_waker))
            .is_pending());
        assert_eq!(state.qpack_waiter_count(), 2);
        feed_encoder(&state, instructions);
        assert_eq!(first_wakes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(second_wakes.0.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(first_read.await.unwrap().status(), 200);
        assert_single_ack(&state, 0);
        assert_eq!(second_read.await.unwrap().status(), 200);
        assert_single_ack(&state, 4);
        assert_eq!(state.qpack_waiter_count(), 0);
        assert!(first.recv_data().await.unwrap().is_none());
        assert!(second.recv_data().await.unwrap().is_none());
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[tokio::test]
    async fn qpack_terminal_response_errors_clear_cached_headers_without_ack() {
        for close in [false, true] {
            let state = Arc::new(SharedState::new(4096));
            let (block, instructions) = dynamic_response(200, 0);
            let mut wire = BytesMut::new();
            headers(&mut wire, block);
            let mut stream = stream(wire.freeze(), 0, state.clone());
            cancel_response(&mut stream);
            assert!(stream.inner.pending_response_headers.is_some());
            if close {
                state.set_conn_error(
                    InternalConnectionError::new(
                        Code::H3_INTERNAL_ERROR,
                        "closed while decoding response".to_string(),
                    )
                    .into(),
                );
            } else {
                stream.inner.max_field_section_size = 0;
                feed_encoder(&state, instructions);
            }
            let error = stream.recv_response().await.unwrap_err();
            if close {
                assert!(matches!(error, StreamError::ConnectionError(_)));
            } else {
                assert!(matches!(error, StreamError::HeaderTooBig { .. }));
            }
            assert!(stream.inner.pending_response_headers.is_none());
            assert_eq!(state.qpack_waiter_count(), 0);
            assert!(state.take_qpack_decoder_instructions().is_empty());
        }
    }
}
