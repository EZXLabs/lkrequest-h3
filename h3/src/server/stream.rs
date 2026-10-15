//! Server-side HTTP/3 stream management

use bytes::Buf;

use crate::{
    error::{
        connection_error_creators::CloseStream, internal_error::InternalConnectionError, Code,
        StreamError,
    },
    quic::{self},
    shared_state::{ConnectionState, SharedState},
};

use super::connection::RequestEnd;
use std::sync::Arc;

use std::{
    option::Option,
    result::Result,
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures_util::future;
use http::{response, HeaderMap, Response};

use quic::StreamId;

use crate::{
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::SendStream as _,
    stream::{self},
};

#[cfg(feature = "tracing")]
use tracing::{error, instrument};

/// Manage request and response transfer for an incoming request
///
/// The [`RequestStream`] struct is used to send and/or receive
/// information from the client.
/// After sending the final response, call [`RequestStream::finish`] to close the stream.
pub struct RequestStream<S, B> {
    pub(super) inner: crate::connection::RequestStream<S, B>,
    pub(super) request_end: Arc<RequestEnd>,
}

impl<S, B> AsMut<crate::connection::RequestStream<S, B>> for RequestStream<S, B> {
    fn as_mut(&mut self) -> &mut crate::connection::RequestStream<S, B> {
        &mut self.inner
    }
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
    B: Buf,
{
    /// Receive data sent from the client.
    ///
    /// This returns a chunk of the request body, or `None` if the request body is finished.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_data(cx)).await
    }

    /// Poll for data sent from the client.
    ///
    /// This returns a chunk of the request body, or `None` if the request body is finished.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        self.inner.poll_recv_data(cx)
    }

    /// Receive an optional set of trailers for the request
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        let mut registration = self.inner.take_close_waiter();
        let mut qpack_registration = self.inner.take_qpack_waiter();
        future::poll_fn(|cx| {
            self.inner.poll_recv_trailers_with_waiter(
                cx,
                &mut registration,
                &mut qpack_registration,
            )
        })
        .await
    }

    /// Poll for an optional set of trailers for the request
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        self.inner.poll_recv_trailers(cx)
    }

    /// Tell the peer to stop sending into the underlying QUIC stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        self.inner.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }

    /// Check if this stream was opened during 0-RTT.
    ///
    /// See [RFC 8470 Section 5.2](https://www.rfc-editor.org/rfc/rfc8470.html#section-5.2).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use h3::server::RequestStream;
    /// # async fn example(mut stream: RequestStream<impl h3::quic::BidiStream<bytes::Bytes> + h3::quic::Is0rtt, bytes::Bytes>) {
    /// if stream.is_0rtt() {
    ///     // Reject non-idempotent methods (e.g., POST, PUT, DELETE)
    ///     // to prevent replay attacks
    /// }
    /// # }
    /// ```
    pub fn is_0rtt(&self) -> bool
    where
        S: quic::Is0rtt,
    {
        self.inner.stream.is_0rtt()
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    #[cfg(test)]
    #[allow(missing_docs)]
    pub async fn send_encoded_headers_for_test(&mut self, block: bytes::Bytes) {
        stream::write(&mut self.inner.stream, Frame::Headers(block))
            .await
            .expect("send encoded response headers");
    }

    /// Send the HTTP/3 response
    ///
    /// This should be called before trying to send any data with
    /// [`RequestStream::send_data`].
    pub async fn send_response(&mut self, resp: Response<()>) -> Result<(), StreamError> {
        let (parts, _) = resp.into_parts();
        let response::Parts {
            status, headers, ..
        } = parts;
        let headers = Header::response(status, headers);

        let mut block = BytesMut::new();
        let mem_size = qpack::encode_stateless(&mut block, headers).map_err(|_e| {
            self.handle_connection_error_on_stream(InternalConnectionError {
                code: Code::H3_INTERNAL_ERROR,
                message: "Failed to encode headers".to_string(),
            })
        })?;

        let max_mem_size = self.inner.settings().max_field_section_size;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.2.2
        //# An implementation that
        //# has received this parameter SHOULD NOT send an HTTP message header
        //# that exceeds the indicated size, as the peer will likely refuse to
        //# process it.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.2
        //# An HTTP implementation MUST NOT send frames or requests that would be
        //# invalid based on its current understanding of the peer's settings.

        if mem_size > max_mem_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size: max_mem_size,
            });
        }

        stream::write(&mut self.inner.stream, Frame::Headers(block.freeze()))
            .await
            .map_err(|e| self.handle_quic_stream_error(e))?;

        Ok(())
    }

    /// Send some data on the response body.
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        self.inner.send_data(buf).await
    }

    /// Stop a stream with an error code
    ///
    /// The code can be [`Code::H3_NO_ERROR`].
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the response.
    ///
    /// [`RequestStream::finish`] must be called to finalize a request.
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.inner.send_trailers(trailers).await
    }

    /// End the response without trailers.
    ///
    /// [`RequestStream::finish`] must be called to finalize a request.
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

    /// Returns the underlying stream id
    pub fn send_id(&self) -> StreamId {
        self.inner.stream.send_id()
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Splits the Request-Stream into send and receive.
    /// This can be used the send and receive data on different tasks.
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.inner.split();
        (
            RequestStream {
                inner: send,
                request_end: self.request_end.clone(),
            },
            RequestStream {
                inner: recv,
                request_end: self.request_end,
            },
        )
    }
}

impl Drop for RequestEnd {
    fn drop(&mut self) {
        if let Err(_error) = self.request_end.send(self.stream_id) {
            #[cfg(feature = "tracing")]
            error!(
                "failed to notify connection of request end: {} {}",
                self.stream_id, _error
            );
        }
    }
}

#[cfg(test)]
mod qpack_cancellation_tests {
    use super::*;
    use crate::{frame::FrameStream, stream::BufRecvStream};
    use bytes::Bytes;
    use std::future::Future;

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

    fn blocked_trailers() -> (RequestStream<FinishedRecv, Bytes>, Arc<SharedState>, Bytes) {
        let state = Arc::new(SharedState::new(4096));
        let mut trailers = HeaderMap::new();
        trailers.insert("x-dynamic", "retained".parse().unwrap());
        let (block, instructions) = qpack::encode_dynamic_for_test(0, Header::trailer(trailers));
        let mut wire = BytesMut::new();
        Frame::<Bytes>::Headers(block).encode_with_payload(&mut wire);
        let (request_end, _) = tokio::sync::mpsc::unbounded_channel();
        let stream = RequestStream {
            inner: crate::connection::RequestStream::new(
                FrameStream::new(BufRecvStream::new(FinishedRecv(Some(wire.freeze())))),
                u64::MAX,
                state.clone(),
                false,
            ),
            request_end: Arc::new(RequestEnd {
                request_end,
                stream_id: StreamId::try_from(0).unwrap(),
            }),
        };
        (stream, state, instructions)
    }

    #[tokio::test]
    async fn qpack_server_cancelled_trailers_release_waiter_and_resume_once() {
        let (mut stream, state, instructions) = blocked_trailers();
        for _ in 0..2 {
            let mut read = Box::pin(stream.recv_trailers());
            assert!(read
                .as_mut()
                .poll(&mut Context::from_waker(
                    futures_util::task::noop_waker_ref()
                ))
                .is_pending());
            assert_eq!(state.qpack_waiter_count(), 1);
            drop(read);
            assert_eq!(state.qpack_waiter_count(), 0);
            assert!(stream.inner.trailers.is_some());
        }
        state
            .process_qpack_encoder(&mut BytesMut::from(instructions.as_ref()))
            .unwrap();
        assert_eq!(state.take_qpack_decoder_instructions().as_ref(), b"\x01");
        assert_eq!(
            stream.recv_trailers().await.unwrap().unwrap()["x-dynamic"],
            "retained"
        );
        assert_eq!(state.take_qpack_decoder_instructions().as_ref(), b"\x80");
        assert!(stream.recv_trailers().await.unwrap().is_none());
        assert!(state.take_qpack_decoder_instructions().is_empty());
    }

    #[test]
    fn qpack_server_raw_trailer_stop_and_error_unregister_waiter() {
        for stop in [false, true] {
            let (mut stream, state, _) = blocked_trailers();
            let mut cx = Context::from_waker(futures_util::task::noop_waker_ref());
            assert!(stream.poll_recv_trailers(&mut cx).is_pending());
            assert_eq!(state.qpack_waiter_count(), 1);
            if stop {
                stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            } else {
                state.set_conn_error(
                    InternalConnectionError::new(
                        Code::H3_INTERNAL_ERROR,
                        "closed while decoding trailers".to_string(),
                    )
                    .into(),
                );
                assert!(matches!(
                    stream.poll_recv_trailers(&mut cx),
                    Poll::Ready(Err(StreamError::ConnectionError(_)))
                ));
            }
            assert_eq!(state.qpack_waiter_count(), 0);
            assert!(state.take_qpack_decoder_instructions().is_empty());
        }
    }
}
