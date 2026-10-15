use std::task::{Context, Poll};

use bytes::Buf;

#[cfg(feature = "tracing")]
use tracing::trace;

use crate::error::Code;
use crate::proto::frame::SettingsError;
use crate::proto::push::InvalidPushId;
use crate::quic::{InvalidStreamId, StreamErrorIncoming};
use crate::stream::{BufRecvStream, WriteBuf};
use crate::{
    buf::BufList,
    proto::{
        frame::{self, Frame, PayloadLen},
        stream::StreamId,
    },
    quic::{BidiStream, RecvStream, SendStream},
};

/// Decodes Frames from the underlying QUIC stream
pub struct FrameStream<S, B> {
    pub stream: BufRecvStream<S, B>,
    // Already read data from the stream
    decoder: FrameDecoder,
    remaining_data: usize,
    reading_data_frame: bool,
    wait_for_incomplete_response_frame_headers: bool,
}

impl<S, B> FrameStream<S, B> {
    pub fn new(stream: BufRecvStream<S, B>) -> Self {
        Self {
            stream,
            decoder: FrameDecoder::default(),
            remaining_data: 0,
            reading_data_frame: false,
            wait_for_incomplete_response_frame_headers: false,
        }
    }

    pub(crate) fn accept_truncated_response_payloads(mut self, enabled: bool) -> Self {
        self.decoder.accept_truncated_response_payloads = enabled;
        self
    }

    pub(crate) fn wait_for_incomplete_response_frame_headers(mut self, enabled: bool) -> Self {
        self.wait_for_incomplete_response_frame_headers = enabled;
        self
    }

    /// Unwraps the Framed streamer and returns the underlying stream **without** data loss for
    /// partially received/read frames.
    pub fn into_inner(self) -> BufRecvStream<S, B> {
        self.stream
    }
}

impl<S, B> FrameStream<S, B>
where
    S: crate::quic::Is0rtt,
{
    /// Checks if the stream was opened in 0-RTT mode
    pub(crate) fn is_0rtt(&self) -> bool {
        self.stream.is_0rtt()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: RecvStream,
{
    /// Polls the stream for the next frame header
    ///
    /// When a frame header is received use `poll_data` to retrieve the frame's data.
    pub fn poll_next(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        self.poll_next_with_eof_context(cx, true)
    }

    pub(crate) fn poll_next_after_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        self.poll_next_with_eof_context(cx, false)
    }

    fn poll_next_with_eof_context(
        &mut self,
        cx: &mut Context<'_>,
        allow_headers: bool,
    ) -> Poll<Result<Option<Frame<PayloadLen>>, FrameStreamError>> {
        assert!(
            self.remaining_data == 0,
            "There is still data to read, please call poll_data() until it returns None."
        );

        loop {
            match self
                .decoder
                .decode_with_context(self.stream.buf_mut(), allow_headers)?
            {
                Some(Frame::Data(PayloadLen(len))) => {
                    self.remaining_data = len;
                    self.reading_data_frame = true;
                    return Poll::Ready(Ok(Some(Frame::Data(PayloadLen(len)))));
                }
                frame @ Some(Frame::WebTransportStream(_)) => {
                    self.remaining_data = usize::MAX;
                    self.reading_data_frame = false;
                    return Poll::Ready(Ok(frame));
                }
                Some(frame) => return Poll::Ready(Ok(Some(frame))),
                None => {}
            }

            match self.try_recv(cx)? {
                // Received a chunk but the frame is incomplete, poll until we get `Pending`.
                Poll::Ready(false) => continue,
                Poll::Pending => return Poll::Pending,
                Poll::Ready(true) => {
                    if self.stream.buf_mut().has_remaining() {
                        if self.decoder.accept_truncated_response_payloads {
                            if let Some(ty) =
                                FrameDecoder::incomplete_payload_type(self.stream.buf())
                            {
                                if !ty.is_known()
                                    || (allow_headers && ty == frame::FrameType::HEADERS)
                                {
                                    let buffered = self.stream.buf_mut();
                                    buffered.advance(buffered.remaining());
                                    self.decoder.expected = None;
                                    return Poll::Ready(Ok(None));
                                }
                                return Poll::Ready(Err(FrameStreamError::Proto(
                                    FrameProtocolError::ForbiddenFrame(ty.value()),
                                )));
                            }
                        }
                        // Reached the end of receive stream, but there is still some data:
                        // The frame is incomplete.
                        return Poll::Ready(Err(FrameStreamError::UnexpectedEnd));
                    } else {
                        return Poll::Ready(Ok(None));
                    }
                }
            }
        }
    }

    /// Retrieves the next piece of data in an incoming data packet or webtransport stream
    ///
    ///
    /// WebTransport bidirectional payload has no finite length and is processed until the end of the stream.
    pub fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, FrameStreamError>> {
        if self.remaining_data == 0 {
            return Poll::Ready(Ok(None));
        };

        let end = match self.try_recv(cx) {
            Poll::Ready(Ok(end)) => end,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => false,
        };
        let data = self.stream.buf_mut().take_chunk(self.remaining_data);

        match (data, end) {
            (None, true) => {
                self.remaining_data = 0;
                Poll::Ready(Ok(None))
            }
            (None, false) => Poll::Pending,
            (Some(d), true)
                if d.remaining() < self.remaining_data
                    && !self.stream.buf_mut().has_remaining()
                    && !(self.decoder.accept_truncated_response_payloads
                        && self.reading_data_frame) =>
            {
                Poll::Ready(Err(FrameStreamError::UnexpectedEnd))
            }
            (Some(d), _) => {
                self.remaining_data -= d.remaining();
                Poll::Ready(Ok(Some(d)))
            }
        }
    }

    /// Stops the underlying stream with the provided error code
    pub(crate) fn stop_sending(&mut self, error_code: Code) {
        self.stream.stop_sending(error_code.into());
    }

    pub(crate) fn has_data(&self) -> bool {
        self.remaining_data != 0
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.stream.is_eos() && !self.stream.buf().has_remaining()
    }

    pub(crate) fn waits_for_incomplete_header(&self) -> bool {
        self.wait_for_incomplete_response_frame_headers
            && self.stream.is_eos()
            && FrameDecoder::incomplete_header(self.stream.buf())
    }

    fn try_recv(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, FrameStreamError>> {
        if self.stream.is_eos() {
            return Poll::Ready(Ok(true));
        }
        match self.stream.poll_read(cx) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(FrameStreamError::Quic(e))),
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(eos)) => Poll::Ready(Ok(eos)),
        }
    }

    pub fn id(&self) -> StreamId {
        self.stream.recv_id()
    }
}

impl<T, B> SendStream<B> for FrameStream<T, B>
where
    T: SendStream<B>,
    B: Buf,
{
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_ready(cx)
    }

    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.stream.send_data(data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.stream.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.stream.reset(reset_code)
    }

    fn send_id(&self) -> StreamId {
        self.stream.send_id()
    }
}

impl<S, B> FrameStream<S, B>
where
    S: BidiStream<B>,
    B: Buf,
{
    pub(crate) fn split(self) -> (FrameStream<S::SendStream, B>, FrameStream<S::RecvStream, B>) {
        let (send, recv) = self.stream.split();
        (
            FrameStream {
                stream: send,
                decoder: FrameDecoder::default(),
                remaining_data: 0,
                reading_data_frame: false,
                wait_for_incomplete_response_frame_headers: false,
            },
            FrameStream {
                stream: recv,
                decoder: self.decoder,
                remaining_data: self.remaining_data,
                reading_data_frame: self.reading_data_frame,
                wait_for_incomplete_response_frame_headers: self
                    .wait_for_incomplete_response_frame_headers,
            },
        )
    }
}

#[derive(Default)]
pub struct FrameDecoder {
    expected: Option<usize>,
    accept_truncated_response_payloads: bool,
}

impl FrameDecoder {
    fn incomplete_header<B: Buf>(src: &BufList<B>) -> bool {
        let mut cursor = src.cursor();
        if !cursor.has_remaining() {
            return false;
        }
        match frame::FrameType::decode(&mut cursor) {
            Err(_) => true,
            Ok(ty) if ty == frame::FrameType::WEBTRANSPORT_BI_STREAM => false,
            Ok(_) => crate::proto::varint::VarInt::decode(&mut cursor).is_err(),
        }
    }

    fn frame_header<B: Buf>(src: &BufList<B>) -> Option<(frame::FrameType, u64, usize)> {
        let mut cursor = src.cursor();
        let ty = frame::FrameType::decode(&mut cursor).ok()?;
        if ty == frame::FrameType::WEBTRANSPORT_BI_STREAM {
            return None;
        }
        let length = crate::proto::varint::VarInt::decode(&mut cursor)
            .ok()?
            .into_inner();
        Some((ty, length, cursor.remaining()))
    }

    fn incomplete_payload_type<B: Buf>(src: &BufList<B>) -> Option<frame::FrameType> {
        let (ty, length, available) = Self::frame_header(src)?;
        (length > available as u64).then_some(ty)
    }

    #[cfg(test)]
    fn decode<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        self.decode_with_context(src, true)
    }

    fn decode_with_context<B: Buf>(
        &mut self,
        src: &mut BufList<B>,
        allow_headers: bool,
    ) -> Result<Option<Frame<PayloadLen>>, FrameStreamError> {
        // Decode in a loop since we ignore unknown frames, and there may be
        // other frames already in our BufList.
        loop {
            if !src.has_remaining() {
                return Ok(None);
            }

            if self.accept_truncated_response_payloads {
                if let Some((ty, _, _)) = Self::frame_header(src) {
                    let allowed_known = ty == frame::FrameType::DATA
                        || (allow_headers && ty == frame::FrameType::HEADERS);
                    // Chrome recognizes ORIGIN and ACCEPT_CH even though this backend
                    // does not implement those control-frame extensions.
                    if (ty.is_known() && !allowed_known) || matches!(ty.value(), 0x0c | 0x89) {
                        return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                            ty.value(),
                        )));
                    }
                }
            }

            if let Some(min) = self.expected {
                if src.remaining() < min {
                    return Ok(None);
                }
            }

            let (pos, decoded) = {
                let mut cur = src.cursor();
                let decoded = Frame::decode(&mut cur);
                (cur.position(), decoded)
            };

            match decoded {
                Err(frame::FrameError::UnknownFrame(_ty)) => {
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1
                    //# Frames of unknown types (Section 9), including reserved frames
                    //# (Section 7.2.8) MAY be sent on a request or push stream before,
                    //# after, or interleaved with other frames described in this section.
                    //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.8
                    //# Endpoints MUST
                    //# NOT consider these frames to have any meaning upon receipt.
                    #[cfg(feature = "tracing")]
                    trace!("ignore unknown frame type {:#x}", _ty);

                    src.advance(pos);
                    self.expected = None;
                    continue;
                }
                Err(frame::FrameError::Incomplete(min)) => {
                    self.expected = Some(min);
                    return Ok(None);
                }
                Ok(frame) => {
                    src.advance(pos);
                    self.expected = None;
                    return Ok(Some(frame));
                }
                // -------------- Map the error Values --------------
                Err(frame::FrameError::InvalidStreamId(e)) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidStreamId(e),
                    ));
                }
                Err(frame::FrameError::InvalidPushId(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::InvalidPushId(
                        e,
                    )));
                }
                Err(frame::FrameError::Settings(e)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Settings(e)));
                }
                Err(frame::FrameError::UnsupportedFrame(ty)) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(
                        ty,
                    )));
                }
                Err(frame::FrameError::InvalidFrameValue) => {
                    return Err(FrameStreamError::Proto(
                        FrameProtocolError::InvalidFrameValue,
                    ));
                }
                Err(frame::FrameError::Malformed) => {
                    return Err(FrameStreamError::Proto(FrameProtocolError::Malformed));
                }
            }
        }
    }
}

#[derive(Debug)]
/// Errors that can occur while decoding frames
pub enum FrameStreamError {
    Proto(FrameProtocolError),
    Quic(StreamErrorIncoming),
    UnexpectedEnd,
}

#[derive(Debug, PartialEq)]
/// Protocol specific errors that can occur while decoding frames in a stream
pub enum FrameProtocolError {
    Malformed,
    ForbiddenFrame(u64), // Known (http2) frames that should generate an error
    InvalidFrameValue,
    Settings(SettingsError),
    InvalidStreamId(InvalidStreamId),
    InvalidPushId(InvalidPushId),
}

#[cfg(test)]
mod tests {
    use super::*;

    use assert_matches::assert_matches;
    use bytes::{BufMut, Bytes, BytesMut};
    use futures_util::future::poll_fn;
    use std::{cell::Cell, collections::VecDeque, rc::Rc};

    use crate::proto::{coding::Encode, frame::FrameType, varint::VarInt};

    // Decoder

    #[test]
    fn one_frame() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn incomplete_frame() {
        let frame = Frame::headers(&b"salut"[..]);

        let mut buf = BytesMut::with_capacity(16);
        frame.encode(&mut buf);
        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    #[test]
    fn header_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers(&b"salut"[..]).encode_with_payload(&mut buf);
        let mut buf_list = BufList::new();
        // Cut buffer between type and length
        buf_list.push(&buf[..1]);
        buf_list.push(&buf[1..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn varint_spread_multiple_buf() {
        let mut buf = BytesMut::with_capacity(16);
        Frame::headers("salut".repeat(1024)).encode_with_payload(&mut buf);

        let mut buf_list = BufList::new();
        // Cut buffer in the middle of length's varint
        buf_list.push(&buf[..2]);
        buf_list.push(&buf[2..]);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf_list), Ok(Some(Frame::Headers(_))));
    }

    #[test]
    fn two_frames_then_incomplete() {
        let mut buf = BytesMut::with_capacity(64);
        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);

        buf.truncate(buf.len() - 1);
        let mut buf = BufList::from(buf);

        let mut decoder = FrameDecoder::default();
        assert_matches!(decoder.decode(&mut buf), Ok(Some(Frame::Headers(_))));
        assert_matches!(
            decoder.decode(&mut buf),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_matches!(decoder.decode(&mut buf), Ok(None));
    }

    // FrameStream

    #[test]
    fn incomplete_header_classification_excludes_payloads_and_webtransport() {
        for bytes in [
            &b"\x40"[..],
            &b"\x01"[..],
            &b"\x01\x40"[..],
            &b"\x40\x42\x80\x00"[..],
        ] {
            assert!(
                FrameDecoder::incomplete_header(&BufList::from(Bytes::copy_from_slice(bytes))),
                "{bytes:?}"
            );
        }
        for bytes in [
            &b"\x01\x05abc"[..],
            &b"\x21\x05abc"[..],
            &b"\x00\x05abc"[..],
            &b"\x40\x41"[..],
        ] {
            assert!(
                !FrameDecoder::incomplete_header(&BufList::from(Bytes::copy_from_slice(bytes))),
                "{bytes:?}"
            );
        }
        assert!(!FrameDecoder::incomplete_header(&BufList::<Bytes>::new()));
    }

    #[tokio::test]
    async fn incomplete_header_wait_classification_requires_opt_in_and_fin() {
        for enabled in [false, true] {
            for bytes in [&b"\x40"[..], &b"\x01\x40"[..]] {
                let mut recv = FakeRecv::default();
                recv.chunk(Bytes::copy_from_slice(bytes));
                let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv))
                    .wait_for_incomplete_response_frame_headers(enabled);
                assert!(!stream.waits_for_incomplete_header());
                assert_matches!(
                    poll_fn(|cx| stream.poll_next(cx)).await,
                    Err(FrameStreamError::UnexpectedEnd)
                );
                assert_eq!(stream.waits_for_incomplete_header(), enabled);
            }
        }
    }

    macro_rules! assert_poll_matches {
        ($poll_fn:expr, $match:pat) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match
            );
        };
        ($poll_fn:expr, $match:pat if $cond:expr ) => {
            assert_matches!(
                poll_fn($poll_fn).await,
                $match if $cond
            );
        }
    }

    #[tokio::test]
    async fn poll_full_request() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        Frame::Data(&b"body"[..]).encode_with_payload(&mut buf);
        Frame::headers(&b"trailer"[..]).encode_with_payload(&mut buf);
        recv.chunk(buf.freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 4
        );
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
    }

    #[tokio::test]
    async fn poll_next_applies_backpressure_before_reading_more_chunks() {
        const CHUNK_COUNT: usize = 64;
        const FRAMES_PER_CHUNK: usize = 16;
        const FRAME_PAYLOAD_SIZE: usize = 1024;

        let mut encoded_chunk = BytesMut::new();
        let payload = Bytes::from(vec![0_u8; FRAME_PAYLOAD_SIZE]);
        for _ in 0..FRAMES_PER_CHUNK {
            Frame::headers(payload.clone()).encode_with_payload(&mut encoded_chunk);
        }
        let encoded_chunk = encoded_chunk.freeze();
        let max_buffered = encoded_chunk.len();

        let mut recv = FakeRecv::default();
        for _ in 0..CHUNK_COUNT {
            recv.chunk(encoded_chunk.clone());
        }
        let transport_polls = recv.poll_count.clone();

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // Model a consumer that processes one frame per wake while the
        // transport can provide chunks containing many complete frames.
        for _ in 0..CHUNK_COUNT {
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(_))));
        }

        let buffered = stream.stream.buf().remaining();
        assert!(
            buffered <= max_buffered,
            "frame buffering grew past one transport chunk: {buffered} > {max_buffered}"
        );
        assert_eq!(
            transport_polls.get(),
            CHUNK_COUNT.div_ceil(FRAMES_PER_CHUNK),
            "transport was polled while complete frames were still buffered"
        );
    }

    #[tokio::test]
    async fn poll_next_incomplete_frame() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        Frame::headers(&b"header"[..]).encode_with_payload(&mut buf);
        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 1));
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    #[should_panic(
        expected = "There is still data to read, please call poll_data() until it returns None"
    )]
    async fn poll_next_reamining_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // There is still data to consume, poll_next should panic
        let _ = poll_fn(|cx| stream.poll_next(cx)).await;
    }

    #[tokio::test]
    async fn poll_data_split() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Body is split into two bufs
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        let mut buf = buf.freeze();
        recv.chunk(buf.split_to(buf.len() - 2));
        recv.chunk(buf);
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        // We get the total size of data about to be received
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        // Then we get parts of body, chunked as they arrived
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if b.remaining() == 2
        );
    }

    #[tokio::test]
    async fn poll_data_unexpected_end() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // Truncated body
        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"b"[..]);
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn response_payload_eof_keeps_partial_data() {
        let mut recv = FakeRecv::default();
        recv.chunk(Bytes::from_static(b"\x00\x05abc"));
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(5))))
        );
        assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(Some(bytes)) if bytes == b"abc".as_slice());
        assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(None));
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
    }

    #[tokio::test]
    async fn response_payload_eof_accepts_headers_and_unknown_payloads() {
        for bytes in [
            b"\x01\x05ab".as_slice(),
            b"\x21\x05x".as_slice(),
            b"\x01\x05".as_slice(),
        ] {
            let mut recv = FakeRecv::default();
            recv.chunk(Bytes::copy_from_slice(bytes));
            let mut stream: FrameStream<_, ()> =
                FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
        }
    }

    #[tokio::test]
    async fn response_payload_eof_preserves_incomplete_header_errors() {
        for bytes in [b"\x40".as_slice(), b"\x00\x40".as_slice()] {
            let mut recv = FakeRecv::default();
            recv.chunk(Bytes::copy_from_slice(bytes));
            let mut stream: FrameStream<_, ()> =
                FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
            assert_poll_matches!(
                |cx| stream.poll_next(cx),
                Err(FrameStreamError::UnexpectedEnd)
            );
        }
    }

    #[tokio::test]
    async fn response_payload_eof_preserves_trailer_and_control_ordering() {
        for (bytes, ty, after_trailers) in [
            (b"\x01\x05x".as_slice(), 1, true),
            (b"\x04\x05x".as_slice(), 4, false),
            (b"\x06\x05x".as_slice(), 6, false),
        ] {
            let mut recv = FakeRecv::default();
            recv.chunk(Bytes::copy_from_slice(bytes));
            let mut stream: FrameStream<_, ()> =
                FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
            let result = poll_fn(|cx| {
                if after_trailers {
                    stream.poll_next_after_trailers(cx)
                } else {
                    stream.poll_next(cx)
                }
            })
            .await;
            assert_matches!(result, Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(value))) if value == ty);
        }
        let mut recv = FakeRecv::default();
        recv.chunk(Bytes::from_static(b"\x21\x05x"));
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
        assert_poll_matches!(|cx| stream.poll_next_after_trailers(cx), Ok(None));
    }

    #[tokio::test]
    async fn response_payload_eof_preserves_complete_invalid_frame_payload() {
        let mut recv = FakeRecv::default();
        recv.chunk(Bytes::from_static(b"\x01\x03\x00\x00\xff"));
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(Some(Frame::Headers(payload))) if payload == b"\x00\x00\xff".as_slice());
    }

    #[tokio::test]
    async fn response_payload_eof_does_not_change_webtransport() {
        let mut recv = FakeRecv::default();
        recv.chunk(Bytes::from_static(b"\x40\x41\x00abc"));
        let mut stream: FrameStream<_, ()> =
            FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::WebTransportStream(_)))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Err(FrameStreamError::UnexpectedEnd)
        );
    }

    #[tokio::test]
    async fn response_control_headers_reject_without_waiting_for_fin() {
        for (bytes, ty) in [
            (b"\x04\x05x".as_slice(), 4),
            (b"\x06\x05x".as_slice(), 6),
            (b"\x0c\x05x".as_slice(), 12),
            (b"\x0c\x01x".as_slice(), 12),
            (b"\x40\x89\x05x".as_slice(), 137),
            (b"\x40\x89\x01x".as_slice(), 137),
            (b"\x21\x00\x40\x89\x05x".as_slice(), 137),
        ] {
            let mut recv = FakeRecv::default();
            recv.chunk(Bytes::copy_from_slice(bytes));
            let polls = recv.poll_count.clone();
            let mut stream: FrameStream<_, ()> =
                FrameStream::new(BufRecvStream::new(recv)).accept_truncated_response_payloads(true);
            assert_poll_matches!(|cx| stream.poll_next(cx), Err(FrameStreamError::Proto(FrameProtocolError::ForbiddenFrame(value))) if value == ty);
            assert_eq!(polls.get(), 1, "the forbidden frame header must suffice");
        }
    }

    #[tokio::test]
    async fn poll_data_ignores_unknown_frames() {
        use crate::proto::varint::BufMutExt as _;

        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        // grease a lil
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(0);

        // grease with some data
        crate::proto::frame::FrameType::grease().encode(&mut buf);
        buf.write_var(6);
        buf.put_slice(b"grease");

        // Body
        Frame::Data(Bytes::from("body")).encode_with_payload(&mut buf);

        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"body"
        );
    }

    #[tokio::test]
    async fn poll_data_eos_but_buffered_data() {
        let mut recv = FakeRecv::default();
        let mut buf = BytesMut::with_capacity(64);

        FrameType::DATA.encode(&mut buf);
        VarInt::from(4u32).encode(&mut buf);
        buf.put_slice(&b"bo"[..]);
        recv.chunk(buf.clone().freeze());

        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(4))))
        );

        buf.truncate(0);
        buf.put_slice(&b"dy"[..]);
        stream.stream.buf_mut().push_bytes(&mut buf.freeze());

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"bo"
        );

        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(b)) if &*b == b"dy"
        );
    }

    #[tokio::test]
    async fn poll_data_delayed_fin_allows_completion() {
        let mut recv = FakeRecv {
            pending_at: Some(2),
            ..FakeRecv::default()
        };
        let mut buf = BytesMut::new();
        FrameType::DATA.encode(&mut buf);
        VarInt::from(5u32).encode(&mut buf);
        buf.put_slice(b"abc");
        recv.chunk(buf.freeze());
        let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

        assert_poll_matches!(
            |cx| stream.poll_next(cx),
            Ok(Some(Frame::Data(PayloadLen(5))))
        );
        assert_poll_matches!(
            |cx| to_bytes(stream.poll_data(cx)),
            Ok(Some(bytes)) if &*bytes == b"abc"
        );
        assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(None));
        assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
    }

    #[tokio::test]
    async fn poll_data_webtransport_fin_allows_completion() {
        for fragmented in [true, false] {
            let mut recv = FakeRecv::default();
            let mut buf = BytesMut::new();
            FrameType::WEBTRANSPORT_BI_STREAM.encode(&mut buf);
            VarInt::from(0u32).encode(&mut buf);
            recv.chunk(buf.freeze());
            if fragmented {
                recv.chunk(Bytes::from_static(b"abc"));
                recv.chunk(Bytes::from_static(b"de"));
            }
            let mut stream: FrameStream<_, ()> = FrameStream::new(BufRecvStream::new(recv));

            assert_poll_matches!(
                |cx| stream.poll_next(cx),
                Ok(Some(Frame::WebTransportStream(_)))
            );
            if fragmented {
                assert_poll_matches!(
                    |cx| to_bytes(stream.poll_data(cx)),
                    Ok(Some(bytes)) if &*bytes == b"abc"
                );
                assert_poll_matches!(
                    |cx| to_bytes(stream.poll_data(cx)),
                    Ok(Some(bytes)) if &*bytes == b"de"
                );
            }
            assert_poll_matches!(|cx| to_bytes(stream.poll_data(cx)), Ok(None));
            assert_poll_matches!(|cx| stream.poll_next(cx), Ok(None));
        }
    }

    // Helpers

    #[derive(Default)]
    struct FakeRecv {
        chunks: VecDeque<Bytes>,
        poll_count: Rc<Cell<usize>>,
        pending_at: Option<usize>,
    }

    impl FakeRecv {
        fn chunk(&mut self, buf: Bytes) -> &mut Self {
            self.chunks.push_back(buf);
            self
        }
    }

    impl RecvStream for FakeRecv {
        type Buf = Bytes;

        fn poll_data(
            &mut self,
            cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Self::Buf>, StreamErrorIncoming>> {
            self.poll_count.set(self.poll_count.get() + 1);
            if self.pending_at == Some(self.poll_count.get()) {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Poll::Ready(Ok(self.chunks.pop_front()))
        }

        fn stop_sending(&mut self, _: u64) {
            unimplemented!()
        }

        fn recv_id(&self) -> StreamId {
            unimplemented!()
        }
    }

    fn to_bytes(
        x: Poll<Result<Option<impl Buf>, FrameStreamError>>,
    ) -> Poll<Result<Option<Bytes>, FrameStreamError>> {
        x.map(|b| b.map(|b| b.map(|mut b| b.copy_to_bytes(b.remaining()))))
    }
}
