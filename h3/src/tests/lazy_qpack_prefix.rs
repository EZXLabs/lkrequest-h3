use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    sync::{Arc, Mutex},
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use futures_util::{task::noop_waker_ref, FutureExt};

use crate::{
    client,
    error::{Code, ConnectionError, LocalError},
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};

const CONTROL: u64 = 2;
const ENCODER: u64 = 6;
const DECODER: u64 = 10;

#[derive(Clone, Copy)]
enum Step {
    Pending,
    Zero,
    Accept(usize),
    Stop,
    ConnectionError,
    Unknown,
}

#[derive(Default)]
struct Recording {
    opened: Vec<u64>,
    bytes: BTreeMap<u64, Vec<u8>>,
    steps: BTreeMap<u64, VecDeque<Step>>,
    closed: Vec<u64>,
}

type Shared = Arc<Mutex<Recording>>;

#[derive(Clone)]
struct MemoryConnection(Shared);

struct MemoryStream {
    id: u64,
    recording: Shared,
}

impl quic::OpenStreams<Bytes> for MemoryConnection {
    type BidiStream = MemoryStream;
    type SendStream = MemoryStream;

    fn poll_open_bidi(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        unreachable!("this fixture exercises only critical streams")
    }

    fn poll_open_send(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        let mut recording = self.0.lock().unwrap();
        let id = 2 + 4 * recording.opened.len() as u64;
        recording.opened.push(id);
        recording.bytes.insert(id, Vec::new());
        Poll::Ready(Ok(MemoryStream {
            id,
            recording: self.0.clone(),
        }))
    }

    fn close(&mut self, code: Code, _: &[u8]) {
        self.0.lock().unwrap().closed.push(code.value());
    }
}

impl quic::Connection<Bytes> for MemoryConnection {
    type RecvStream = MemoryStream;
    type OpenStreams = Self;

    fn poll_accept_recv(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        Poll::Pending
    }

    fn poll_accept_bidi(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        Poll::Pending
    }

    fn opener(&self) -> Self::OpenStreams {
        self.clone()
    }
}

impl quic::RecvStream for MemoryStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        _: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        Poll::Pending
    }

    fn stop_sending(&mut self, _: u64) {
        unreachable!("no incoming data in this fixture")
    }

    fn recv_id(&self) -> StreamId {
        StreamId::try_from(self.id).unwrap()
    }
}

impl quic::SendStream<Bytes> for MemoryStream {
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        let mut data = data.into();
        let mut recording = self.recording.lock().unwrap();
        let output = recording.bytes.get_mut(&self.id).unwrap();
        while data.has_remaining() {
            let count = data.chunk().len();
            output.extend_from_slice(data.chunk());
            data.advance(count);
        }
        Ok(())
    }

    fn poll_finish(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        unreachable!("critical streams must remain open")
    }

    fn reset(&mut self, _: u64) {
        unreachable!("critical streams must not be reset")
    }

    fn send_id(&self) -> StreamId {
        StreamId::try_from(self.id).unwrap()
    }
}

impl quic::SendStreamUnframed<Bytes> for MemoryStream {
    fn poll_send<D: Buf>(
        &mut self,
        _: &mut Context<'_>,
        data: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        let mut recording = self.recording.lock().unwrap();
        let step = recording.steps.entry(self.id).or_default().pop_front();
        let count = match step {
            Some(Step::Pending) => return Poll::Pending,
            Some(Step::Zero) => return Poll::Ready(Ok(0)),
            Some(Step::Stop) => {
                return Poll::Ready(Err(StreamErrorIncoming::StreamTerminated {
                    error_code: 0x155,
                }));
            }
            Some(Step::ConnectionError) => {
                return Poll::Ready(Err(StreamErrorIncoming::ConnectionErrorIncoming {
                    connection_error: ConnectionErrorIncoming::ApplicationClose {
                        error_code: 0x155,
                    },
                }));
            }
            Some(Step::Unknown) => {
                return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                    std::io::Error::other("controlled QPACK write error"),
                ))));
            }
            Some(Step::Accept(limit)) => limit.min(data.remaining()),
            None => data.remaining(),
        };
        let accepted = data.copy_to_bytes(count);
        recording
            .bytes
            .get_mut(&self.id)
            .unwrap()
            .extend_from_slice(&accepted);
        Poll::Ready(Ok(count))
    }
}

type Driver = client::Connection<MemoryConnection, Bytes>;
type Sender = client::SendRequest<MemoryConnection, Bytes>;

fn fixture(defer: Option<bool>) -> (Driver, Sender, Shared) {
    let recording = Shared::default();
    let mut builder = client::builder();
    builder.send_grease(false);
    if let Some(defer) = defer {
        builder.defer_qpack_stream_prefixes(defer);
    }
    let (driver, sender) = builder
        .build(MemoryConnection(recording.clone()))
        .now_or_never()
        .expect("constructor must not wait for QPACK instructions")
        .expect("constructor");
    assert_eq!(
        recording.lock().unwrap().opened,
        [CONTROL, ENCODER, DECODER]
    );
    (driver, sender, recording)
}

fn bytes(recording: &Shared, id: u64) -> Vec<u8> {
    recording.lock().unwrap().bytes[&id].clone()
}

fn steps(recording: &Shared, id: u64, values: impl IntoIterator<Item = Step>) {
    recording
        .lock()
        .unwrap()
        .steps
        .insert(id, values.into_iter().collect());
}

fn poll_decoder(driver: &mut Driver) -> Result<(), ConnectionError> {
    driver
        .inner
        .poll_qpack(&mut Context::from_waker(noop_waker_ref()))
}

#[test]
fn lazy_qpack_prefix_default_and_explicit_false_remain_eager() {
    for setting in [None, Some(false)] {
        let (mut driver, _sender, recording) = fixture(setting);
        assert_eq!(bytes(&recording, ENCODER), [2]);
        assert_eq!(bytes(&recording, DECODER), [3]);
        poll_decoder(&mut driver).unwrap();
        assert_eq!(bytes(&recording, ENCODER), [2]);
        assert_eq!(bytes(&recording, DECODER), [3]);
    }
}

#[test]
fn lazy_qpack_prefix_idle_enabled_preserves_stream_ids_and_settings() {
    let (_eager_driver, _eager_sender, eager) = fixture(Some(false));
    let (mut driver, _sender, recording) = fixture(Some(true));
    assert_eq!(bytes(&recording, CONTROL), bytes(&eager, CONTROL));
    assert_eq!(bytes(&recording, CONTROL)[..2], [0, 4]);
    for _ in 0..3 {
        poll_decoder(&mut driver).unwrap();
        driver
            .inner
            .send_qpack_encoder_instructions_for_test(Bytes::new())
            .now_or_never()
            .expect("empty encoder batch");
    }
    assert!(bytes(&recording, ENCODER).is_empty());
    assert!(bytes(&recording, DECODER).is_empty());
}

#[test]
fn lazy_qpack_prefix_decoder_first_and_later_instructions_have_one_type() {
    for defer in [false, true] {
        let (mut driver, _sender, recording) = fixture(Some(defer));
        driver.inner.shared.queue_qpack_header_ack(0);
        poll_decoder(&mut driver).unwrap();
        assert_eq!(bytes(&recording, DECODER), [3, 0x80]);
        driver.inner.shared.queue_qpack_header_ack(4);
        poll_decoder(&mut driver).unwrap();
        poll_decoder(&mut driver).unwrap();
        assert_eq!(bytes(&recording, DECODER), [3, 0x80, 0x84]);
        assert_eq!(
            bytes(&recording, ENCODER),
            if defer { vec![] } else { vec![2] }
        );
    }
}

#[test]
fn lazy_qpack_prefix_encoder_first_and_later_instructions_have_one_type() {
    for defer in [false, true] {
        let (mut driver, _sender, recording) = fixture(Some(defer));
        driver
            .inner
            .send_qpack_encoder_instructions_for_test(Bytes::from_static(&[0x20]))
            .now_or_never()
            .expect("first encoder instruction");
        driver
            .inner
            .send_qpack_encoder_instructions_for_test(Bytes::from_static(&[0x21]))
            .now_or_never()
            .expect("later encoder instruction");
        assert_eq!(bytes(&recording, ENCODER), [2, 0x20, 0x21]);
        assert_eq!(
            bytes(&recording, DECODER),
            if defer { vec![] } else { vec![3] }
        );
    }
}

#[test]
fn lazy_qpack_prefix_decoder_pending_zero_partial_and_new_queue_keep_order() {
    let (mut driver, _sender, recording) = fixture(Some(true));
    steps(
        &recording,
        DECODER,
        [
            Step::Pending,
            Step::Zero,
            Step::Accept(1),
            Step::Pending,
            Step::Accept(1),
            Step::Pending,
        ],
    );
    driver.inner.shared.queue_qpack_header_ack(0);
    poll_decoder(&mut driver).unwrap();
    assert!(bytes(&recording, DECODER).is_empty());
    poll_decoder(&mut driver).unwrap();
    assert!(bytes(&recording, DECODER).is_empty());
    poll_decoder(&mut driver).unwrap();
    assert_eq!(bytes(&recording, DECODER), [3]);
    driver.inner.shared.queue_qpack_header_ack(4);
    poll_decoder(&mut driver).unwrap();
    assert_eq!(bytes(&recording, DECODER), [3, 0x80]);
    poll_decoder(&mut driver).unwrap();
    assert_eq!(bytes(&recording, DECODER), [3, 0x80, 0x84]);
    driver.inner.shared.queue_qpack_header_ack(8);
    poll_decoder(&mut driver).unwrap();
    assert_eq!(bytes(&recording, DECODER), [3, 0x80, 0x84, 0x88]);
}

#[test]
fn lazy_qpack_prefix_encoder_pending_future_drop_retains_queued_bytes() {
    let (mut driver, _sender, recording) = fixture(Some(true));
    steps(
        &recording,
        ENCODER,
        [Step::Pending, Step::Zero, Step::Accept(1), Step::Pending],
    );
    let mut cx = Context::from_waker(noop_waker_ref());
    let mut first = Box::pin(
        driver
            .inner
            .send_qpack_encoder_instructions_for_test(Bytes::from_static(&[0x20, 0x21])),
    );
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(bytes(&recording, ENCODER).is_empty());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert!(bytes(&recording, ENCODER).is_empty());
    assert!(first.as_mut().poll(&mut cx).is_pending());
    assert_eq!(bytes(&recording, ENCODER), [2]);
    drop(first);
    driver
        .inner
        .send_qpack_encoder_instructions_for_test(Bytes::from_static(&[0x22]))
        .now_or_never()
        .expect("retained encoder queue");
    assert_eq!(bytes(&recording, ENCODER), [2, 0x20, 0x21, 0x22]);
}

fn decoder_failure(step: Step, expected: Option<Code>) {
    for prefix_accepted in [false, true] {
        let (mut driver, _sender, recording) = fixture(Some(true));
        let mut script = Vec::new();
        if prefix_accepted {
            script.push(Step::Accept(1));
        }
        script.push(step);
        steps(&recording, DECODER, script);
        driver.inner.shared.queue_qpack_header_ack(0);
        let error = poll_decoder(&mut driver).expect_err("deferred write error must propagate");
        assert_eq!(
            bytes(&recording, DECODER),
            if prefix_accepted { vec![3] } else { vec![] }
        );
        match expected {
            Some(expected) => {
                assert!(matches!(error, ConnectionError::Local {
                    error: LocalError::Application { code, .. }
                } if code == expected));
                assert_eq!(recording.lock().unwrap().closed, [expected.value()]);
            }
            None => {
                assert!(matches!(
                    error,
                    ConnectionError::Remote(ConnectionErrorIncoming::ApplicationClose {
                        error_code: 0x155
                    })
                ));
                assert!(recording.lock().unwrap().closed.is_empty());
            }
        }
        assert!(driver.inner.handled_connection_error.is_some());
    }
}

#[test]
fn lazy_qpack_prefix_decoder_stop_preserves_critical_stream_error() {
    decoder_failure(Step::Stop, Some(Code::H3_CLOSED_CRITICAL_STREAM));
}

#[test]
fn lazy_qpack_prefix_decoder_unknown_preserves_decoder_stream_error() {
    decoder_failure(Step::Unknown, Some(Code::QPACK_DECODER_STREAM_ERROR));
}

#[test]
fn lazy_qpack_prefix_decoder_connection_error_preserves_remote_cause() {
    decoder_failure(Step::ConnectionError, None);
}
