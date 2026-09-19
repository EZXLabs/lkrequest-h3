use std::{collections::HashSet, task::Poll, time::Duration};

use bytes::{Buf, Bytes};
use futures_util::future;
use http::Request;
use tokio::sync::oneshot;

use crate::{
    client,
    config::Config,
    proto::{coding::Encode, frame, varint::BufExt},
};

use super::Pair;

struct WireCapture {
    settings: Vec<(u64, u64)>,
    control_frames: Vec<(u64, Vec<u8>)>,
    request_frames: Vec<(u64, Vec<u8>)>,
    extra_uni_stream: bool,
}

async fn read_varint(stream: &mut quinn::RecvStream) -> u64 {
    let mut encoded = [0u8; 8];
    stream.read_exact(&mut encoded[..1]).await.unwrap();
    let len = 1 << (encoded[0] >> 6);
    stream.read_exact(&mut encoded[1..len]).await.unwrap();
    (&encoded[..len]).get_var().unwrap()
}

async fn read_frame(stream: &mut quinn::RecvStream) -> (u64, Vec<u8>) {
    let ty = read_varint(stream).await;
    let len = read_varint(stream).await as usize;
    let mut payload = vec![0; len];
    stream.read_exact(&mut payload).await.unwrap();
    (ty, payload)
}

async fn capture_wire(chromium: bool, setting_grease: bool, control_grease: bool) -> WireCapture {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (done_tx, done_rx) = oneshot::channel();

    let client = async {
        let mut builder = client::builder();
        builder
            .send_grease(setting_grease)
            .chromium_grease(chromium)
            .control_grease_frame(control_grease)
            .ordered_settings(vec![(1, 65536), (7, 100)])
            .priority_updates(vec![(0, b"u=0, i".to_vec())]);
        let (mut driver, mut sender) = builder
            .build::<_, _, Bytes>(pair.client().await)
            .await
            .unwrap();
        let mut request = sender
            .send_request(Request::get("https://localhost/").body(()).unwrap())
            .await
            .unwrap();
        request.finish().await.unwrap();
        future::poll_fn(|cx| {
            let _ = driver.poll_close(cx);
            Poll::Ready(())
        })
        .await;
        tokio::select! {
            result = done_rx => result.unwrap(),
            error = future::poll_fn(|cx| driver.poll_close(cx)) => panic!("client closed: {error:?}"),
        }
    };

    let server = async {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut server_control = connection.open_uni().await.unwrap();
        server_control.write_all(&[0, 4, 0]).await.unwrap();
        let mut control = connection.accept_uni().await.unwrap();
        assert_eq!(read_varint(&mut control).await, 0);
        let (ty, settings_bytes) = read_frame(&mut control).await;
        assert_eq!(ty, 4, "SETTINGS must be the first control frame");
        let mut input = settings_bytes.as_slice();
        let mut settings = Vec::new();
        while input.has_remaining() {
            settings.push((input.get_var().unwrap(), input.get_var().unwrap()));
        }
        let mut control_frames = Vec::new();
        if control_grease {
            control_frames.push(read_frame(&mut control).await);
        }
        control_frames.push(read_frame(&mut control).await);

        let (_send, mut recv) = connection.accept_bi().await.unwrap();
        let request = recv.read_to_end(4096).await.unwrap();
        let mut input = request.as_slice();
        let mut request_frames = Vec::new();
        while input.has_remaining() {
            let ty = input.get_var().unwrap();
            let len = input.get_var().unwrap() as usize;
            request_frames.push((ty, input.copy_to_bytes(len).to_vec()));
        }

        let mut stream_types = Vec::new();
        for _ in 0..2 {
            let mut stream = connection.accept_uni().await.unwrap();
            stream_types.push(read_varint(&mut stream).await);
        }
        stream_types.sort_unstable();
        assert_eq!(stream_types, [2, 3]);
        let extra_uni_stream =
            tokio::time::timeout(Duration::from_millis(100), connection.accept_uni())
                .await
                .is_ok();
        done_tx.send(()).unwrap();
        WireCapture {
            settings,
            control_frames,
            request_frames,
            extra_uni_stream,
        }
    };

    tokio::time::timeout(Duration::from_secs(5), async {
        let (_, capture) = tokio::join!(client, server);
        capture
    })
    .await
    .expect("wire capture timed out")
}

#[tokio::test]
async fn chromium_settings_grease_uses_u32_random_id_and_value() {
    let capture = capture_wire(true, true, true).await;
    assert_eq!(&capture.settings[..2], &[(1, 65536), (7, 100)]);
    assert_eq!(capture.settings.len(), 3);
    let (id, value) = capture.settings[2];
    assert_eq!((id - 33) % 31, 0);
    assert!(
        id <= 133_143_986_178,
        "GREASE setting ID exceeds Chromium's u32 range: {id}"
    );
    assert!(value <= u32::MAX as u64);
}

#[tokio::test]
async fn chromium_control_grease_has_short_random_payload_before_priority() {
    let capture = capture_wire(true, true, true).await;
    let (ty, payload) = &capture.control_frames[0];
    assert_eq!((ty - 33) % 31, 0);
    assert!(
        payload.len() <= 3,
        "Chromium GREASE payload must be 0..=3 bytes"
    );
    assert!(ty <= &133_143_986_178);
    assert_eq!(payload.len() as u64, ((ty - 33) / 31) % 4);
    assert_eq!(capture.control_frames[1], (0xf0700, b"\0u=0, i".to_vec()));
}

#[tokio::test]
async fn chromium_get_fin_has_no_request_grease_or_reserved_uni_stream() {
    let capture = capture_wire(true, true, true).await;
    assert_eq!(
        capture.request_frames.len(),
        1,
        "GET must end immediately after HEADERS"
    );
    assert_eq!(capture.request_frames[0].0, 1);
    assert!(!capture.extra_uni_stream);
}

#[tokio::test]
async fn legacy_grease_keeps_zero_setting_and_six_byte_frame_payloads() {
    let capture = capture_wire(false, true, true).await;
    assert_eq!(capture.settings[2].1, 0);
    assert_eq!(capture.control_frames[0].1, b"grease");
    assert_eq!(capture.request_frames.len(), 2);
    assert_eq!(capture.request_frames[1].1, b"grease");
    assert!(capture.extra_uni_stream);
}

#[tokio::test]
async fn chromium_mode_respects_disabled_grease_flags() {
    let capture = capture_wire(true, false, false).await;
    assert_eq!(capture.settings, [(1, 65536), (7, 100)]);
    assert_eq!(capture.control_frames, [(0xf0700, b"\0u=0, i".to_vec())]);
    assert_eq!(capture.request_frames.len(), 1);
    assert!(!capture.extra_uni_stream);
}

#[tokio::test]
async fn chromium_control_grease_can_be_enabled_without_setting_grease() {
    let capture = capture_wire(true, false, true).await;
    assert_eq!(capture.settings, [(1, 65536), (7, 100)]);
    assert_eq!(capture.control_frames.len(), 2);
    assert!(capture.control_frames[0].1.len() <= 3);
    assert_eq!(capture.control_frames[1], (0xf0700, b"\0u=0, i".to_vec()));
    assert_eq!(capture.request_frames.len(), 1);
    assert!(!capture.extra_uni_stream);
}

#[tokio::test]
async fn chromium_setting_grease_can_be_enabled_without_control_grease() {
    let capture = capture_wire(true, true, false).await;
    assert_eq!(capture.settings.len(), 3);
    assert_eq!((capture.settings[2].0 - 33) % 31, 0);
    assert_eq!(capture.control_frames, [(0xf0700, b"\0u=0, i".to_vec())]);
    assert_eq!(capture.request_frames.len(), 1);
    assert!(!capture.extra_uni_stream);
}

#[test]
fn chromium_sorts_settings_even_when_random_grease_is_disabled() {
    let settings = frame::Settings::try_from(Config {
        send_grease: false,
        chromium_grease: true,
        ordered_settings: Some(vec![(51, 1), (33, 42), (7, 100), (1, 65536)]),
        ..Config::default()
    })
    .unwrap();
    assert_eq!(
        decode_settings(settings),
        [(1, 65536), (7, 100), (33, 42), (51, 1)]
    );
}

#[test]
fn generic_settings_preserve_explicit_order() {
    let settings = frame::Settings::try_from(Config {
        send_grease: false,
        ordered_settings: Some(vec![(51, 1), (33, 42), (7, 100), (1, 65536)]),
        ..Config::default()
    })
    .unwrap();
    assert_eq!(
        decode_settings(settings),
        [(51, 1), (33, 42), (7, 100), (1, 65536)]
    );
}

fn decode_settings(settings: frame::Settings) -> Vec<(u64, u64)> {
    let mut wire = Vec::new();
    settings.encode(&mut wire);
    let mut input = wire.as_slice();
    assert_eq!(input.get_var().unwrap(), 4);
    let _length = input.get_var().unwrap();
    let mut entries = Vec::new();
    while input.has_remaining() {
        entries.push((input.get_var().unwrap(), input.get_var().unwrap()));
    }
    entries
}

#[test]
fn chromium_settings_grease_randomizes_value_independently_from_id() {
    fastrand::seed(42);
    let mut values = HashSet::new();
    let mut independent = false;
    for _ in 0..32 {
        let settings = frame::Settings::try_from(Config {
            chromium_grease: true,
            ordered_settings: Some(Vec::new()),
            ..Config::default()
        })
        .unwrap();
        let mut wire = Vec::new();
        settings.encode(&mut wire);
        let mut input = wire.as_slice();
        assert_eq!(input.get_var().unwrap(), 4);
        let _length = input.get_var().unwrap();
        let id = input.get_var().unwrap();
        let value = input.get_var().unwrap();
        assert!(!input.has_remaining());
        values.insert(value);
        independent |= value != (id - 33) / 31;
    }
    assert!(values.len() > 1, "GREASE setting value must not be fixed");
    assert!(
        independent,
        "GREASE setting value must use a separate random draw"
    );
}

#[test]
fn chromium_control_grease_randomizes_payload_length_and_bytes() {
    fastrand::seed(42);
    let mut lengths = HashSet::new();
    let mut nonempty_payloads = HashSet::new();
    for _ in 0..64 {
        let mut wire = Vec::new();
        frame::Frame::<Bytes>::ChromiumGrease.encode(&mut wire);
        let mut input = wire.as_slice();
        let ty = input.get_var().unwrap();
        let len = input.get_var().unwrap();
        assert_eq!(len, ((ty - 33) / 31) % 4);
        assert_eq!(len as usize, input.remaining());
        lengths.insert(len);
        if len != 0 {
            nonempty_payloads.insert(input.to_vec());
        }
    }
    assert_eq!(lengths, HashSet::from([0, 1, 2, 3]));
    assert!(
        nonempty_payloads.len() > 3,
        "GREASE payload bytes must vary"
    );
}
