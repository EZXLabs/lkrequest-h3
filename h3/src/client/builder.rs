//! HTTP/3 client builder

use std::{
    marker::PhantomData,
    sync::{atomic::AtomicUsize, Arc},
};

use bytes::{Buf, Bytes};

use crate::{
    config::{Config, PseudoHeader},
    connection::ConnectionInner,
    error::ConnectionError,
    quic::{self},
    shared_state::SharedState,
};

use super::connection::{Connection, SendRequest};

/// Start building a new HTTP/3 client
pub fn builder() -> Builder {
    Builder::new()
}

/// Create a new HTTP/3 client with default settings
pub async fn new<C, O>(
    conn: C,
) -> Result<(Connection<C, Bytes>, SendRequest<O, Bytes>), ConnectionError>
where
    C: quic::Connection<Bytes, OpenStreams = O>,
    O: quic::OpenStreams<Bytes>,
{
    //= https://www.rfc-editor.org/rfc/rfc9114#section-3.3
    //= type=implication
    //# Clients SHOULD NOT open more than one HTTP/3 connection to a given IP
    //# address and UDP port, where the IP address and port might be derived
    //# from a URI, a selected alternative service ([ALTSVC]), a configured
    //# proxy, or name resolution of any of these.
    Builder::new().build(conn).await
}

/// HTTP/3 client builder
///
/// Set the configuration for a new client.
///
/// # Examples
/// ```rust
/// # use h3::quic;
/// # async fn doc<C, O, B>(quic: C)
/// # where
/// #   C: quic::Connection<B, OpenStreams = O>,
/// #   O: quic::OpenStreams<B>,
/// #   B: bytes::Buf,
/// # {
/// let h3_conn = h3::client::builder()
///     .max_field_section_size(8192)
///     .build(quic)
///     .await
///     .expect("Failed to build connection");
/// # }
/// ```
pub struct Builder {
    config: Config,
}

impl Builder {
    pub(super) fn new() -> Self {
        Builder {
            config: Default::default(),
        }
    }

    // Not public API, just used in unit tests
    #[doc(hidden)]
    #[cfg(test)]
    pub fn send_settings(&mut self, value: bool) -> &mut Self {
        self.config.send_settings = value;
        self
    }

    /// Set the maximum header size this client is willing to accept
    ///
    /// See [header size constraints] section of the specification for details.
    ///
    /// [header size constraints]: https://www.rfc-editor.org/rfc/rfc9114.html#name-header-size-constraints
    pub fn max_field_section_size(&mut self, value: u64) -> &mut Self {
        self.config.settings.max_field_section_size = value;
        self
    }

    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub fn send_grease(&mut self, enabled: bool) -> &mut Self {
        self.config.send_grease = enabled;
        self
    }

    /// Indicates that the client supports HTTP/3 datagrams
    ///
    /// See: <https://www.rfc-editor.org/rfc/rfc9297#section-2.1.1>
    pub fn enable_datagram(&mut self, enabled: bool) -> &mut Self {
        self.config.settings.enable_datagram = enabled;
        self
    }

    /// Enables the extended CONNECT protocol required for various HTTP/3 extensions.
    pub fn enable_extended_connect(&mut self, value: bool) -> &mut Self {
        self.config.settings.enable_extended_connect = value;
        self
    }

    /// Append additional settings after the built-in client settings.
    pub fn additional_settings(&mut self, settings: Vec<(u64, u64)>) -> &mut Self {
        self.config.additional_settings = settings;
        self
    }

    /// Override the exact serialized SETTINGS order.
    pub fn ordered_settings(&mut self, settings: Vec<(u64, u64)>) -> &mut Self {
        self.config.ordered_settings = Some(settings);
        self
    }

    /// Override the request pseudo-header serialization order.
    pub fn pseudo_header_order(&mut self, order: Vec<PseudoHeader>) -> &mut Self {
        self.config.pseudo_header_order = Some(order);
        self
    }

    /// Configure PRIORITY_UPDATE frames (RFC 9218) to send on the control
    /// stream after SETTINGS.
    ///
    /// Each entry is `(element_id, field_value)` where `element_id` is the
    /// predicted request stream ID and `field_value` is the serialized
    /// priority field value (e.g., `b"u=1, i"`).
    pub fn priority_updates(&mut self, updates: Vec<(u64, Vec<u8>)>) -> &mut Self {
        self.config.priority_updates = updates;
        self
    }

    /// Send a single GREASE frame (RFC 9114 §7.2.8 reserved type) on the
    /// control stream after SETTINGS. Distinct from [`Self::send_grease`]:
    /// browsers such as Chrome emit a reserved *frame* on the control stream in
    /// addition to the reserved *setting*.
    pub fn control_grease_frame(&mut self, enabled: bool) -> &mut Self {
        self.config.send_control_grease_frame = enabled;
        self
    }

    /// Create a new HTTP/3 client from a `quic` connection
    pub async fn build<C, O, B>(
        &mut self,
        quic: C,
    ) -> Result<(Connection<C, B>, SendRequest<O, B>), ConnectionError>
    where
        C: quic::Connection<B, OpenStreams = O>,
        O: quic::OpenStreams<B>,
        B: Buf,
    {
        let open = quic.opener();
        let shared = SharedState::default();

        let conn_state = Arc::new(shared);
        let max_field_section_size = self.config.settings.max_field_section_size;
        let send_grease_frame = self.config.send_grease;
        let pseudo_header_order = self.config.pseudo_header_order.clone();
        let inner = ConnectionInner::new(quic, conn_state.clone(), self.config.clone()).await?;
        let send_request = SendRequest {
            open,
            conn_state,
            max_field_section_size,
            sender_count: Arc::new(AtomicUsize::new(1)),
            send_grease_frame,
            pseudo_header_order,
            _buf: PhantomData,
        };

        Ok((
            Connection {
                inner,
                sent_closing: None,
                recv_closing: None,
            },
            send_request,
        ))
    }
}
