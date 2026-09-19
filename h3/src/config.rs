use std::convert::TryFrom;

use crate::proto::{frame, varint::VarInt};

/// Request pseudo-header identifiers that can be reordered before QPACK encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PseudoHeader {
    /// `:method`
    Method,
    /// `:scheme`
    Scheme,
    /// `:authority`
    Authority,
    /// `:path`
    Path,
    /// `:status`
    Status,
    /// `:protocol`
    Protocol,
}

/// Configures the HTTP/3 connection
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Just like in HTTP/2, HTTP/3 also uses the concept of "grease"
    /// to prevent potential interoperability issues in the future.
    /// In HTTP/3, the concept of grease is used to ensure that the protocol can evolve
    /// and accommodate future changes without breaking existing implementations.
    pub(crate) send_grease: bool,

    /// Use Chromium's GREASE values and omit request/extra unidirectional GREASE.
    pub(crate) chromium_grease: bool,

    #[cfg(test)]
    pub(crate) send_settings: bool,

    /// HTTP/3 Settings
    pub settings: Settings,

    /// Extra settings appended after the built-in settings.
    pub(crate) additional_settings: Vec<(u64, u64)>,

    /// Exact ordered settings list to serialize when present.
    pub(crate) ordered_settings: Option<Vec<(u64, u64)>>,

    /// Preferred request pseudo-header serialization order.
    pub(crate) pseudo_header_order: Option<Vec<PseudoHeader>>,

    /// PRIORITY_UPDATE frames to send on the control stream after SETTINGS.
    ///
    /// Each entry is `(element_id, field_value)` where `element_id` is the
    /// request stream ID and `field_value` is the RFC 9218 priority field
    /// value (e.g., `b"u=1, i"`).
    pub(crate) priority_updates: Vec<(u64, Vec<u8>)>,

    /// Whether to emit a single GREASE frame (RFC 9114 §7.2.8 reserved type) on
    /// the control stream after SETTINGS. This is distinct from `send_grease`
    /// (which only adds a reserved *setting* and greases request streams); some
    /// browsers — notably Chrome — additionally send a reserved *frame* on the
    /// control stream.
    pub(crate) send_control_grease_frame: bool,
}

/// HTTP/3 Settings
#[derive(Debug, Clone, Copy)]
pub struct Settings {
    /// The MAX_FIELD_SECTION_SIZE in HTTP/3 refers to the maximum size of the dynamic table used in HPACK compression.
    /// HPACK is the compression algorithm used in HTTP/3 to reduce the size of the header fields in HTTP requests and responses.

    /// In HTTP/3, the MAX_FIELD_SECTION_SIZE is set to 12.
    /// This means that the dynamic table used for HPACK compression can have a maximum size of 2^12 bytes, which is 4KB.
    pub(crate) max_field_section_size: u64,

    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub(crate) enable_webtransport: bool,
    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub(crate) enable_extended_connect: bool,
    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub(crate) enable_datagram: bool,
    /// The maximum number of concurrent streams that can be opened by the peer.
    pub(crate) max_webtransport_sessions: u64,
}

impl From<&frame::Settings> for Settings {
    fn from(settings: &frame::Settings) -> Self {
        let defaults: Self = Default::default();
        Self {
            max_field_section_size: settings
                .get(frame::SettingId::MAX_HEADER_LIST_SIZE)
                .unwrap_or(defaults.max_field_section_size),
            enable_webtransport: settings
                .get(frame::SettingId::ENABLE_WEBTRANSPORT)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_webtransport),
            max_webtransport_sessions: settings
                .get(frame::SettingId::WEBTRANSPORT_MAX_SESSIONS)
                .unwrap_or(defaults.max_webtransport_sessions),
            enable_datagram: settings
                .get(frame::SettingId::H3_DATAGRAM)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_datagram),
            enable_extended_connect: settings
                .get(frame::SettingId::ENABLE_CONNECT_PROTOCOL)
                .map(|value| value != 0)
                .unwrap_or(defaults.enable_extended_connect),
        }
    }
}

impl TryFrom<Config> for frame::Settings {
    type Error = frame::SettingsError;
    fn try_from(value: Config) -> Result<Self, Self::Error> {
        let mut settings = frame::Settings::default();

        let Config {
            send_grease,
            chromium_grease,
            #[cfg(test)]
                send_settings: _,
            settings:
                Settings {
                    max_field_section_size,
                    enable_webtransport,
                    enable_extended_connect,
                    enable_datagram,
                    max_webtransport_sessions,
                },
            additional_settings,
            ordered_settings,
            pseudo_header_order: _,
            priority_updates: _,
            send_control_grease_frame: _,
        } = value;

        if let Some(entries) = ordered_settings {
            for (id, val) in entries {
                settings.insert(frame::SettingId(id), val)?;
            }
        } else {
            settings.insert(
                frame::SettingId::MAX_HEADER_LIST_SIZE,
                max_field_section_size,
            )?;
            settings.insert(
                frame::SettingId::ENABLE_CONNECT_PROTOCOL,
                enable_extended_connect as u64,
            )?;
            settings.insert(
                frame::SettingId::ENABLE_WEBTRANSPORT,
                enable_webtransport as u64,
            )?;
            settings.insert(frame::SettingId::H3_DATAGRAM, enable_datagram as u64)?;
            settings.insert(
                frame::SettingId::WEBTRANSPORT_MAX_SESSIONS,
                max_webtransport_sessions,
            )?;

            for (id, val) in additional_settings {
                settings.insert(frame::SettingId(id), val)?;
            }
        }

        let grease_setting = if send_grease {
            //  Grease Settings (https://www.rfc-editor.org/rfc/rfc9114.html#name-defined-settings-parameters)
            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers of the format 0x1f * N + 0x21 for non-negative
            //# integer values of N are reserved to exercise the requirement that
            //# unknown identifiers be ignored.  Such settings have no defined
            //# meaning.  Endpoints SHOULD include at least one such setting in their
            //# SETTINGS frame.

            //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.4.1
            //# Setting identifiers that were defined in [HTTP/2] where there is no
            //# corresponding HTTP/3 setting have also been reserved
            //# (Section 11.2.2).  These reserved settings MUST NOT be sent, and
            //# their receipt MUST be treated as a connection error of type
            //# H3_SETTINGS_ERROR.
            Some(if chromium_grease {
                (
                    frame::SettingId(31 * u64::from(fastrand::u32(..)) + 33),
                    u64::from(fastrand::u32(..)),
                )
            } else {
                (frame::SettingId::grease(), 0)
            })
        } else {
            None
        };

        Ok(finish_settings(settings, grease_setting, chromium_grease))
    }
}

fn finish_settings(
    mut settings: frame::Settings,
    grease_setting: Option<(frame::SettingId, u64)>,
    chromium_grease: bool,
) -> frame::Settings {
    if let Some((id, value)) = grease_setting {
        if let Err(_err) = settings.insert(id, value) {
            #[cfg(feature = "tracing")]
            tracing::warn!("Error when adding the grease Setting. Reason {}", _err);
        }
    }
    if chromium_grease {
        settings.sort_by_id();
    }
    settings
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_field_section_size: VarInt::MAX.0,
            enable_webtransport: false,
            enable_extended_connect: false,
            enable_datagram: false,
            max_webtransport_sessions: 0,
        }
    }
}

impl Settings {
    /// https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3/#section-3.1
    /// Sets `SETTINGS_ENABLE_WEBTRANSPORT` if enabled
    pub fn enable_webtransport(&self) -> bool {
        self.enable_webtransport
    }

    /// Enable HTTP Datagrams, see https://datatracker.ietf.org/doc/rfc9297/ for details
    pub fn enable_datagram(&self) -> bool {
        self.enable_datagram
    }

    /// https://www.rfc-editor.org/info/rfc8441 defines an extended CONNECT method in Section 4,
    /// enabled by the SETTINGS_ENABLE_CONNECT_PROTOCOL parameter.
    /// That parameter is only defined for HTTP/2.
    /// for extended CONNECT in HTTP/3; instead, the SETTINGS_ENABLE_WEBTRANSPORT setting implies that an endpoint supports extended CONNECT.
    pub fn enable_extended_connect(&self) -> bool {
        self.enable_extended_connect
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            send_grease: true,
            chromium_grease: false,
            #[cfg(test)]
            send_settings: true,
            settings: Default::default(),
            additional_settings: Vec::new(),
            ordered_settings: None,
            pseudo_header_order: None,
            priority_updates: Vec::new(),
            send_control_grease_frame: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{finish_settings, frame};

    #[test]
    fn chromium_settings_sort_low_grease_id_before_datagram() {
        let mut settings = frame::Settings::default();
        settings.insert(frame::SettingId(51), 1).unwrap();
        settings.insert(frame::SettingId(7), 100).unwrap();
        settings.insert(frame::SettingId(1), 65536).unwrap();

        let settings = finish_settings(settings, Some((frame::SettingId(33), 42)), true);
        let mut wire = Vec::new();
        settings.encode(&mut wire);
        assert_eq!(wire, [4, 12, 1, 0x80, 1, 0, 0, 7, 0x40, 100, 33, 42, 51, 1]);
    }
}
