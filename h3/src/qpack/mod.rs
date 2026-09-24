pub use self::{
    decoder::{decode_stateless, Decoded, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

pub(crate) use decoder::{ack_header, Decoder};

#[cfg(test)]
pub(crate) fn encode_dynamic_for_test(
    stream_id: u64,
    fields: crate::proto::headers::Header,
) -> (bytes::Bytes, bytes::Bytes) {
    let mut table = dynamic::DynamicTable::new();
    let mut encoder_instructions = bytes::BytesMut::new();
    encoder::set_dynamic_table_size(&mut table, &mut encoder_instructions, 4096).unwrap();
    table.set_max_blocked(100).unwrap();

    let mut encoder = encoder::Encoder::from(table);
    let mut field_section = bytes::BytesMut::new();
    let required = encoder
        .encode(
            stream_id,
            &mut field_section,
            &mut encoder_instructions,
            fields,
        )
        .unwrap();
    assert!(
        required > 0,
        "test field section must use the dynamic table"
    );
    (field_section.freeze(), encoder_instructions.freeze())
}

mod block;
mod dynamic;
mod field;
mod parse_error;
mod static_;
mod stream;
mod vas;

mod decoder;
mod encoder;

mod prefix_int;
mod prefix_string;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum Error {
    Encoder(EncoderError),
    Decoder(DecoderError),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encoder(e) => write!(f, "Encoder {}", e),
            Error::Decoder(e) => write!(f, "Decoder {}", e),
        }
    }
}
