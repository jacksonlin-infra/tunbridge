use serde::{de::DeserializeOwned, Serialize};

use crate::protocol::{ProtocolError, MAX_FRAME_BYTES};

const LENGTH_PREFIX_BYTES: usize = 4;

/// Encode one length-prefixed IPC frame.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| ProtocolError::InvalidFrame(error.to_string()))?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }

    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode exactly one length-prefixed IPC frame.
///
/// The transport must not append a second frame or ignore trailing bytes. This
/// prevents parsers at different layers from disagreeing about message bounds.
pub fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, ProtocolError> {
    if frame.len() < LENGTH_PREFIX_BYTES {
        return Err(ProtocolError::InvalidFrame("missing length prefix".into()));
    }

    let mut prefix = [0_u8; LENGTH_PREFIX_BYTES];
    prefix.copy_from_slice(&frame[..LENGTH_PREFIX_BYTES]);
    let length = u32::from_le_bytes(prefix) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(length));
    }
    if frame.len() != LENGTH_PREFIX_BYTES + length {
        return Err(ProtocolError::InvalidFrame(format!(
            "length prefix declares {length} bytes but frame contains {}",
            frame.len().saturating_sub(LENGTH_PREFIX_BYTES)
        )));
    }

    serde_json::from_slice(&frame[LENGTH_PREFIX_BYTES..])
        .map_err(|error| ProtocolError::InvalidFrame(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::Hello;

    #[test]
    fn round_trip_exact_frame() {
        let hello = Hello::new("0.1.0");
        let encoded = encode(&hello).unwrap();
        assert_eq!(decode::<Hello>(&encoded).unwrap(), hello);
    }

    #[test]
    fn rejects_oversize_before_json_parse() {
        let mut frame = ((MAX_FRAME_BYTES + 1) as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(b"{}");
        assert!(matches!(
            decode::<Hello>(&frame),
            Err(ProtocolError::FrameTooLarge(_))
        ));
    }

    #[test]
    fn rejects_truncated_and_trailing_bytes() {
        let mut truncated = 10_u32.to_le_bytes().to_vec();
        truncated.extend_from_slice(b"{}");
        assert!(matches!(
            decode::<Hello>(&truncated),
            Err(ProtocolError::InvalidFrame(_))
        ));

        let mut trailing = encode(&Hello::new("0.1.0")).unwrap();
        trailing.push(0);
        assert!(matches!(
            decode::<Hello>(&trailing),
            Err(ProtocolError::InvalidFrame(_))
        ));
    }

    #[test]
    fn serde_rejects_unknown_and_duplicate_fields() {
        fn framed(json: &str) -> Vec<u8> {
            let mut result = (json.len() as u32).to_le_bytes().to_vec();
            result.extend_from_slice(json.as_bytes());
            result
        }

        let unknown =
            framed(r#"{"kind":"hello","protocol":1,"client_version":"0.1.0","path":"C:\\evil"}"#);
        assert!(decode::<Hello>(&unknown).is_err());

        let duplicate =
            framed(r#"{"kind":"hello","protocol":1,"protocol":1,"client_version":"0.1.0"}"#);
        assert!(decode::<Hello>(&duplicate).is_err());
    }
}
