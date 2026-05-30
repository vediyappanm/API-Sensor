// ---------------------------------------------------------------------------
// WebSocket frame parser
// ---------------------------------------------------------------------------

#[derive(Debug)]
// `fin` and `payload_len` are parsed from the frame header and retained for
// completeness/diagnostics even though the emitter doesn't currently read them.
#[allow(dead_code)]
pub struct WsFrame {
    pub fin: bool,
    pub opcode: u8,
    pub payload_len: usize,
    pub payload: Vec<u8>, // unmasked
}

pub fn parse_websocket_frame(buf: &[u8]) -> Option<(WsFrame, usize)> {
    if buf.len() < 2 {
        return None;
    }
    let fin = (buf[0] & 0x80) != 0;
    let opcode = buf[0] & 0x0F;
    let masked = (buf[1] & 0x80) != 0;
    let len7 = (buf[1] & 0x7F) as usize;

    let (header_len, payload_len) = match len7 {
        126 => {
            if buf.len() < 4 {
                return None;
            }
            (4, u16::from_be_bytes([buf[2], buf[3]]) as usize)
        }
        127 => {
            if buf.len() < 10 {
                return None;
            }
            (10, u64::from_be_bytes(buf[2..10].try_into().ok()?) as usize)
        }
        n => (2, n),
    };

    let mask_start: usize = header_len;
    let data_start: usize = if masked { mask_start + 4 } else { mask_start };
    let total_len = data_start.checked_add(payload_len)?;
    let capture = payload_len.min(4096);

    if buf.len() < data_start {
        return None;
    }

    let available = buf.len().saturating_sub(data_start).min(capture);
    let payload = if masked && buf.len() >= mask_start + 4 {
        let mask = &buf[mask_start..mask_start + 4];
        buf[data_start..data_start + available]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect()
    } else if buf.len() >= data_start + available {
        buf[data_start..data_start + available].to_vec()
    } else {
        return None;
    };

    Some((
        WsFrame {
            fin,
            opcode,
            payload_len,
            payload,
        },
        total_len,
    ))
}

pub fn ws_opcode_name(opcode: u8) -> &'static str {
    match opcode {
        0x0 => "continuation",
        0x1 => "text",
        0x2 => "binary",
        0x8 => "close",
        0x9 => "ping",
        0xA => "pong",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_websocket_frame_parse() {
        // Unmasked text frame: FIN=1, opcode=1 (text), payload = "hello"
        let payload = b"hello";
        let mut buf = vec![0x81u8, 0x05]; // FIN+text, len=5
        buf.extend_from_slice(payload);
        let (frame, consumed) = parse_websocket_frame(&buf).unwrap();
        assert!(frame.fin);
        assert_eq!(frame.opcode, 0x1);
        assert_eq!(frame.payload_len, 5);
        assert_eq!(&frame.payload, b"hello");
        assert_eq!(consumed, 7);
    }

    #[test]
    fn test_websocket_frame_parse_masked() {
        // Masked text frame "Hi" with mask [0x37,0xfa,0x21,0x3d]
        let mask = [0x37u8, 0xfa, 0x21, 0x3d];
        let raw_payload = b"Hi";
        let masked: Vec<u8> = raw_payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        let mut buf = vec![0x81u8, 0x82]; // FIN+text, mask bit set, len=2
        buf.extend_from_slice(&mask);
        buf.extend_from_slice(&masked);
        let (frame, _consumed) = parse_websocket_frame(&buf).unwrap();
        assert_eq!(&frame.payload, b"Hi");
    }
}
