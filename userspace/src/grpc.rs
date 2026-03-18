use serde::Serialize;

// ---------------------------------------------------------------------------
// gRPC Protobuf body decoder
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct ProtoField {
    pub field_number: u32,
    pub wire_type:    u8,
    pub value_str:    String,
}

pub fn read_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift  = 0u32;
    let mut i      = 0;
    loop {
        if i >= buf.len() || i >= 10 { return None; }
        let byte = buf[i] as u64;
        result |= (byte & 0x7F) << shift;
        i += 1;
        if byte & 0x80 == 0 { break; }
        shift += 7;
    }
    Some((result, i))
}

pub fn decode_grpc_fields(buf: &[u8]) -> Vec<ProtoField> {
    // Strip 5-byte gRPC frame prefix: [compress_flag(1)] [length(4)]
    if buf.len() < 5 { return vec![]; }
    let _compress = buf[0];
    let msg_len   = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
    let proto_start = 5;
    let proto_end   = (proto_start + msg_len).min(buf.len());
    if proto_end <= proto_start { return vec![]; }
    let proto = &buf[proto_start..proto_end];

    let mut fields = Vec::new();
    let mut i = 0;
    while i < proto.len() {
        let (tag, tag_bytes) = match read_varint(&proto[i..]) {
            Some(v) => v,
            None    => break,
        };
        i += tag_bytes;
        let field_number = (tag >> 3) as u32;
        let wire_type    = (tag & 0x7) as u8;

        let value_str = match wire_type {
            0 => {
                // Varint
                let (val, bytes) = match read_varint(&proto[i..]) {
                    Some(v) => v, None => break,
                };
                i += bytes;
                format!("{}", val)
            }
            1 => {
                // 64-bit
                if i + 8 > proto.len() { break; }
                let val = u64::from_le_bytes(proto[i..i+8].try_into().unwrap_or([0;8]));
                i += 8;
                format!("0x{:016x}", val)
            }
            2 => {
                // Length-delimited
                let (len, len_bytes) = match read_varint(&proto[i..]) {
                    Some(v) => v, None => break,
                };
                i += len_bytes;
                let len_usize = len as usize;
                let end = i.saturating_add(len_usize).min(proto.len()).min(i.saturating_add(256));
                let data = &proto[i..end];
                i = i.saturating_add(len_usize);
                if i > proto.len() { i = proto.len(); }
                match std::str::from_utf8(data) {
                    Ok(s) if s.chars().all(|c| !c.is_control() || c == '\n') => {
                        format!("\"{}\"", s.chars().take(128).collect::<String>())
                    }
                    _ => format!("hex:{}", hex_encode(data)),
                }
            }
            5 => {
                // 32-bit
                if i + 4 > proto.len() { break; }
                let val = u32::from_le_bytes(proto[i..i+4].try_into().unwrap_or([0;4]));
                i += 4;
                format!("0x{:08x}", val)
            }
            _ => break,
        };

        fields.push(ProtoField { field_number, wire_type, value_str });
        if fields.len() >= 64 { break; }
    }
    fields
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().take(32).map(|b| format!("{:02x}", b)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_grpc_protobuf_decode() {
        // Build a minimal protobuf message: field 1, wire type 2 (length-delimited), value "test"
        let field_tag: u8 = (1 << 3) | 2; // field_number=1, wire_type=2
        let value = b"test";
        let mut proto_msg = vec![field_tag, value.len() as u8];
        proto_msg.extend_from_slice(value);

        // Wrap in gRPC frame prefix: [compress=0, len(4 bytes)]
        let mut buf = vec![0x00u8]; // no compression
        let msg_len = proto_msg.len() as u32;
        buf.extend_from_slice(&msg_len.to_be_bytes());
        buf.extend_from_slice(&proto_msg);

        let fields = decode_grpc_fields(&buf);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].field_number, 1);
        assert_eq!(fields[0].wire_type, 2);
        assert!(fields[0].value_str.contains("test"));
    }
}
