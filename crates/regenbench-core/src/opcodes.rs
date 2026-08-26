pub use crate::types::{OpcodeCategory, OpcodeClassification, ParsedOpcode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Unknown opcode byte 0x{0:02x} at index {1}")]
    UnknownOpcode(u8, usize),
    #[error("Stream ended while reading fixed argument for {0}")]
    TruncatedFixedArg(String),
    #[error("Stream ended while reading length prefix for {0}")]
    TruncatedLengthPrefix(String),
    #[error("Stream ended while reading {length} bytes payload for {name}")]
    TruncatedPayload { name: String, length: usize },
    #[error("Delimited opcode {0} is missing delimiter newline")]
    MissingDelimiter(String),
    #[error("GLOBAL/INST second field is missing delimiter newline")]
    MissingGlobalSecondField,
}

lazy_static::lazy_static! {
    static ref OPCODE_TABLE_INIT: [Option<&'static OpcodeClassification>; 256] = build_opcode_table();
    
    pub static ref OPCODES_BY_NAME: std::collections::HashMap<&'static str, &'static OpcodeClassification> = {
        let mut map = std::collections::HashMap::new();
        for opt in OPCODE_TABLE_INIT.iter() {
            if let Some(op) = opt {
                map.insert(op.name, *op);
            }
        }
        map
    };
}

fn build_opcode_table() -> [Option<&'static OpcodeClassification>; 256] {
    let mut table: [Option<&'static OpcodeClassification>; 256] = [None; 256];
    
    macro_rules! add_opcode {
        ($code:expr, $name:expr, $cat:expr, $width:expr, $proto:expr) => {
            let op = Box::leak(Box::new(OpcodeClassification {
                code: $code,
                name: $name,
                category: $cat,
                arg_width: $width,
                proto: $proto,
            }));
            table[$code as usize] = Some(op);
        };
    }

    // Protocol 0-5 opcodes from Python's pickletools
    // Format: add_opcode!(code, name, category, arg_width, min_protocol)
    
    // PROTO - protocol version
    add_opcode!(0x80, "PROTO", OpcodeCategory::FixedArg, Some(1), 0);
    
    // FRAME - protocol 4 frame
    add_opcode!(0x81, "FRAME", OpcodeCategory::LengthPrefixed, Some(8), 4);
    
    // SHORT_BINUNICODE - short unicode string (protocol 2+)
    add_opcode!(0x8c, "SHORT_BINUNICODE", OpcodeCategory::LengthPrefixed, Some(1), 2);
    
    // BINUNICODE - unicode string with 4-byte length (protocol 1+)
    add_opcode!(0x8d, "BINUNICODE8", OpcodeCategory::LengthPrefixed, Some(4), 4);
    add_opcode!(0x58, "BINUNICODE", OpcodeCategory::LengthPrefixed, Some(4), 1);
    
    // SHORT_BINBYTES - short bytes (protocol 3+)
    add_opcode!(0x43, "SHORT_BINBYTES", OpcodeCategory::LengthPrefixed, Some(1), 3);
    
    // BINBYTES - bytes with 4-byte length (protocol 3+)
    add_opcode!(0x42, "BINBYTES", OpcodeCategory::LengthPrefixed, Some(4), 3);
    
    // BINBYTES8 - bytes with 8-byte length (protocol 4+)
    add_opcode!(0x8e, "BINBYTES8", OpcodeCategory::LengthPrefixed, Some(8), 4);
    
    // BYTEARRAY8 - bytearray (protocol 5+)
    add_opcode!(0x96, "BYTEARRAY8", OpcodeCategory::LengthPrefixed, Some(4), 5);
    
    // NEXT_BUFFER / READONLY_BUFFER (protocol 5+)
    add_opcode!(0x97, "NEXT_BUFFER", OpcodeCategory::NoArg, None, 5);
    add_opcode!(0x98, "READONLY_BUFFER", OpcodeCategory::NoArg, None, 5);
    
    // NONE - protocol 0
    add_opcode!(0x4e, "NONE", OpcodeCategory::NoArg, None, 0);
    
    // NEWTRUE / NEWFALSE (protocol 2+)
    add_opcode!(0x88, "NEWTRUE", OpcodeCategory::NoArg, None, 2);
    add_opcode!(0x89, "NEWFALSE", OpcodeCategory::NoArg, None, 2);
    
    // LONG1 / LONG4 (protocol 2+)
    add_opcode!(0x8a, "LONG1", OpcodeCategory::LengthPrefixed, Some(1), 2);
    add_opcode!(0x8b, "LONG4", OpcodeCategory::LengthPrefixed, Some(4), 2);
    
    // EMPTY_LIST (protocol 1+)
    add_opcode!(0x5d, "EMPTY_LIST", OpcodeCategory::NoArg, None, 1);
    
    // APPEND / APPENDS
    add_opcode!(0x61, "APPEND", OpcodeCategory::NoArg, None, 0);
    add_opcode!(0x65, "APPENDS", OpcodeCategory::NoArg, None, 1);
    
    // LIST (protocol 0)
    add_opcode!(0x6c, "LIST", OpcodeCategory::NoArg, None, 0);
    
    // EMPTY_TUPLE (protocol 1+)
    add_opcode!(0x29, "EMPTY_TUPLE", OpcodeCategory::NoArg, None, 1);
    
    // TUPLE / TUPLE1 / TUPLE2 / TUPLE3
    add_opcode!(0x74, "TUPLE", OpcodeCategory::NoArg, None, 0);
    add_opcode!(0x85, "TUPLE1", OpcodeCategory::NoArg, None, 2);
    add_opcode!(0x86, "TUPLE2", OpcodeCategory::NoArg, None, 2);
    add_opcode!(0x87, "TUPLE3", OpcodeCategory::NoArg, None, 2);
    
    // EMPTY_DICT (protocol 1+)
    add_opcode!(0x7d, "EMPTY_DICT", OpcodeCategory::NoArg, None, 1);
    
    // DICT
    add_opcode!(0x64, "DICT", OpcodeCategory::NoArg, None, 0);
    
    // SETITEM / SETITEMS
    add_opcode!(0x73, "SETITEM", OpcodeCategory::NoArg, None, 0);
    add_opcode!(0x75, "SETITEMS", OpcodeCategory::NoArg, None, 1);
    
    // EMPTY_SET / ADDITEMS / FROZENSET (protocol 4+)
    add_opcode!(0x8f, "EMPTY_SET", OpcodeCategory::NoArg, None, 4);
    add_opcode!(0x90, "ADDITEMS", OpcodeCategory::NoArg, None, 4);
    add_opcode!(0x91, "FROZENSET", OpcodeCategory::NoArg, None, 4);
    
    // POP / DUP / MARK / POP_MARK
    add_opcode!(0x30, "POP", OpcodeCategory::NoArg, None, 0);
    add_opcode!(0x32, "DUP", OpcodeCategory::NoArg, None, 0);
    add_opcode!(0x28, "MARK", OpcodeCategory::NoArg, None, 0);
    add_opcode!(0x31, "POP_MARK", OpcodeCategory::NoArg, None, 1);
    
    // GET / BINGET / LONG_BINGET
    add_opcode!(0x67, "GET", OpcodeCategory::FixedArg, Some(1), 0);
    add_opcode!(0x68, "BINGET", OpcodeCategory::FixedArg, Some(1), 1);
    add_opcode!(0x6a, "LONG_BINGET", OpcodeCategory::FixedArg, Some(4), 1);
    
    // PUT / BINPUT / LONG_BINPUT
    add_opcode!(0x70, "PUT", OpcodeCategory::FixedArg, Some(1), 0);
    add_opcode!(0x71, "BINPUT", OpcodeCategory::FixedArg, Some(1), 1);
    add_opcode!(0x72, "LONG_BINPUT", OpcodeCategory::FixedArg, Some(4), 1);
    
    // MEMOIZE (protocol 4+)
    add_opcode!(0x94, "MEMOIZE", OpcodeCategory::NoArg, None, 4);
    
    // EXT1 / EXT2 / EXT4 (protocol 2+)
    add_opcode!(0x82, "EXT1", OpcodeCategory::FixedArg, Some(1), 2);
    add_opcode!(0x83, "EXT2", OpcodeCategory::FixedArg, Some(2), 2);
    add_opcode!(0x84, "EXT4", OpcodeCategory::FixedArg, Some(4), 2);
    
    // GLOBAL / INST
    add_opcode!(0x63, "GLOBAL", OpcodeCategory::Delimited, None, 0);
    add_opcode!(0x69, "INST", OpcodeCategory::Delimited, None, 0);
    
    // STACK_GLOBAL (protocol 4+)
    add_opcode!(0x93, "STACK_GLOBAL", OpcodeCategory::NoArg, None, 4);
    
    // REDUCE
    add_opcode!(0x52, "REDUCE", OpcodeCategory::NoArg, None, 0);
    
    // BUILD
    add_opcode!(0x62, "BUILD", OpcodeCategory::NoArg, None, 0);
    
    // OBJ / NEWOBJ / NEWOBJ_EX
    add_opcode!(0x6f, "OBJ", OpcodeCategory::NoArg, None, 1);
    add_opcode!(0x81, "NEWOBJ", OpcodeCategory::NoArg, None, 2);
    add_opcode!(0x92, "NEWOBJ_EX", OpcodeCategory::NoArg, None, 4);
    
    // STOP
    add_opcode!(0x2e, "STOP", OpcodeCategory::NoArg, None, 0);
    
    // FRAME (protocol 4+)
    add_opcode!(0x95, "FRAME", OpcodeCategory::LengthPrefixed, Some(8), 4);
    
    // PERSID / BINPERSID
    add_opcode!(0x50, "PERSID", OpcodeCategory::Delimited, None, 0);
    add_opcode!(0x51, "BINPERSID", OpcodeCategory::NoArg, None, 1);
    
    // INT / LONG (protocol 0)
    add_opcode!(0x49, "INT", OpcodeCategory::Delimited, None, 0);
    add_opcode!(0x4c, "LONG", OpcodeCategory::Delimited, None, 0);
    
    // BININT / BININT1 / BININT2
    add_opcode!(0x4a, "BININT", OpcodeCategory::FixedArg, Some(4), 1);
    add_opcode!(0x4b, "BININT1", OpcodeCategory::FixedArg, Some(1), 1);
    add_opcode!(0x4d, "BININT2", OpcodeCategory::FixedArg, Some(2), 1);
    
    // BINFLOAT (protocol 1+)
    add_opcode!(0x47, "BINFLOAT", OpcodeCategory::FixedArg, Some(8), 1);
    
    // FLOAT (protocol 0)
    add_opcode!(0x46, "FLOAT", OpcodeCategory::Delimited, None, 0);
    
    // STRING / BINSTRING / SHORT_BINSTRING / UNICODE
    add_opcode!(0x53, "STRING", OpcodeCategory::Delimited, None, 0);
    add_opcode!(0x54, "BINSTRING", OpcodeCategory::LengthPrefixed, Some(4), 1);
    add_opcode!(0x55, "SHORT_BINSTRING", OpcodeCategory::LengthPrefixed, Some(1), 1);
    add_opcode!(0x56, "UNICODE", OpcodeCategory::Delimited, None, 1);
    
    // LONG1 / LONG4
    add_opcode!(0x8a, "LONG1", OpcodeCategory::LengthPrefixed, Some(1), 2);
    add_opcode!(0x8b, "LONG4", OpcodeCategory::LengthPrefixed, Some(4), 2);
    
    // NEWOBJ / NEWOBJ_EX
    add_opcode!(0x81, "NEWOBJ", OpcodeCategory::NoArg, None, 2);
    add_opcode!(0x92, "NEWOBJ_EX", OpcodeCategory::NoArg, None, 4);
    
    table
}

pub fn parse_pickle(data: &[u8]) -> Result<Vec<ParsedOpcode>, ParseError> {
    let mut parsed = Vec::with_capacity(data.len() / 3);
    let mut i = 0;
    let limit = data.len();

    while i < limit {
        let opcode_byte = data[i];
        i += 1;

        let classification = OPCODE_TABLE_INIT[opcode_byte as usize]
            .ok_or_else(|| ParseError::UnknownOpcode(opcode_byte, i - 1))?;

        let arg = match classification.category {
            OpcodeCategory::NoArg => Vec::new(),
            OpcodeCategory::FixedArg => {
                let width = classification.arg_width.unwrap();
                if i + width > limit {
                    return Err(ParseError::TruncatedFixedArg(classification.name.to_string()));
                }
                let arg = data[i..i + width].to_vec();
                i += width;
                arg
            }
            OpcodeCategory::LengthPrefixed => {
                let width = classification.arg_width.unwrap();
                if i + width > limit {
                    return Err(ParseError::TruncatedLengthPrefix(classification.name.to_string()));
                }
                let prefix = data[i..i + width].to_vec();
                i += width;

                let length = if width == 1 {
                    prefix[0] as usize
                } else if width == 4 {
                    u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize
                } else {
                    u64::from_le_bytes([
                        prefix[0], prefix[1], prefix[2], prefix[3],
                        prefix[4], prefix[5], prefix[6], prefix[7],
                    ]) as usize
                };

                if i + length > limit {
                    return Err(ParseError::TruncatedPayload {
                        name: classification.name.to_string(),
                        length,
                    });
                }
                let payload = data[i..i + length].to_vec();
                i += length;
                [prefix.as_slice(), payload.as_slice()].concat()
            }
            OpcodeCategory::Delimited => {
                let idx = data[i..].iter().position(|&b| b == b'\n');
                let idx = match idx {
                    Some(idx) => idx,
                    None => return Err(ParseError::MissingDelimiter(classification.name.to_string())),
                };
                let arg = data[i..i + idx + 1].to_vec();
                i += idx + 1;

                if classification.name == "GLOBAL" || classification.name == "INST" {
                    let idx2 = data[i..].iter().position(|&b| b == b'\n');
                    let idx2 = match idx2 {
                        Some(idx2) => idx2,
                        None => return Err(ParseError::MissingGlobalSecondField),
                    };
                    let arg2 = data[i..i + idx2 + 1].to_vec();
                    i += idx2 + 1;
                    [arg.as_slice(), arg2.as_slice()].concat()
                } else {
                    arg
                }
            }
        };

        parsed.push(ParsedOpcode {
            classification: (*classification).clone(),
            arg,
        });

        if classification.name == "STOP" {
            let remaining = &data[i..];
            if remaining.iter().all(|&b| b == b'\n' || b == b'\r' || b == b' ' || b == b'\t' || b == 0) {
                break;
            }
        }
    }

    Ok(parsed)
}

pub fn reconstruct(parsed: &[ParsedOpcode]) -> Vec<u8> {
    let mut out = Vec::new();
    for opcode in parsed {
        out.push(opcode.classification.code);
        out.extend_from_slice(&opcode.arg);
    }
    out
}

pub fn get_opcode_classification(name: &str) -> Option<&'static OpcodeClassification> {
    OPCODES_BY_NAME.get(name).copied()
}

pub fn get_opcode_by_byte(byte: u8) -> Option<&'static OpcodeClassification> {
    OPCODE_TABLE_INIT[byte as usize]
}