use crate::opcodes::{parse_pickle, OPCODES_BY_NAME, get_opcode_classification};
use crate::types::{ParsedOpcode, OpcodeCategory, MutatorConfig};
use lazy_static::lazy_static;
use rand::Rng;
use rand::seq::SliceRandom;

#[derive(Debug, Clone)]
pub struct PickleMutator {
    sample_strings: Vec<String>,
    sample_ints: Vec<i64>,
    sample_floats: Vec<f64>,
}

impl Default for PickleMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl PickleMutator {
    pub fn new() -> Self {
        Self {
            sample_strings: vec![
                "benign".to_string(),
                "fuzzed".to_string(),
                "".to_string(),
                "A".repeat(10),
                "A".repeat(256),
                "127.0.0.1".to_string(),
                "localhost".to_string(),
                "admin".to_string(),
                "root".to_string(),
            ],
            sample_ints: vec![
                0, 1, -1, 127, 255, 32767, 65535, 2147483647, -2147483648,
            ],
            sample_floats: vec![
                0.0, 1.0, -1.0, 3.14159, 1e-5, f64::INFINITY, f64::NEG_INFINITY, f64::NAN,
            ],
        }
    }

    pub fn mutate(&self, pkl_bytes: &[u8], config: MutatorConfig, rng: &mut impl Rng) -> Vec<u8> {
        let mut parsed = match parse_pickle(pkl_bytes) {
            Ok(p) => p,
            Err(_) => return pkl_bytes.to_vec(),
        };

        let mut encoded_any = false;

        for opcode in &mut parsed {
            if opcode.classification.name == "STOP" {
                continue;
            }

            if rng.gen_bool(config.op_swap_prob) {
                self.mutate_opcode_swap(opcode, rng);
            }

            if rng.gen_bool(config.callable_sub_prob) {
                self.mutate_callable_substitution(opcode, rng);
            }

            if config.encoding_prob > 0.0 && rng.gen_bool(config.encoding_prob) {
                if self.mutate_opcode_encoding(opcode, rng) {
                    encoded_any = true;
                }
            }

            if rng.gen_bool(config.arg_fuzz_prob) {
                self.mutate_argument_fuzz(opcode, rng);
            }
        }

        let mut out = self.reassemble(&parsed);
        if encoded_any {
            out = ensure_proto(&out, 4);
        }
        out
    }

    fn reassemble(&self, parsed: &[ParsedOpcode]) -> Vec<u8> {
        let mut out = Vec::new();
        for opcode in parsed {
            out.push(opcode.classification.code);
            out.extend_from_slice(&opcode.arg);
        }
        out
    }

    fn mutate_opcode_swap(&self, opcode: &mut ParsedOpcode, rng: &mut impl Rng) {
        if opcode.classification.category != OpcodeCategory::NoArg {
            return;
        }
        let equivalents = match opcode.classification.name {
            "NONE" => vec!["NEWTRUE", "NEWFALSE"],
            "NEWTRUE" => vec!["NONE", "NEWFALSE"],
            "NEWFALSE" => vec!["NONE", "NEWTRUE"],
            _ => return,
        };
        if let Some(new_name) = equivalents.choose(rng) {
            if let Some(new_opcode) = OPCODES_BY_NAME.get(new_name) {
                opcode.classification = (*new_opcode).clone();
                opcode.arg.clear();
            }
        }
    }

    fn mutate_callable_substitution(&self, opcode: &mut ParsedOpcode, rng: &mut impl Rng) {
        if !(opcode.classification.name == "GLOBAL" || opcode.classification.name == "INST") {
            return;
        }
        if let Some(entry) = DANGEROUS_CALLABLES.choose(rng) {
            let new_arg = format!("{}\n{}\n", entry.0, entry.1).into_bytes();
            opcode.arg = new_arg;
        }
    }

    fn mutate_opcode_encoding(&self, opcode: &mut ParsedOpcode, rng: &mut impl Rng) -> bool {
        if !(opcode.classification.name == "GLOBAL" || opcode.classification.name == "INST") {
            return false;
        }
        let fields: Vec<&[u8]> = opcode.arg.split(|&b| b == b'\n').collect();
        if fields.len() < 2 {
            return false;
        }
        let module = std::str::from_utf8(fields[0]).unwrap_or("");
        let name = std::str::from_utf8(fields[1]).unwrap_or("");

        let encoded = [
            &encode_short_binunicode(module)[..],
            &encode_short_binunicode(name)[..],
            &[0x93][..], // STACK_GLOBAL
        ].concat();

        if let Some(stack_global) = get_opcode_classification("STACK_GLOBAL") {
            opcode.classification = (*stack_global).clone();
        }
        opcode.arg = encoded;
        true
    }

    fn mutate_argument_fuzz(&self, opcode: &mut ParsedOpcode, rng: &mut impl Rng) {
        if opcode.classification.category == OpcodeCategory::NoArg {
            opcode.arg.clear();
            return;
        }

        match opcode.classification.category {
            OpcodeCategory::LengthPrefixed => {
                let new_payload = self.sample_strings.choose(rng).unwrap().as_bytes();
                let length = new_payload.len();
                let width = opcode.classification.arg_width.unwrap_or(1);

                let prefix = if width == 1 {
                    vec![length.min(255) as u8]
                } else if width == 4 {
                    (length as u32).to_le_bytes().to_vec()
                } else {
                    (length as u64).to_le_bytes().to_vec()
                };
                opcode.arg = [prefix.as_slice(), new_payload].concat();
            }
            OpcodeCategory::FixedArg => {
                let name = opcode.classification.name;
                let width = opcode.classification.arg_width.unwrap_or(1);
                if name == "BINFLOAT" && width == 8 {
                    let val = *self.sample_floats.choose(rng).unwrap();
                    opcode.arg = val.to_be_bytes().to_vec();
                } else if name == "BININT" && width == 4 {
                    let val = *self.sample_ints.choose(rng).unwrap();
                    opcode.arg = (val as i32).to_le_bytes().to_vec();
                } else if name == "BININT1" && width == 1 {
                    let val = rng.gen_range(0..=255);
                    opcode.arg = vec![val];
                } else if name == "BININT2" && width == 2 {
                    let val = rng.gen_range(0..=65535);
                    opcode.arg = (val as u16).to_le_bytes().to_vec();
                }
            }
            OpcodeCategory::Delimited => {
                if opcode.classification.name == "GLOBAL" || opcode.classification.name == "INST" {
                    return;
                }
                if opcode.classification.name == "INT" || opcode.classification.name == "LONG" {
                    let val = *self.sample_ints.choose(rng).unwrap();
                    opcode.arg = format!("{}\n", val).into_bytes();
                } else if opcode.classification.name == "FLOAT" {
                    let val = *self.sample_floats.choose(rng).unwrap();
                    opcode.arg = format!("{}\n", val).into_bytes();
                } else if opcode.classification.name == "STRING" || opcode.classification.name == "UNICODE" {
                    let val = self.sample_strings.choose(rng).unwrap();
                    opcode.arg = format!("'{}'\n", val).into_bytes();
                }
            }
            OpcodeCategory::NoArg => {}
        }
    }

    pub fn mutate_structural_stacking(&self, pkl_bytes: &[u8]) -> Vec<u8> {
        let extra = b"}\x94\x8c\x10fuzzed_stack_payload\x94\x88\x86\x94.";
        [pkl_bytes, extra].concat()
    }
}

fn encode_short_binunicode(s: &str) -> Vec<u8> {
    let data = s.as_bytes();
    let mut out = vec![0x8c];
    out.push(data.len().min(255) as u8);
    out.extend_from_slice(&data[..data.len().min(255)]);
    out
}

fn ensure_proto(stream: &[u8], min_proto: u8) -> Vec<u8> {
    if stream.len() >= 2 && stream[0] == 0x80 && stream[1] < min_proto {
        let mut out = vec![0x80, min_proto];
        out.extend_from_slice(&stream[2..]);
        out
    } else {
        stream.to_vec()
    }
}

lazy_static! {
    static ref DANGEROUS_CALLABLES: Vec<(&'static str, &'static str)> = vec![
        ("os", "system"),
        ("posix", "system"),
        ("subprocess", "Popen"),
        ("subprocess", "run"),
        ("subprocess", "call"),
        ("subprocess", "check_call"),
        ("subprocess", "check_output"),
        ("subprocess", "getstatusoutput"),
        ("subprocess", "getoutput"),
        ("builtins", "eval"),
        ("builtins", "exec"),
        ("runpy", "run_path"),
        ("numpy.testing._private.utils", "runstring"),
        ("IPython.utils.process", "system"),
        ("yaml", "unsafe_load"),
        ("pty", "spawn"),
        ("os", "popen"),
        ("platform", "popen"),
        ("posix", "execv"),
    ];
}