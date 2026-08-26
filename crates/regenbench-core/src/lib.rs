pub mod opcodes;
pub mod mutators;
pub mod evasion;
pub mod types;

pub use opcodes::{parse_pickle, ParseError, get_opcode_classification, get_opcode_by_byte, reconstruct};
pub use mutators::{PickleMutator};
pub use evasion::{EvasionStrategy, apply_pipeline, get_strategy, STRATEGY_NAMES, PIPELINE_ORDER};
pub use types::{OpcodeCategory, OpcodeClassification, ParsedOpcode, MutatorConfig, EvasionConfig};