#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeCategory {
    NoArg,
    FixedArg,
    LengthPrefixed,
    Delimited,
}

#[derive(Debug, Clone)]
pub struct OpcodeClassification {
    pub code: u8,
    pub name: &'static str,
    pub category: OpcodeCategory,
    pub arg_width: Option<usize>,
    pub proto: u8,
}

#[derive(Debug, Clone)]
pub struct ParsedOpcode {
    pub classification: OpcodeClassification,
    pub arg: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct MutatorConfig {
    pub op_swap_prob: f64,
    pub callable_sub_prob: f64,
    pub arg_fuzz_prob: f64,
    pub stack_prob: f64,
    pub encoding_prob: f64,
}

impl Default for MutatorConfig {
    fn default() -> Self {
        Self {
            op_swap_prob: 0.1,
            callable_sub_prob: 0.2,
            arg_fuzz_prob: 0.2,
            stack_prob: 0.05,
            encoding_prob: 0.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct EvasionConfig {
    pub strategies: Vec<String>,
}