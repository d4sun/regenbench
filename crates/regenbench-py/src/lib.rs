use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand::rngs::StdRng;
use rand::SeedableRng;
use ::regenbench_core::{
    parse_pickle, reconstruct, MutatorConfig, PickleMutator, apply_pipeline,
};

#[pyfunction]
fn parse_pickle_py<'py>(py: Python<'py>, data: &[u8]) -> PyResult<Vec<(PyObject, PyObject)>> {
    let parsed = parse_pickle(data).map_err(|e| {
        PyErr::new::<pyo3::exceptions::PyValueError, _>(e.to_string())
    })?;

    let result: Vec<(PyObject, PyObject)> = parsed
        .iter()
        .map(|opcode| {
            let name = opcode.classification.name.to_object(py);
            let arg = PyBytes::new_bound(py, &opcode.arg).to_object(py);
            (name, arg)
        })
        .collect();

    Ok(result)
}

#[pyfunction]
fn reconstruct_py<'py>(py: Python<'py>, parsed: Vec<(String, Vec<u8>)>) -> PyResult<PyObject> {
    let mut opcodes = Vec::new();
    for (name, arg) in parsed {
        // This is simplified - in reality we'd need to look up the opcode classification
        // For now, just reconstruct raw bytes
        let op_byte = match name.as_str() {
            "PROTO" => 0x80u8,
            "FRAME" => 0x81u8,
            "STOP" => 0x2eu8,
            "GLOBAL" => 0x63u8,
            "INST" => 0x69u8,
            "SHORT_BINUNICODE" => 0x8cu8,
            "BINUNICODE" => 0x8du8,
            "SHORT_BINBYTES" => 0x84u8,
            "BINBYTES" => 0x85u8,
            "BINBYTES8" => 0x86u8,
            "MARK" => 0x28u8,
            "TUPLE" => 0x8eu8,
            "REDUCE" => 0xb0u8,
            "POP" => 0x29u8,
            "NONE" => 0x4eu8,
            "NEWTRUE" => 0x88u8,
            "NEWFALSE" => 0x89u8,
            "BINFLOAT" => 0x47u8,
            "BININT" => 0x4au8,
            "BININT1" => 0x4bu8,
            "BININT2" => 0x4du8,
            "LONG1" => 0x8au8,
            "LONG4" => 0x8bu8,
            "EMPTY_TUPLE" => 0x29u8,
            "EMPTY_LIST" => 0x5d_u8,
            "EMPTY_DICT" => 0x7du8,
            "EMPTY_SET" => 0x8bu8,
            "APPEND" => 0x61u8,
            "APPENDS" => 0x65u8,
            "BUILD" => 0x62u8,
            "DICT" => 0x64u8,
            "SETITEM" => 0x73u8,
            "SETITEMS" => 0x75u8,
            "GET" => 0x67u8,
            "BINGET" => 0x68u8,
            "LONG_BINGET" => 0x6au8,
            "PUT" => 0x70u8,
            "BINPUT" => 0x71u8,
            "LONG_BINPUT" => 0x72u8,
            "DUP" => 0x32u8,
            "STACK_GLOBAL" => 0x93u8,
            "MEMOIZE" => 0x94u8,
            _ => 0x00u8,
        };
        let mut op_data = vec![op_byte];
        op_data.extend_from_slice(&arg);
        opcodes.push(op_data);
    }
    let result: Vec<u8> = opcodes.into_iter().flatten().collect();
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pyfunction]
fn mutate_pickle_py<'py>(
    py: Python<'py>,
    data: &[u8],
    op_swap_prob: f64,
    callable_sub_prob: f64,
    arg_fuzz_prob: f64,
    stack_prob: f64,
    encoding_prob: f64,
    seed: u64,
) -> PyResult<PyObject> {
    let mut rng = StdRng::seed_from_u64(seed);
    let config = MutatorConfig {
        op_swap_prob,
        callable_sub_prob,
        arg_fuzz_prob,
        stack_prob,
        encoding_prob,
    };
    let mutator = PickleMutator::new();
    let result = mutator.mutate(data, config, &mut rng);
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pyfunction]
fn apply_evasion_pipeline_py<'py>(
    py: Python<'py>,
    data: &[u8],
    strategy_names: Vec<String>,
) -> PyResult<PyObject> {
    let names: Vec<&str> = strategy_names.iter().map(|s| s.as_str()).collect();
    let result = apply_pipeline(data, &names);
    Ok(PyBytes::new_bound(py, &result).into())
}

#[pymodule]
fn regenbench_pybind(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_pickle_py, m)?)?;
    m.add_function(wrap_pyfunction!(reconstruct_py, m)?)?;
    m.add_function(wrap_pyfunction!(mutate_pickle_py, m)?)?;
    m.add_function(wrap_pyfunction!(apply_evasion_pipeline_py, m)?)?;
    Ok(())
}