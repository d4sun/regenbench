use criterion::{black_box, criterion_group, criterion_main, Criterion};
use regenbench_core::parse_pickle;

fn bench_parse_pickle(c: &mut Criterion) {
    let data = std::fs::read("reference/known_answers/benign_strings.pkl").unwrap_or_else(|_| vec![0x80, 0x02, 0x4e, 0x2e]);
    c.bench_function("parse_pickle", |b| {
        b.iter(|| parse_pickle(black_box(&data)).unwrap())
    });
}

fn bench_parse_pickle_large(c: &mut Criterion) {
    let data = std::fs::read("ci/corpus/torch/benign/benign.pt").unwrap_or_else(|_| vec![0x80, 0x02, 0x4e, 0x2e]);
    c.bench_function("parse_pickle_large", |b| {
        b.iter(|| parse_pickle(black_box(&data)).unwrap())
    });
}

criterion_group!(benches, bench_parse_pickle, bench_parse_pickle_large);
criterion_main!(benches);