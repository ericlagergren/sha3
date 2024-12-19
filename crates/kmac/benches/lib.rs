//! Benchmarks

use core::{hint::black_box, time::Duration};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pprof::criterion::{Output, PProfProfiler};
use sha3_kmac::{Kmac128, Kmac256};

fn bench_new<T, F>(c: &mut Criterion, name: &'static str, f: &F)
where
    F: Fn(&[u8], &[u8]) -> T,
{
    let mut g = c.benchmark_group(name);
    for size in [32, 48, 64, 1024].iter() {
        let mut i = 0;
        let k = vec![0u8; *size];
        let s = b"hello, world!";

        g.throughput(Throughput::Bytes(*size as u64));
        let name = BenchmarkId::new("new", *size);
        g.bench_function(name, move |b| {
            b.iter(|| {
                black_box(f(black_box(&k), black_box(s)));
                i += 1;
            })
        });
    }
    g.finish();
}

fn bench_alg<T, F>(c: &mut Criterion, name: &'static str, f: F)
where
    F: Fn(&[u8], &[u8]) -> T,
{
    bench_new(c, name, &f);
}

fn bench_throughput(c: &mut Criterion) {
    bench_alg(c, "KMAC-128", |k, s| Kmac128::new(k, s));
    bench_alg(c, "KMAC-256", |k, s| Kmac256::new(k, s));
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .with_profiler(PProfProfiler::new(100, Output::Protobuf));
    targets = bench_throughput,
}
criterion_main!(benches);
