use criterion::{black_box, criterion_group, criterion_main, Criterion};
use veri_zexe::errors::DPCApiError;

const INNER_DOMAIN_SIZE: usize = 1 << 15;

// Setup algorithm in DPC scheme
fn dpc_setup() -> Result<(), DPCApiError> {
    let rng = &mut ark_std::test_rng();
    let max_inner_degree = (1 << 16) + 4;
    let inner_srs = veri_zexe::proofs::universal_setup_inner(max_inner_degree, rng)?;
    let max_outer_degree = (1 << 17) + 4;
    let outer_srs = veri_zexe::proofs::universal_setup_outer(max_outer_degree, rng)?;

    // 2-input-2-output
    let num_non_fee_input = 1;
    let (_dpc_pk, _dpc_vk, (_utxo_n_constraints, _outer_n_constraints)) =
        veri_zexe::proofs::transaction::preprocess(
            &outer_srs,
            &inner_srs,
            num_non_fee_input,
            INNER_DOMAIN_SIZE,
        )?;
    // eprintln!(
    //     "utxo constraints: {}, outer constraints: {}",
    //     utxo_n_constraints, outer_n_constraints
    // );
    Ok(())
}
pub fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("DPC Setup", |b| b.iter(|| dpc_setup()));
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark
);
criterion_main!(benches);
