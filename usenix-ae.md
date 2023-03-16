# USENIX23 Artifact Evaluation README

## Getting Started

First, ensure you have [Rust](https://www.rust-lang.org/tools/install) installed. 
Then, try to run `cargo build --release` to compile the project.


## E1: Benchmark using a powerful server

In your AWS EC2 instance of type `c5a.16xlarge` (64 vCPU, 128GB RAM), simply run:

```
cargo test dpc_bench --release -- --nocapture
```

> ⚠️ If you run on MacOS, you won't see memory usage report in the log since we rely on a crate [`proc-status`](https://github.com/Canop/proc-status) that only works on Linux machines.

You should see terminal output logs similar to the following:

```
running 1 test
ℹ️️ inner_srs size: 13632280 bytes, outer_srs size: 52430120 bytes
⏱️ DPC::Setup::universal (inner_max_deg: 131076, outer_max_deg: 262148) takes 1975 ms

ℹ️ num of inputs/outputs: 2
ℹ️ num_constraint of (unpadded) UTXO circuit: 32779
ℹ️ num_constraint of (unpadded) outer circuit: 87176
ℹ️ num_constraint of UTXO circuit: 65536, of outer circuit: 87176
ℹ️️ indexed DPC vk size: 4372 bytes
⏱️ DPC::Setup::circuit-specific takes 9807 ms
ℹ️ birth predicate size: 32768; death predicate size: 32768
⏱️ DPC::GenAddress takes 1 ms
ℹ️️ indexed predicate vk size: 1354 bytes
⏱️ all 4 predicate proofs gen takes: 1666 ms
ℹ️ num_constraint of (unpadded) UTXO circuit: 32779
⏱️️ UTXO proof gen takes: 1600 ms
ℹ️ num_constraint of (unpadded) outer circuit: 87176
⏱️ Outer proof gen takes: 13136 ms
ℹ️ txn_note size: 4738 bytes; txn proof size: 4138 bytes
⏱️ DPC::Execute takes 16879 ms
⏱️ DPC::Verify takes 17 ms

ℹ️ num of inputs/outputs: 3
ℹ️ num_constraint of (unpadded) UTXO circuit: 48183
ℹ️ num_constraint of (unpadded) outer circuit: 126076
ℹ️ num_constraint of UTXO circuit: 65536, of outer circuit: 126076
ℹ️️ indexed DPC vk size: 4372 bytes
⏱️ DPC::Setup::circuit-specific takes 16470 ms
ℹ️ birth predicate size: 32768; death predicate size: 32768
⏱️ DPC::GenAddress takes 1 ms
ℹ️️ indexed predicate vk size: 1354 bytes
⏱️ all 6 predicate proofs gen takes: 2227 ms
ℹ️ num_constraint of (unpadded) UTXO circuit: 48183
⏱️️ UTXO proof gen takes: 1595 ms
ℹ️ num_constraint of (unpadded) outer circuit: 126076
test bench::dpc_bench has been running for over 60 seconds
⏱️ Outer proof gen takes: 24769 ms
ℹ️ txn_note size: 4802 bytes; txn proof size: 4138 bytes
⏱️ DPC::Execute takes 29251 ms
⏱️ DPC::Verify takes 18 ms
...
```

`DPC::Execute` is the transaction generation we refer to in [VeriZexe](https://eprint.iacr.org/2022/802.pdf).
All of VeriZexe data reported (including the constraint complexity) in Table 2 of [XCZ+22] can be found in these logs.

## E3: Benchmark across different hardware environments

Enter your other two AWS EC2 instances of types `a1.xlarge` (4 vCPU, 8GB RAM) and `c5a.4xlarge` (16 vCPU, 32GB RAM).

Since we only measure the `2x2`-transaction, we comment out the other transaction dimensions first by going to file `./src/bench.rs`, Line `70-71`:

```rust
    zcash_transaction_full_cycle(&inner_srs, &outer_srs, 2)?;
    zcash_transaction_full_cycle(&inner_srs, &outer_srs, 3)?; // # comment this line
    zcash_transaction_full_cycle(&inner_srs, &outer_srs, 4)?; // # comment this line
```

Then simply run `cargo test dpc_bench --release -- --nocapture` again to get Table 4 of [XCZ+22].
