use coin::{Block, BlockHeader, Blockchain, coinbase_transaction};
use criterion::{Criterion, criterion_group, criterion_main};
use miner::mine_block_threads;

fn setup_chain() -> Blockchain {
    let mut bc = Blockchain::new();
    bc.add_block(Block {
        header: BlockHeader {
            previous_hash: String::new(),
            merkle_root: String::new(),
            timestamp: 0,
            nonce: 0,
            difficulty: 0,
        },
        transactions: vec![coinbase_transaction("bench", bc.block_subsidy())],
    });
    bc
}

fn bench_single_thread(c: &mut Criterion) {
    c.bench_function("mine_1_thread", |b| {
        b.iter(|| {
            let mut bc = setup_chain();
            mine_block_threads(&mut bc, "bench", 1);
        });
    });
}

fn bench_multi_thread(c: &mut Criterion) {
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2);
    c.bench_function(&format!("mine_{}_threads", threads), |b| {
        b.iter(|| {
            let mut bc = setup_chain();
            mine_block_threads(&mut bc, "bench", threads);
        });
    });
}

criterion_group!(benches, bench_single_thread, bench_multi_thread);
criterion_main!(benches);
