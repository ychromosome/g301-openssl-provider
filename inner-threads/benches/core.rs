// SPDX-License-Identifier: LicenseRef-G301-Inner-Reserved

use std::array;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use g301_inner_threads::test_vectors::session_from_deterministic_exporter;
use g301_inner_threads::{DataChannel, EndpointRole, OpenedRecord, Session};
use openssl::cipher::Cipher;
use openssl::cipher_ctx::CipherCtx;
use zeroize::Zeroizing;

const CONTEXT: &[u8] = b"G301-WHITEPAPER-TEST";
const PAYLOAD_SIZES: [usize; 4] = [31, 136, 1024, 16_384];
const EVP_KEY_LEN: usize = 32;
const EVP_IV_LEN: usize = 12;
const EVP_TAG_LEN: usize = 16;
const EVP_HEADER_LEN: usize = 16;
const EVP_AAD_LEN: usize = 139;
const EVP_DUMMY_HEADER: [u8; EVP_HEADER_LEN] = [0; EVP_HEADER_LEN];

static BENCHMARK_EPOCH: AtomicU64 = AtomicU64::new(0);

struct EvpBaseline {
    cipher: Cipher,
    key: Zeroizing<[u8; EVP_KEY_LEN]>,
    base_iv: Zeroizing<[u8; EVP_IV_LEN]>,
    aad: [u8; EVP_AAD_LEN],
}

fn next_epoch() -> u64 {
    let epoch = BENCHMARK_EPOCH.fetch_add(1, Ordering::Relaxed);
    assert_ne!(epoch, u64::MAX, "benchmark epoch exhausted");
    epoch
}

fn benchmark_exporter() -> [u8; 48] {
    let mut exporter = array::from_fn(|index| index as u8);
    exporter[40..].copy_from_slice(&next_epoch().to_be_bytes());
    exporter
}

fn session(role: EndpointRole, mut exporter: [u8; 48]) -> Session {
    let session = session_from_deterministic_exporter(role, &mut exporter, CONTEXT).unwrap();
    assert_eq!(exporter, [0; 48]);
    session
}

fn active_pair() -> (Session, Session) {
    let exporter = benchmark_exporter();
    let mut client = session(EndpointRole::Client, exporter);
    let mut server = session(EndpointRole::Server, exporter);
    let client_commit = client.seal_commit().unwrap();
    let server_commit = server.seal_commit().unwrap();
    assert!(matches!(
        server.open_record(&client_commit),
        Ok(OpenedRecord::Commit)
    ));
    assert!(matches!(
        client.open_record(&server_commit),
        Ok(OpenedRecord::Commit)
    ));
    (client, server)
}

fn evp_baseline() -> EvpBaseline {
    let epoch = next_epoch();
    let mut key = [0x42; EVP_KEY_LEN];
    key[EVP_KEY_LEN - 8..].copy_from_slice(&epoch.to_be_bytes());

    let cipher = Cipher::fetch(None, "AES-256-GCM", None).unwrap();
    assert_eq!(cipher.key_length(), EVP_KEY_LEN);
    assert_eq!(cipher.iv_length(), EVP_IV_LEN);

    EvpBaseline {
        cipher,
        key: Zeroizing::new(key),
        base_iv: Zeroizing::new([0x24; EVP_IV_LEN]),
        aad: [0x3c; EVP_AAD_LEN],
    }
}

fn evp_nonce(base_iv: &[u8; EVP_IV_LEN], sequence: u64) -> [u8; EVP_IV_LEN] {
    let mut nonce = *base_iv;
    for (dst, src) in nonce[4..].iter_mut().zip(sequence.to_be_bytes()) {
        *dst ^= src;
    }
    nonce
}

fn evp_seal_record(baseline: &EvpBaseline, sequence: u64, plaintext: &[u8]) -> Vec<u8> {
    let nonce = evp_nonce(&baseline.base_iv, sequence);
    let mut ctx = CipherCtx::new().unwrap();
    ctx.encrypt_init(Some(&baseline.cipher), None, None)
        .unwrap();
    ctx.set_iv_length(EVP_IV_LEN).unwrap();
    ctx.encrypt_init(None, Some(&baseline.key[..]), Some(&nonce))
        .unwrap();
    ctx.cipher_update(&baseline.aad, None).unwrap();

    let mut output = Vec::with_capacity(EVP_HEADER_LEN + plaintext.len() + EVP_TAG_LEN);
    output.extend_from_slice(&EVP_DUMMY_HEADER);
    let written = ctx.cipher_update_vec(plaintext, &mut output).unwrap();
    assert_eq!(written, plaintext.len());
    let final_written = ctx.cipher_final_vec(&mut output).unwrap();
    assert_eq!(final_written, 0);
    assert_eq!(output.len(), EVP_HEADER_LEN + plaintext.len());

    let mut tag = [0; EVP_TAG_LEN];
    ctx.tag(&mut tag).unwrap();
    output.extend_from_slice(&tag);
    assert_eq!(output.len(), EVP_HEADER_LEN + plaintext.len() + EVP_TAG_LEN);
    output
}

fn evp_open_record(baseline: &EvpBaseline, sequence: u64, input: &[u8]) -> Vec<u8> {
    assert!(input.len() >= EVP_HEADER_LEN + EVP_TAG_LEN);
    let ciphertext_end = input.len() - EVP_TAG_LEN;
    let ciphertext = &input[EVP_HEADER_LEN..ciphertext_end];
    let tag = &input[ciphertext_end..];
    let nonce = evp_nonce(&baseline.base_iv, sequence);

    let mut ctx = CipherCtx::new().unwrap();
    ctx.decrypt_init(Some(&baseline.cipher), None, None)
        .unwrap();
    ctx.set_iv_length(EVP_IV_LEN).unwrap();
    ctx.decrypt_init(None, Some(&baseline.key[..]), Some(&nonce))
        .unwrap();
    ctx.cipher_update(&baseline.aad, None).unwrap();

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let written = ctx.cipher_update_vec(ciphertext, &mut plaintext).unwrap();
    assert_eq!(written, ciphertext.len());
    ctx.set_tag(tag).unwrap();
    let final_written = ctx.cipher_final_vec(&mut plaintext).unwrap();
    assert_eq!(final_written, 0);
    assert_eq!(plaintext.len(), ciphertext.len());
    plaintext
}

fn records_per_batch(size: usize) -> usize {
    match size {
        0..=136 => 4096,
        137..=1024 => 1024,
        _ => 64,
    }
}

fn benchmarks(criterion: &mut Criterion) {
    criterion.bench_function("derive_10_contexts", |benchmark| {
        benchmark.iter(|| {
            session(
                black_box(EndpointRole::Client),
                black_box(benchmark_exporter()),
            )
        })
    });

    let mut seal_group = criterion.benchmark_group("seal_data");
    for size in PAYLOAD_SIZES {
        let count = records_per_batch(size);
        let payload = vec![0x5a; size];
        seal_group.throughput(Throughput::Bytes((size * count) as u64));
        seal_group.bench_with_input(BenchmarkId::new("menora", size), &size, |benchmark, _| {
            benchmark.iter_batched_ref(
                || active_pair().0,
                |client| {
                    for _ in 0..count {
                        black_box(
                            client
                                .seal_data(DataChannel::Menora, black_box(&payload))
                                .unwrap(),
                        );
                    }
                },
                BatchSize::SmallInput,
            )
        });
        seal_group.bench_with_input(
            BenchmarkId::new("evp_aes_256_gcm", size),
            &size,
            |benchmark, _| {
                benchmark.iter_batched_ref(
                    evp_baseline,
                    |baseline| {
                        for sequence in 0..count {
                            black_box(evp_seal_record(
                                baseline,
                                sequence as u64,
                                black_box(&payload),
                            ));
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    seal_group.finish();

    let mut open_group = criterion.benchmark_group("open_data");
    for size in PAYLOAD_SIZES {
        let count = records_per_batch(size);
        let payload = vec![0xa5; size];
        open_group.throughput(Throughput::Bytes((size * count) as u64));
        open_group.bench_with_input(BenchmarkId::new("menora", size), &size, |benchmark, _| {
            benchmark.iter_batched_ref(
                || {
                    let (mut client, server) = active_pair();
                    let records = (0..count)
                        .map(|_| client.seal_data(DataChannel::Menora, &payload).unwrap())
                        .collect::<Vec<_>>();
                    (server, records)
                },
                |(server, records)| {
                    for record in records {
                        black_box(server.open_record(black_box(record)).unwrap());
                    }
                },
                BatchSize::SmallInput,
            )
        });
        open_group.bench_with_input(
            BenchmarkId::new("evp_aes_256_gcm", size),
            &size,
            |benchmark, _| {
                benchmark.iter_batched_ref(
                    || {
                        let baseline = evp_baseline();
                        let records = (0..count)
                            .map(|sequence| evp_seal_record(&baseline, sequence as u64, &payload))
                            .collect::<Vec<_>>();
                        (baseline, records)
                    },
                    |(baseline, records)| {
                        for (sequence, record) in records.iter().enumerate() {
                            black_box(evp_open_record(
                                baseline,
                                sequence as u64,
                                black_box(record.as_slice()),
                            ));
                        }
                    },
                    BatchSize::SmallInput,
                )
            },
        );
    }
    open_group.finish();
}

fn config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(5))
        .sample_size(100)
}

criterion_group! {
    name = core;
    config = config();
    targets = benchmarks
}
criterion_main!(core);
