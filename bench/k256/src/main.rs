//! Benchmarks k256 (pure Rust) on the same operations as the C and Mojo
//! suites, with the same methodology: minimum over repeated rounds, and a
//! dependency chained through each loop so nothing can be hoisted.

use std::hint::black_box;
use std::time::Instant;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};

fn bench<F: FnMut() -> u64>(name: &str, rounds: usize, iters: usize, mut f: F) {
    let mut best = f64::MAX;
    let mut sink = 0u64;
    for _ in 0..rounds {
        let t0 = Instant::now();
        for _ in 0..iters {
            sink = sink.wrapping_add(f());
        }
        let us = t0.elapsed().as_nanos() as f64 / 1000.0 / iters as f64;
        if us < best {
            best = us;
        }
    }
    black_box(sink);
    println!("{:<34}{:>12.4}", name, best);
}

fn main() {
    // Deterministic key material, same shape as the other suites.
    let mut sk_bytes = [0u8; 32];
    for (i, b) in sk_bytes.iter_mut().enumerate() {
        *b = (1 + i * 7) as u8;
    }
    let mut msg = [0u8; 32];
    for (i, b) in msg.iter_mut().enumerate() {
        *b = (200 - i * 3) as u8;
    }

    let secret = SecretKey::from_slice(&sk_bytes).expect("valid secret key");
    let signing = SigningKey::from(&secret);
    let verifying = VerifyingKey::from(&signing);
    let public = PublicKey::from(verifying);

    let sig: Signature = signing.sign_prehash(&msg).expect("sign");

    println!("{:<34}{:>12}", "Benchmark", "Min(us)");
    println!();

    bench("ecdsa_verify", 10, 200, || {
        verifying.verify_prehash(&msg, &sig).is_ok() as u64
    });

    bench("ecdsa_sign", 10, 200, || {
        let s: Signature = signing.sign_prehash(&msg).expect("sign");
        s.to_bytes()[0] as u64
    });

    // Isolate k*G: multiply the generator by the secret scalar directly,
    // rather than going through SigningKey (which does extra bookkeeping).
    let scalar = *secret.to_nonzero_scalar().as_ref();
    bench("ec_keygen (generic mul)", 10, 200, || {
        let p = k256::ProjectivePoint::GENERATOR * scalar;
        p.to_affine().to_encoded_point(true).as_bytes()[1] as u64
    });
    // The generic Mul impl does not use the precomputed generator table;
    // mul_by_generator is the one that does.
    bench("ec_keygen (mul_by_generator)", 10, 200, || {
        use elliptic_curve::ops::MulByGenerator;
        let p = k256::ProjectivePoint::mul_by_generator(&scalar);
        p.to_affine().to_encoded_point(true).as_bytes()[1] as u64
    });

    bench("ecdh", 10, 200, || {
        let shared = k256::ecdh::diffie_hellman(
            secret.to_nonzero_scalar(),
            public.as_affine(),
        );
        shared.raw_secret_bytes()[0] as u64
    });
}
