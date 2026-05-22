"""
AegisLEO PQC Benchmarks
-----------------------
Measures ML-KEM-1024 and ML-DSA-65 operation latency on the current hardware.

Run on each node to characterize crypto overhead:
    python -m experiments.pqc_benchmarks

Expected output:
    ML-KEM-1024  keygen:       X.XXX ms
    ML-KEM-1024  encapsulate:  X.XXX ms
    ML-KEM-1024  decapsulate:  X.XXX ms
    ML-DSA-65    keygen:       X.XXX ms
    ML-DSA-65    sign:         X.XXX ms
    ML-DSA-65    verify:       X.XXX ms
"""

import time
import statistics

import oqs

ITERATIONS = 50


def bench(label: str, fn, n: int = ITERATIONS) -> float:
    times = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    median = statistics.median(times)
    print(f"  {label:<30} {median:7.3f} ms  (median of {n})")
    return median


def benchmark_kem(algorithm: str = "ML-KEM-1024") -> None:
    print(f"\n{algorithm}")

    with oqs.KeyEncapsulation(algorithm) as kem:
        bench("keygen", kem.generate_keypair)
        public_key = kem.export_public_key()

    with oqs.KeyEncapsulation(algorithm) as enc:
        enc.generate_keypair()
        pub = enc.export_public_key()
        bench("encapsulate", lambda: enc.encap_secret(pub))
        ct, ss = enc.encap_secret(pub)

    with oqs.KeyEncapsulation(algorithm, enc.export_secret_key()) as dec:
        bench("decapsulate", lambda: dec.decap_secret(ct))


def benchmark_sig(algorithm: str = "ML-DSA-65") -> None:
    print(f"\n{algorithm}")
    message = b"AegisLEO benchmark payload " * 10

    with oqs.Signature(algorithm) as signer:
        bench("keygen", signer.generate_keypair)
        signer.generate_keypair()
        bench("sign", lambda: signer.sign(message))
        sig = signer.sign(message)
        pub = signer.export_public_key()

    with oqs.Signature(algorithm) as verifier:
        bench("verify", lambda: verifier.verify(message, sig, pub))


if __name__ == "__main__":
    print("AegisLEO PQC Benchmark")
    print("=" * 45)
    benchmark_kem("ML-KEM-1024")
    benchmark_sig("ML-DSA-65")
    print()
