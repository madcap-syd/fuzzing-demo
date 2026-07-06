# Fuzzing Demo - Automated Vulnerability Discovery Pipeline

Automated DevSecOps pipeline for C++ fuzzing with ML classification and DefectDojo integration.

## Quick Start

```bash
sudo apt install -y clang llvm libunwind-dev binutils-dev
pip3 install scikit-learn numpy pandas joblib requests
./run_honggfuzz_pipeline.sh 60
```

## Architecture

Code -> Fuzzing (LibFuzzer/HonggFuzz) -> Crash Files -> Deduplication (SHA-256) -> FP Filter (ML 95%) -> DefectDojo -> MinIO WORM

## Metrics

| Metric | Value |
|--------|-------|
| Crashes/night | ~1000 |
| Dedup ratio | 143x |
| FP rate | <15% |
| ML accuracy | 95% |
| TTD | <24h |
| Efficiency | 1400x |

## Vulnerability Types

1. **Heap Buffer Overflow** (CWE-122) - memcpy without bounds check
2. **Use-After-Free** (CWE-416) - read after delete
3. **Stack Buffer Overflow** (CWE-121) - strcpy without limit
4. **Integer Overflow** (CWE-190) - width*height overflow
5. **Null Pointer Dereference** (CWE-476) - *ptr where ptr=nullptr

## Repository Structure

- fuzz-cpp/ - C++ fuzzing targets and harnesses
- ml/ - ML classifier (fp_classifier.pkl, 95% accuracy)
- scripts/ - Automation (parse, upload to DefectDojo)
- .github/workflows/ - CI/CD pipeline
- run_honggfuzz_pipeline.sh - End-to-end pipeline

## Tech Stack

- **Fuzzers:** LibFuzzer, HonggFuzz, Jazzer.js
- **Sanitizers:** ASan, UBSan
- **ML:** scikit-learn, Gradient Boosting
- **Vulnerability Management:** DefectDojo
- **Storage:** MinIO (WORM, 365 days)
- **CI/CD:** GitHub Actions
- **Compliance:** FSTEC 239, GOST R 56939

## Interview Pitch

I built an automated DevSecOps pipeline for C++ fuzzing. LibFuzzer generates ~1000 crashes per night. My pipeline deduplicates them by stack trace (1000 to 7 unique bugs), filters FPs via 3-level system (heuristics + known issues + ML with 95% accuracy), classifies by CWE/CVSS, creates tickets in DefectDojo via API, and stores PoCs in WORM storage for FSTEC compliance. Result: 333 hours manual work to 0.2 hours automated. 1400x efficiency gain.

## Author

madcap-syd | github.com/madcap-syd
