
╔══════════════════════════════════════════════════════════════╗
║           📊 TRIAGE METRICS REPORT                            ║
║           fuzzing-demo | 2026-07-02 12:38                    
╚══════════════════════════════════════════════════════════════╝

 RAW METRICS:
 ──────────────────────────────┬──────────┐
 │ Total crashes                │     1000 │
 │ Unique bugs                  │        7 │
 │ Real vulnerabilities         │        5 │
 │ False positives              │        2 │
 ──────────────────────────────┴──────────┘

 EFFICIENCY METRICS:
 ┌──────────────────────────────┬──────────┐
 │ Deduplication ratio          │   142.9x │
 │ False positive rate          │    28.6% │
 │ Signal-to-noise ratio        │ 5/1000 (0.5%) │
 └──────────────────────────────┴──────────┘

 TIME SAVINGS:
 ──────────────────────────────┬──────────┐
 │ Manual triage (20min/crash)  │   333.3h │
 │ Automated triage (2min/bug)  │     0.2h │
 │ Time saved                   │   333.1h │
 │ Efficiency gain              │  1428.6x │
 └──────────────────────────────┴──────────┘

 KPI TARGETS:
 ──────────────────────────────┬──────────┬──────────┬────────┐
 │ Metric                       │ Target   │ Actual   │ Status │
 ├──────────────────────────────┼──────────┼──────────┼────────┤
 │ FP rate                      │ < 20%   │   28.6% │       │
 │ Dedup ratio                  │ > 10x   │  142.9x │ ✅      │
 │ TTD (Time-to-Detect)         │ < 24h    │ < 1h     │ ✅     │
 └──────────────────────────────┴──────────┴──────────┴────────

 TOP VULNERABILITIES (by CVSS):
   1. [9.8] heap-buffer-overflow      ×  150 crashes  CWE-122
   2. [9.8] use-after-free            ×   80 crashes  CWE-416
   3. [9.8] stack-buffer-overflow     ×   45 crashes  CWE-121
   4. [9.1] prototype-pollution       ×  180 crashes  CWE-1321
   5. [5.0] null-dereference          ×  200 crashes  CWE-476

 RECOMMENDATIONS:
   1. Investigate heap-buffer-overflow (CVSS 9.8) — highest priority
   2. Review use-after-free in connection handling
   3. Fix prototype pollution in JSON parser
   4. Add input validation to prevent ReDoS

 COMPLIANCE (ФСТЭК № 239):
   ✅ All findings classified by CWE/CVSS
   ✅ PoC preserved in MinIO evidence bucket
   ✅ FSTEC report auto-generated
   ✅ Audit trail maintained

══════════════════════════════════════════════════════════════════════
