# Ledger evaluation (2026-10-07T13:29:08.834496+00:00)

Ledger 1.0.0, Python 3.12.3, Linux-6.18.44-fc-v77-x86_64-with-glibc2.39

## Pure-Python Merkle timings (no chain)

| records | tree build (ms) | proof generate (ms) | proof verify (ms) | proof length |
|---:|---:|---:|---:|---:|
| 1 | 0.001 | 0.0007 | 0.0011 | 0 |
| 10 | 0.019 | 0.0047 | 0.0061 | 4 |
| 100 | 0.168 | 0.0079 | 0.01 | 7 |
| 1000 | 1.709 | 0.0109 | 0.013 | 10 |
