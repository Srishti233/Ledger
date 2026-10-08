# Ledger evaluation (2026-10-08T04:22:45.932778+00:00)

Ledger 1.0.0, Python 3.12.15, Linux-6.17.0-1022-azure-x86_64-with-glibc2.41

## Against the live local chain

| records | gas used | anchor (s) | inclusion-proof verify (ms) | record verify incl. chain (ms) | batch verify incl. chain (ms) | verdict |
|---:|---:|---:|---:|---:|---:|---|
| 1 | 123078 | 0.1286 | 0.0006 | 8.099 | 7.992 | verified |
| 10 | 123078 | 0.1263 | 0.0036 | 7.84 | 8.099 | verified |
| 100 | 123078 | 0.131 | 0.0062 | 8.327 | 10.916 | verified |
| 1000 | 123090 | 0.1697 | 0.0149 | 10.939 | 50.763 | verified |

Gas range across batch sizes: 123078 to 123090 (spread 12).
A throwaway warm-up anchor ran first (gas 123030) and is excluded from the table. On a brand-new contract the very first anchor also initialises the batch counter and can cost more than later ones; on a contract that already holds batches, as here if other anchors ran first, the warm-up is just another steady-state call.

### Illustrative cost per batch (assumptions, not a live price feed)

| scenario | cost per batch (ETH) |
|---|---:|
| Ethereum L1, assumed 20 gwei | 0.002461800 |
| Typical rollup L2, assumed 0.05 gwei | 0.000006155 |
| Low-fee public testnet (no real value) | 0.000000000 |

## Pure-Python Merkle timings (no chain)

| records | tree build (ms) | proof generate (ms) | proof verify (ms) | proof length |
|---:|---:|---:|---:|---:|
| 1 | 0.001 | 0.0007 | 0.0012 | 0 |
| 10 | 0.022 | 0.0051 | 0.0067 | 4 |
| 100 | 0.181 | 0.0083 | 0.0107 | 7 |
| 1000 | 1.297 | 0.0063 | 0.0081 | 10 |
