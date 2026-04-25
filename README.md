\# AHEPQC-IIoT: Adaptive Hybrid Post-Quantum Cryptography Migration Framework for Fuel and Petroleum Industrial IoT Infrastructure



> Course project for \*\*CSEC 559 — Advanced Topics in Cybersecurity\*\*, 

> Rochester Institute of Technology, Spring 2026.



This repository accompanies our term paper \*"An Adaptive Hybrid Post-Quantum Cryptography Migration Framework for Fuel and Petroleum Industrial IoT Infrastructure"\*, which proposes a tiered post-quantum cryptography migration framework for fuel-sector Industrial IoT and evaluates it against the PQShield-IoT baseline of Narayanan et al.



\## Authors



\- Nadeen Ahmad

\- Lana Al Tajer

\- Farida Emam

\- Farkh Leka Hashimy

\- Sara Zako



\## Contents



| Folder | Contents |

|---|---|

| `simulation/` | Contiki-NG C source for sensors and gateways (Run A baseline + Run B proposed), shared `project-conf.h` |

| `analysis/` | Python parser that ingests Cooja logs and produces the seven evaluation metrics and QERS scores reported in the paper |

| `results/` | Raw Cooja logs (`COOJA\_A.txt`, `COOJA\_B.txt`) and the parsed metric output |

| `docs/` | Architecture notes, methodology details, and figures referenced in the paper |



\## Methodology note



The Cooja simulation produces \*\*real network behaviour\*\* (UDP, RPL, 6LoWPAN, CSMA) but \*\*models cryptographic costs\*\* from published constrained-device benchmarks (Shahid et al. 2026, FIPS 203/204).



\## Results summary



| Metric | Run A (Baseline) | Run B (AHEPQC-IIoT) | Δ |

|---|---|---|---|

| Peak per-sensor RAM (KB) | 61.5 | 16.5 | −73.2% |

| Communication overhead (B) | 3,256 | 806 | −75.3% |

| Key + signature size (B) | 4,532 | 800 | −82.3% |

| Fusion QERS | 31.5 | 95.5 | +64.0 |



\## License



MIT — see \[LICENSE](LICENSE).



\## Acknowledgements



Completed as part of CSEC 559 (Spring 2026) at Rochester Institute of Technology, under the supervision of Dr. Wesam Almobaideen.

