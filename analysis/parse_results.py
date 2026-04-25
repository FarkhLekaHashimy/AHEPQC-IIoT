#!/usr/bin/env python3
"""
parse_results.py
================
Parses Cooja logs for Run A and Run B.
Reports all 7 evaluation metrics and computes QERS
(Basic, Tuned, Fusion) for both runs.

Source: Rassekhnia (2026) - QERS framework
        Quantum Encryption Resilience Score QERS.pdf

Usage:
    python3 parse_results.py COOJA_A.log COOJA_B.log
"""

import re, sys, statistics, math

# ================================================================
# STATIC METRICS (not from simulation logs)
# These are fixed values based on algorithm specs
# ================================================================

# Metric 6: Firmware update time (seconds)
# Based on SLH-DSA-SHA2-128s (7856 byte signature) over
# WirelessHART at 250 kbps for a 512 KB firmware image
# Time = (512*1024 + 7856) / (250000/8) = ~16.8 seconds
# Same for both Run A and Run B since SLH-DSA is used at
# enterprise tier for all firmware signing
FIRMWARE_UPDATE_TIME = 17.0   # seconds (same both runs)

# Metric 7: Key/signature sizes (bytes)
# Run A: sensor transmits ML-KEM-512 ciphertext + Dilithium2 sig + cert
# Run B: sensor transmits ML-KEM-512 public key only
RUN_A_KEY_SIG = 800 + 2420 + 1312   # = 4532 bytes
RUN_B_KEY_SIG = 800                   # = 800 bytes

# ================================================================
# LOG PARSER
# ================================================================

def parse_log(path):
    d = {
        "lat":  [],   # latency ms
        "nrg":  [],   # energy uJ
        "ram":  [],   # RAM bytes
        "txb":  [],   # TX bytes
        "thr":  [],   # throughput msg/min
        "pkt":  []    # packet loss count
    }
    tags = {
        "M_LAT": "lat",
        "M_NRG": "nrg",
        "M_RAM": "ram",
        "M_TXB": "txb",
        "M_THR": "thr",
        "M_PKT": "pkt"
    }
    try:
        for line in open(path):
            for tag, key in tags.items():
                m = re.search(tag + r'\s+(\d+)', line)
                if m:
                    d[key].append(int(m.group(1)))
    except FileNotFoundError:
        print(f"ERROR: File not found: {path}")
        sys.exit(1)
    return d

def avg(lst):
    return statistics.mean(lst) if lst else 0.0

def pct_improve(a, b):
    """Percentage improvement, lower is better."""
    return ((a - b) / a * 100) if a != 0 else 0.0

# ================================================================
# QERS CALCULATION
# Source: Rassekhnia (2026) QERS formulation
# ================================================================

def normalize(val, vmin, vmax, ms=100):
    """Min-max normalization scaled to ms (default 100)."""
    if vmax == vmin:
        return 0.0
    return ms * (val - vmin) / (vmax - vmin)

def compute_qers(metrics_a, metrics_b, key_sig_a, key_sig_b):
    """
    Compute Basic QERS, Tuned QERS, and Fusion QERS
    for both Run A and Run B.

    QERS formula (Rassekhnia 2026):
    Basic:  MS - (α*L + β*O + γ*Ploss)
    Tuned:  MS - (α*L + β*O + γ*Ploss + δ*C + ζ*E + η*K) + ε*R
    Fusion: α*(MS - P) + β*S
      P = weighted performance subscore
      S = weighted security subscore
    """
    MS = 100  # maximum score

    # Raw values
    L_a  = avg(metrics_a["lat"])
    L_b  = avg(metrics_b["lat"])
    E_a  = avg(metrics_a["nrg"])
    E_b  = avg(metrics_b["nrg"])
    O_a  = avg(metrics_a["txb"])   # communication overhead
    O_b  = avg(metrics_b["txb"])
    K_a  = float(key_sig_a)        # key/sig sizes
    K_b  = float(key_sig_b)
    # Packet loss: count / total rounds
    Pl_a = len(metrics_a["pkt"]) / max(len(metrics_a["lat"]), 1) * 100
    Pl_b = len(metrics_b["pkt"]) / max(len(metrics_b["lat"]), 1) * 100
    # CPU utilization: modeled from timing ratios
    # Run A has more crypto time, so higher CPU %
    C_a  = 65.0   # % modeled: ECDH+KEM+Dilithium2 on sensor
    C_b  = 25.0   # % modeled: KEM only on sensor
    # RSSI: same for both (same radio conditions in Cooja)
    R    = 70.0   # dBm modeled constant

    # --- NORMALIZATION ---
    # For penalty metrics (lower=better): normalize so higher=worse
    # For benefit metrics (higher=better): normalize normally

    vals = [L_a, L_b]
    L_n_a = normalize(L_a, min(vals), max(vals))
    L_n_b = normalize(L_b, min(vals), max(vals))

    vals = [O_a, O_b]
    O_n_a = normalize(O_a, min(vals), max(vals))
    O_n_b = normalize(O_b, min(vals), max(vals))

    vals = [Pl_a, Pl_b]
    P_n_a = normalize(Pl_a, min(vals), max(vals))
    P_n_b = normalize(Pl_b, min(vals), max(vals))

    vals = [C_a, C_b]
    C_n_a = normalize(C_a, min(vals), max(vals))
    C_n_b = normalize(C_b, min(vals), max(vals))

    vals = [E_a, E_b]
    E_n_a = normalize(E_a, min(vals), max(vals))
    E_n_b = normalize(E_b, min(vals), max(vals))

    vals = [K_a, K_b]
    K_n_a = normalize(K_a, min(vals), max(vals))
    K_n_b = normalize(K_b, min(vals), max(vals))

    # RSSI is a benefit (higher=better), same for both
    R_n = normalize(R, 0, 100)

    # --- QERS WEIGHTS ---
    # Following Rassekhnia (2026) suggested weights
    alpha, beta, gamma = 0.35, 0.30, 0.20   # Basic
    delta, zeta, eta   = 0.10, 0.15, 0.10   # Tuned extras
    epsilon            = 0.05                # RSSI weight

    # --- BASIC QERS ---
    # QERSbasic = MS - (α*L + β*O + γ*Ploss)
    basic_a = MS - (alpha*L_n_a + beta*O_n_a + gamma*P_n_a)
    basic_b = MS - (alpha*L_n_b + beta*O_n_b + gamma*P_n_b)

    # --- TUNED QERS ---
    # QERStuned = MS - (α*L + β*O + γ*Ploss + δ*C + ζ*E + η*K) + ε*R
    tuned_a = MS - (alpha*L_n_a + beta*O_n_a + gamma*P_n_a +
                    delta*C_n_a + zeta*E_n_a + eta*K_n_a) + epsilon*R_n
    tuned_b = MS - (alpha*L_n_b + beta*O_n_b + gamma*P_n_b +
                    delta*C_n_b + zeta*E_n_b + eta*K_n_b) + epsilon*R_n

    # --- FUSION QERS ---
    # Performance subscore P = Σ wi*Ci (penalty: lower metrics = lower P)
    # Security subscore    S = Σ wj*Bj (benefit: PQC resistance + key size)
    #
    # Performance criteria weights
    wp_l, wp_e, wp_c = 0.35, 0.30, 0.20
    wp_o, wp_p       = 0.10, 0.05
    # Security criteria weights
    ws_k, ws_r = 0.60, 0.40  # key size diversity, proven resistance

    # Performance penalty subscores
    P_a = (wp_l*L_n_a + wp_e*E_n_a + wp_c*C_n_a +
           wp_o*O_n_a + wp_p*P_n_a)
    P_b = (wp_l*L_n_b + wp_e*E_n_b + wp_c*C_n_b +
           wp_o*O_n_b + wp_p*P_n_b)

    # Security benefit subscores
    # Run A: Dilithium2 (good) + ECDH (classical, lower PQ score)
    # Run B: Dilithium3 at gateway (better) + hybrid ECDH+MLKEM (best)
    Pr_a = 70.0   # proven resistance score: classical + PQC
    Pr_b = 90.0   # proven resistance score: hybrid + HSM + stronger params
    S_a  = ws_k * (MS - K_n_a) + ws_r * normalize(Pr_a, 0, 100)
    S_b  = ws_k * (MS - K_n_b) + ws_r * normalize(Pr_b, 0, 100)

    # Fusion: α*(MS - P) + β*S  where α+β=1
    f_alpha, f_beta = 0.5, 0.5
    fusion_a = f_alpha * (MS - P_a) + f_beta * S_a
    fusion_b = f_alpha * (MS - P_b) + f_beta * S_b

    return {
        "basic":  (basic_a,  basic_b),
        "tuned":  (tuned_a,  tuned_b),
        "fusion": (fusion_a, fusion_b),
        "raw": {
            "L": (L_a, L_b), "E": (E_a, E_b),
            "O": (O_a, O_b), "K": (K_a, K_b),
            "C": (C_a, C_b), "Pl": (Pl_a, Pl_b)
        }
    }

# ================================================================
# PRINT TABLES
# ================================================================

def print_metrics_table(a, b):
    """Print all 7 metrics comparison table."""
    print("\n" + "="*68)
    print(f"{'METRIC':<32} {'RUN A':>10} {'RUN B':>10} {'IMPROVE':>10}")
    print(f"{'':32} {'Baseline':>10} {'AHEPQC':>10} {'%':>10}")
    print("="*68)

    rows = [
        # (label, a_val, b_val, unit, lower_is_better)
        ("1. Handshake Latency",
         avg(a["lat"]), avg(b["lat"]), "ms", True),
        ("2. Energy per Handshake",
         avg(a["nrg"])/1000, avg(b["nrg"])/1000, "mJ", True),
        ("3. Peak RAM Required",
         avg(a["ram"])/1024, avg(b["ram"])/1024, "KB", True),
        ("4. Communication Overhead",
         avg(a["txb"]), avg(b["txb"]), "B", True),
        ("5. Telemetry Throughput",
         avg(a["thr"]), avg(b["thr"]), "msg/m", False),
        ("6. Firmware Update Time",
         FIRMWARE_UPDATE_TIME, FIRMWARE_UPDATE_TIME, "s", True),
        ("7. Key/Signature Sizes",
         float(RUN_A_KEY_SIG), float(RUN_B_KEY_SIG), "B", True),
    ]

    for label, va, vb, unit, lib in rows:
        if lib:
            imp = pct_improve(va, vb)
            sign = "+" if imp > 0 else ""
        else:
            imp = pct_improve(vb, va) * -1  # higher is better
            sign = "+" if imp > 0 else ""

        print(f"{label:<32} {va:>8.1f}{unit} {vb:>8.1f}{unit} "
              f"{sign}{imp:>7.1f}%")

    print("="*68)
    print(f"  Rounds collected:  Run A = {len(a['lat'])}  "
          f"Run B = {len(b['lat'])}")

def print_qers_table(qers):
    """Print QERS scores for Run A and Run B."""
    ba, bb = qers["basic"]
    ta, tb = qers["tuned"]
    fa, fb = qers["fusion"]

    def rating(s):
        if s >= 85: return "Excellent"
        if s >= 70: return "Good"
        if s >= 50: return "Moderate"
        if s >= 30: return "Poor"
        return "Unusable"

    print("\n" + "="*68)
    print("QERS  (Quantum Encryption Resilience Score) - Rassekhnia 2026")
    print(f"Scale: 0-100  |  85-100=Excellent  70-84=Good  50-69=Moderate")
    print("="*68)
    print(f"{'QERS Layer':<25} {'Run A':>12} {'Run B':>12} {'Improve':>10}")
    print("-"*68)

    for label, va, vb in [
        ("Basic QERS",  ba, bb),
        ("Tuned QERS",  ta, tb),
        ("Fusion QERS", fa, fb)
    ]:
        imp = vb - va
        sign = "+" if imp > 0 else ""
        print(f"{label:<25} {va:>7.1f} ({rating(va):^10}) "
              f"{vb:>7.1f} ({rating(vb):^10}) "
              f"{sign}{imp:>5.1f}")

    print("="*68)
    print("\nQERS Input Metrics Used:")
    raw = qers["raw"]
    print(f"  Latency:      Run A={raw['L'][0]:.1f}ms   "
          f"Run B={raw['L'][1]:.1f}ms")
    print(f"  Energy:       Run A={raw['E'][0]/1000:.2f}mJ  "
          f"Run B={raw['E'][1]/1000:.2f}mJ")
    print(f"  Overhead:     Run A={raw['O'][0]:.0f}B    "
          f"Run B={raw['O'][1]:.0f}B")
    print(f"  Key/Sig:      Run A={raw['K'][0]:.0f}B   "
          f"Run B={raw['K'][1]:.0f}B")
    print(f"  CPU model:    Run A={raw['C'][0]:.0f}%   "
          f"Run B={raw['C'][1]:.0f}%")
    print(f"  Packet loss:  Run A={raw['Pl'][0]:.1f}%  "
          f"Run B={raw['Pl'][1]:.1f}%")
    print(f"  RSSI:         Both=70 dBm (same radio conditions)")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 parse_results.py COOJA_A.log COOJA_B.log")
        sys.exit(1)

    print(f"\nParsing Run A: {sys.argv[1]}")
    a = parse_log(sys.argv[1])

    print(f"Parsing Run B: {sys.argv[2]}")
    b = parse_log(sys.argv[2])

    # Print 7-metric comparison
    print_metrics_table(a, b)

    # Compute and print QERS
    qers = compute_qers(a, b, RUN_A_KEY_SIG, RUN_B_KEY_SIG)
    print_qers_table(qers)

if __name__ == "__main__":
    main()
