# recovery/ -- Loss Detection & Congestion Control

## OVERVIEW

QUIC loss detection and congestion control per RFC 9002. Three parallel CC
implementations coexist: `congestion/` (legacy Reno/CUBIC), `gcongestion/`
(next-gen BBR2 ported from google/quiche) and `vcongestion/` (BBRv3 written
from draft-ietf-ccwg-bbr-07, selected as `vbbr`). `Recovery` enum dispatches
between `LegacyRecovery`, `GRecovery` and `VRecovery` via `enum_dispatch` over
the `RecoveryOps` trait (40+ methods).

## STRUCTURE

```
mod.rs              Recovery enum, RecoveryOps trait, CongestionControlAlgorithm,
                    Sent, ReleaseTime/ReleaseDecision, RecoveryConfig, constants
bandwidth.rs        Bandwidth newtype
bytes_in_flight.rs  Bytes-in-flight tracking
rtt.rs              RTT estimation

congestion/         Legacy CC (Reno, CUBIC)
  mod.rs            CongestionControlOps vtable struct, Congestion state
  recovery.rs       LegacyRecovery impl of RecoveryOps, Acked struct
  reno.rs           Static RENO: CongestionControlOps
  cubic.rs          Static CUBIC: CongestionControlOps
  delivery_rate.rs  Delivery rate sampling
  hystart.rs        HyStart slow-start exit
  prr.rs            Proportional Rate Reduction
  test_sender.rs    Test-only CC sender

gcongestion/        Next-gen CC (BBR2)
  mod.rs            CongestionControl trait, Acked struct, BbrParams (#[doc(hidden)])
  recovery.rs       GRecovery impl of RecoveryOps
  pacer.rs          Token-bucket pacer
  bbr2.rs           BBR2 top-level + Bbr2CongestionControl
  bbr2/             BBR2 state machine substates
    mode.rs         Mode enum (Startup, Drain, ProbeBw, ProbeRtt)
    startup.rs      Startup mode
    drain.rs        Drain mode
    probe_bw.rs     ProbeBW mode (bandwidth probing cycles)
    probe_rtt.rs    ProbeRTT mode (min RTT measurement)
    network_model.rs  Bandwidth/RTT model, BbrParams application
    rtt_jump_detector/  RTT jump detection (global-min + HMM)
  bbr.rs            BBR (v1, not actively used)

vcongestion/        BBRv3 from draft-ietf-ccwg-bbr-07 (no code shared with
                    the other impls besides Bandwidth/RttStats/BytesInFlight/
                    ReleaseDecision)
  mod.rs            Module root, exports VRecovery
  recovery.rs       VRecovery: RFC 9002 loss detection + BBR glue
  bbr/mod.rs        BBRv3 state machine (draft Sections 5.x)
  bbr/tests.rs      Draft Appendix A scenarios, run on sim.rs
  delivery_rate.rs  Delivery rate sampler (draft Section 4.1)
  pacer.rs          Pacer + send quantum (draft Sections 5.6.2/5.6.3)
  windowed_filter.rs  Windowed max filter
  sim.rs            Test-only discrete-event bottleneck simulator
```

## WHERE TO LOOK

| Task | File | Notes |
|------|------|-------|
| Add/change CC algorithm | `congestion/mod.rs` or `gcongestion/mod.rs` | Different dispatch patterns |
| Modify loss detection | `congestion/recovery.rs` or `gcongestion/recovery.rs` | Parallel impls |
| Shared trait surface | `mod.rs:183-320` | `RecoveryOps` -- both impls must satisfy |
| Algorithm selection | `mod.rs:365` | `CongestionControlAlgorithm` enum, `#[repr(C)]` for FFI |
| BBR2 tuning | `gcongestion/bbr2/network_model.rs` | `BbrParams` applied here |
| Pacing | `gcongestion/pacer.rs`, `mod.rs:691` | `ReleaseTime`, `ReleaseDecision` |
| Per-packet metadata | `mod.rs:394` | `Sent` struct |
| qlog integration | grep `#[cfg(feature = "qlog")]` | Gated throughout both impls |

## ANTI-PATTERNS

- **Two `Acked` structs** at `congestion/recovery.rs:1079` and `gcongestion/mod.rs:49`.
  NOT unified. Do NOT create a third.
- **FIXME stubs**: Some `RecoveryOps` methods only apply to one impl. Both sides
  have `// FIXME only used by {congestion,gcongestion}` stubs that return
  defaults. Do not proliferate; prefer narrowing the shared trait.
- **`congestion/` uses C-like vtable** (`CongestionControlOps` with static fn
  pointers: `RENO`, `CUBIC`). `gcongestion/` uses trait objects
  (`CongestionControl` trait). Do not mix dispatch styles.
- **`BbrParams` is `#[doc(hidden)]`** and experimental. Do not stabilize or
  expose without explicit intent.
- **Many `#[cfg(test)]` accessors** on `RecoveryOps` (lines 200-297). Test-only;
  do not call from production code.

## NOTES

- Constants cite RFC 9002: `INITIAL_TIME_THRESHOLD = 9.0/8.0`, `GRANULARITY = 1ms`.
- `CongestionControlAlgorithm` values: Reno=0, CUBIC=1, Bbr2Gcongestion=4,
  CongestionWindowUnchecked=5 when enabled, Vbbr=6. Gaps are intentional (removed variants).
- `Recovery::new_with_config` tries `VRecovery::new`, then `GRecovery::new`;
  falls back to `LegacyRecovery` for Reno, CUBIC, and CongestionWindowUnchecked.
- `vcongestion/` maps BBR's TCP concepts onto QUIC: Fast Recovery = RFC 9002
  Section 7.3.2 recovery period, RTO = persistent congestion (Section 7.6), a
  spurious episode = all congestion-signaled losses later acked. Code comments
  cite draft/RFC sections; keep doing so. Do not port code from gcongestion.
- `bbr2/` is a deeply nested state machine -- changes require understanding all six substates.
- `enable_relaxed_loss_threshold` experiment adjusts time thresholds dynamically on spurious loss.
- `gcongestion/bbr.rs` is BBRv1 -- mostly vestigial alongside BBR2.
