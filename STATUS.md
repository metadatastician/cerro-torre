<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Cerro Torre — Measured Status

**Last measured:** 2026-07-28  
**Honest completion:** ~35%  
**Languages:** Ada/SPARK (primary) · Idris2 (proofs) · Rust (signing) · Zig (FFI)

> This document records **measured** state: every claim below is a file read, a build
> run, or a test executed on the dates shown. Where an existing document in this repo
> contradicts it, this one is correct and the other is stale. Full evidence and
> cross-repo context: `dev-notes/stapeln-ecosystem-COMPREHENSIVE-SITREP-2026-07-28.md`.

## Summary

~35%. The largest real code body in the ecosystem, and it cannot be built.

## What genuinely works

- **23,607 lines of Ada across 59 files, and all 59 pass `gcc -gnats -gnat2022` syntax checking.** This is not scaffolding.
- Excellent Idris2 proofs: 7 files, 88 definitions, all typecheck, ZERO `believe_me`/`assert_total`/holes, with an explicit written HONESTY POLICY banning `cast Refl`
- **Owns two of the four genuinely enforced CI gates in the whole ecosystem**: `formal-verification.yml` (`idris2 --build` on an ipkg — the correct honest form) and `pqcrypto-build-test.yml` (builds liboqs from a resolved SHA, `set -euo pipefail`)

## What is broken, missing, or misreported

- **The project cannot build.** `gprbuild -P cerro_torre.gpr` fails: `imported project file "config/cerro_torre_config.gpr" not found`. `config/` is gitignored (an alire convention — `alr` generates it), and `alr` is not installed. The linker also hard-requires `-loqs`, and liboqs is absent.
- **Provenance verification is `return True`.** `src/policy/cerro_policy_enforce.adb`: `Verify_Trust_Store` and `Verify_Policy` both `-- MVP stub: Return True`. `Check_Signatures` sets `Signatures_Required := 0` and returns Inconclusive; `Check_SBOM` returns `SBOM_Present := False`; `Check_Registry` returns `Registry_Allowed := True`. 17 TODOs in that one file. This is the repo's entire reason to exist.
- **`gnatprove` has never been run** — no `.spark` artifacts. Of 26 files with `pragma SPARK_Mode`, roughly 8 are `On` and 20 are `Off`, and the `Off`s are exactly the security-critical modules (registry, transparency, http, crypto, sbom).
- 33 `Not_Implemented` and 80 `TODO` markers across the Ada.
- `src-rust/main.rs` (`cerro-sign`) fails `cargo check` — `E0277`, ed25519-dalek/rand version mismatch.
- `ffi/zig` fails to build on Zig 0.16 (same error as vordr).
- `ABI-FFI-README.md` is an unfilled template with 27 `{{...}}` placeholders, byte-identical to vordr's, and describes a directory layout this repo does not have.
- Two remotes with two identities: `hyperpolymath -> hyperpolymath/cerrotorre.git` is UNREACHABLE; `main` tracks `origin -> metadatastician/cerro-torre`.
- `alire.toml` carries placeholder identity: `maintainers = ["cerro-torre@example.org"]`, `website = "https://cerro-torre.org"`.

## Notes and open rulings

- `IMPLEMENTATION-STATUS.md` claims 'Build System OK Working 100%' and 'Build Status: PASSING'. Both are false on a clean checkout. `E2E-TEST-RESULTS.md` claims '40/41 PASS (97.6%)' — unreproducible, since no test is buildable and `ct_test_parser.adb` contains 0 assertions.
- `evidence/2025-12-30/` is NOT evidence: 4 files, 16 lines total, `ls -la` output from a DIFFERENT machine (`/home/user/cerro-torre`, root-owned), one of which records a failure (`ls: cannot access .../tests/: No such file or directory`).
- OPEN RULING R4: unblock the build via alr; drop the SPARK claim until gnatprove runs green.

## Next actions

1. URGENT: change Verify_Trust_Store and Verify_Policy from `return True` to `return False` (fail closed) until implemented
2. Unblock the build: install alr (or vendor config/cerro_torre_config.gpr) and liboqs
3. RULING NEEDED (R4): is SPARK the goal, or plain Ada + the (real) Idris2 proofs?
4. Run gnatprove at least once, or remove 'formally verified' from the README
5. Correct IMPLEMENTATION-STATUS.md and E2E-TEST-RESULTS.md — both claim passing states that do not exist
6. Remove the unreachable `hyperpolymath` remote; fix alire.toml placeholder identity

## Ecosystem position

This repo is part of the six-repo container stack designed by `stapeln`. The canonical
integration contract is the 8-file `container/stapeln/` bundle, in which each satellite
consumes its own file:

| File | Consumer |
|---|---|
| `compose.toml` | selur |
| `vordr.toml` | vordr |
| `rokur.toml` | rokur |
| `.gatekeeper.yaml` | svalinn |
| `manifest.toml` + `ct-build.sh` | cerro-torre |
| `deploy.k9.ncl` | K9 / k9-svc |

Runtime chain: `svalinn (443/80) -> rokur (8081) -> app`, with vordr watching all three,
cerro-torre signing each as a `.ctp`, and selur as the network driver.

**As of this measurement no repo emits or consumes that bundle**; five mutually
incompatible ad-hoc contracts exist instead, of which exactly one works.

