<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
> [!WARNING]
> **SUPERSEDED — the percentages and feature ticks below are unmeasured and predate 2026-01-25. Do not cite them.**
> See `STATUS.md` for measured state.
>
> The 2026-07-28 falsification banner that stood here has itself been overtaken by
> events, so it is restated rather than repeated. It said the project *"does not
> build on a clean checkout (config/\*.gpr gitignored, alr absent, liboqs absent)."*
> Two of those three causes are now fixed, and a fourth cause it never identified
> turned out to be the real one.

# Cerro Torre - Implementation Status

## Build status, measured 2026-08-27

**The project compiles for the first time. It does not yet link.**

```
gprbuild -c -k -U -P cerro_torre.gpr -p -j0
  35 of 36 .adb files: zero semantic errors
   1 of 36:            cerro_provenance.adb, 50 errors -- see issue #22
```

Four stacked defects, each hiding the next, are what actually stopped this
building — none of them was the Alire config file that was blamed:

1. **An estate sweep had deleted 1,458 lines of source.** Commit `8c2c1a0`
   (2026-07-23) removed all nine files in `src/build/` while `cerro_torre.gpr:30`
   still listed the directory, so the project died at *project load* — exit 5,
   zero files compiled. Restored in #20.
2. **`.gitignore` hid the deletion.** Line 95 was an unanchored `build/`, which
   matches `src/build/` at any depth, so 1,458 deleted lines of Ada left nothing
   in `git status`. Anchored to `/build/` in #20.
3. **`config/cerro_torre_config.gpr` was gitignored and Alire-generated**, and
   `alr` is unavailable. Nothing in the tree dereferences any
   `Cerro_Torre_Config.*` identifier, so a six-line abstract project satisfies the
   with-clause. Added in #20.
4. **Widespread never-compiled Ada.** Two child units had no parent packages at
   all; two package bodies had no spec; three call sites used a `Spawn` overload
   that does not exist; the keygen block was written against a trust-store API
   that never existed. Fixed in #21.

**Known-open, both tracked:**

- **#22** — `cerro_provenance.adb` is not a broken body: its spec declares 9
  subprograms, it implements 8, and the overlap is **zero**. Two incompatible
  designs of one package. Needs a design decision, not a fix. Zero callers, and no
  fail-open path, so nothing is armed by leaving it.
- **#23** — **liboqs blocks LINK, not compile**, so there is still no `bin/ct`
  here. `src/bindings/liboqs.ads` uses `pragma Import` with no header inclusion,
  so the Ada compiles and `-loqs` fails at link. Owner has ruled the repo must be
  standalone-buildable; `CERRO_FEATURES=infrastructure` does **not** currently
  achieve that (it adds 3 further errors, because `src/core/ct_pqcrypto.adb` is in
  every feature set and references the excluded `src/bindings`).

**On style diagnostics:** `cerro_torre.gpr:75` sets `-gnaty…` but **not**
`-gnatwe`. A forced recompile of a file with 34 style violations exits **0**, so
they are warnings and are excluded from the counts above rather than folded in.

---

**Last Updated**: 2026-01-25 *(the section above is 2026-08-27; everything below this line is the original January document)*
**Version**: 0.2.0-dev

---

## Quick Status Overview

> The table and percentages below are the original January 2026 self-assessment.
> They were never measured, and the `Build System … 0%` row is now wrong in both
> directions — it compiles (35 of 36 bodies clean) but still does not link. Read
> the measured section at the top of this file instead.

| Component | Status | Completeness |
|-----------|--------|--------------|
| **Build System** | ❌ Unbuildable on clean checkout | 0% |
| **Core Types** | ✅ Working | 100% |
| **HTTP Client** | ✅ Working | 95% |
| **Registry Client** | ✅ Working | 80% |
| **Transparency Logs** | ✅ Working | 70% |
| **Cryptography** | ⚠️ Partial | 60% |
| **CLI** | ⚠️ Partial | 40% |
| **SPARK Proofs** | ❌ Blocked | 0% (proven lib issues) |

**Overall Completion**: **~65%** (MVP features implemented)

---

## ✅ Fully Implemented Features

### 1. Build Infrastructure — see the measured Build status at the top of this file

- ⚠️ Alire project configuration — `alr` is not available here, and the config
  project it generates is gitignored; a hand-written abstract stand-in is
  committed instead (#20)
- ✅ GNAT project files
- ✅ Multi-mode builds (Development, Release, Proof)
- ⚠️ Test executables (crypto, parser, e2e) — declared as `Main`, but none can be
  produced until the link succeeds (#23)
- ⚠️ Compilation — **35 of 36 bodies clean as of 2026-08-27** (#20, #21). Not
  "clean compilation": `cerro_provenance.adb` still has 50 errors (#22). This
  line previously read "✅ Clean compilation (no errors, style warnings only)"
  at a time when the project could not even be opened.

### 2. HTTP Client (CT_HTTP) - 95%

**Implemented**:
- ✅ GET/POST/PUT/DELETE/HEAD/PATCH operations
- ✅ Bearer token authentication
- ✅ HTTP Basic authentication
- ✅ TLS verification (enabled by default)
- ✅ Redirect following (configurable)
- ✅ Timeout configuration
- ✅ Custom headers support
- ✅ HTTP version negotiation (HTTP/1.1, HTTP/2, HTTP/3)
- ✅ Encrypted Client Hello (ECH) support
- ✅ DANE/TLSA certificate validation
- ✅ DNS-over-HTTPS (DoH) support
- ✅ Oblivious DNS-over-HTTPS (ODoH) support
- ✅ Proxy support (HTTP, SOCKS4/5)
- ✅ Response parsing (status, headers, body)

**Pending**:
- ⏳ Download to file (streaming) - Function exists but needs testing
- ⏳ Upload from file (streaming) - Function exists but needs testing
- ⏳ WWW-Authenticate header parsing (partial implementation)

**Files**: `src/core/ct_http.{ads,adb}`

### 3. Registry Client (CT_Registry) - 80%

**Implemented**:
- ✅ OCI Distribution API v2 support
- ✅ Image reference parsing (`registry/repo:tag@digest`)
- ✅ Registry client creation
- ✅ Authentication conversion (Registry → HTTP)
- ✅ Pull manifest (GET /v2/{repo}/manifests/{ref})
- ✅ Push manifest (PUT /v2/{repo}/manifests/{tag})
- ✅ Check manifest exists (HEAD request)
- ✅ Pull blob (GET /v2/{repo}/blobs/{digest})
- ✅ Push blob (POST + PUT chunked upload flow)
- ✅ Digest calculation (SHA-256)
- ✅ Docker-Content-Digest header handling
- ✅ List tags (GET /v2/{repo}/tags/list)
- ✅ Catalog repositories (GET /v2/_catalog)

**Pending**:
- ⏳ Chunked blob upload (monolithic POST works, chunking needs implementation)
- ⏳ Pagination (Link header parsing)
- ⏳ Manifest JSON parsing (currently stores raw JSON)
- ⏳ Authentication flow (WWW-Authenticate → token request → retry)

**Cloud Provider Support**:
- ✅ AWS ECR (token-based auth)
- ✅ GCP GCR/Artifact Registry (token-based auth)
- ✅ Azure ACR (token-based auth)
- ✅ Docker Hub (Basic + Bearer auth)
- ✅ GitHub Container Registry (Bearer auth)
- ✅ Self-hosted registries (Basic/Bearer auth)

**Files**: `src/core/ct_registry.{ads,adb}`

### 4. Transparency Logs (CT_Transparency) - 70%

**Implemented**:
- ✅ Rekor API client (Sigstore)
- ✅ Log provider types (Rekor, CT-TLOG, Custom)
- ✅ Upload signature (hashedrekord format)
- ✅ Get entry by UUID
- ✅ Get entry by log index
- ✅ Search by hash
- ✅ JSON request/response handling
- ✅ Entry structure (UUID, signatures, proofs)
- ✅ Signed Entry Timestamp (SET) parsing
- ✅ Inclusion proof parsing

**Pending**:
- ⏳ Merkle inclusion proof verification (parsing done, verification TODO)
- ⏳ SET signature verification (parsing done, verification TODO)
- ⏳ Intoto attestation upload (structure defined, upload TODO)
- ⏳ DSSE envelope upload (structure defined, upload TODO)
- ⏳ Search by public key (API call TODO)
- ⏳ Search by email/identity (API call TODO)
- ⏳ Consistency proof verification (TODO)
- ⏳ Offline bundle verification (TODO)

**Supported Entry Types**:
- ✅ HashedRekord (signature + hash) - **IMPLEMENTED**
- ⏳ Intoto (in-toto attestation) - Pending
- ⏳ DSSE (Dead Simple Signing Envelope) - Pending
- 📋 RFC3161, Alpine, Helm, JAR, RPM, COSE, TUF - Future

**Files**: `src/core/ct_transparency.{ads,adb}`

### 5. JSON Parsing (CT_JSON) - 85%

**Implemented**:
- ✅ JSON string extraction
- ✅ JSON number extraction
- ✅ JSON boolean extraction
- ✅ Nested object navigation
- ✅ JSON builder for creating requests
- ✅ Safe parsing (no crashes on malformed JSON)

**Pending**:
- ⏳ JSON array parsing (partially implemented)
- ⏳ Full JSON schema validation
- ⏳ Pretty-printing for debugging

**Files**: `src/core/ct_json.{ads,adb}`

### 6. Cryptography (Cerro_Crypto) - 60%

**Implemented**:
- ✅ SHA-256 hashing (GNAT.SHA256, tested)
- ✅ SHA-512 hashing (GNAT.SHA512, tested)
- ✅ Hex encoding/decoding
- ✅ Base64 encoding (GNAT.Encode/Decode)
- ✅ Test vectors validated (7/7 pass)

**Pending**:
- ⏳ Ed25519 signing (stub exists, needs implementation)
- ⏳ Ed25519 verification (stub exists, needs implementation)
- ⏳ Ed25519 key generation (stub exists, needs implementation)
- ✅ ML-DSA-87 post-quantum keygen/sign/verify (real, via liboqs; round-trip tested in `ct_test_crypto.adb`, requires `-loqs` linked)
- ⏳ CT-SIG-02 hybrid mode (blocked on Ed25519 keygen/signing above — ML-DSA-87 half alone works)
- ⏳ Constant-time comparison (timing-safe equality)

**Files**: `src/core/cerro_crypto.{ads,adb}`, `src/core/ct_pqcrypto.{ads,adb}`

### 7. URL Utilities (Cerro_URL) - 90%

**Implemented**:
- ✅ URL encoding (RFC 3986)
- ✅ URL decoding
- ✅ URL component parsing
- ✅ Path joining

**Files**: `src/core/cerro_url.{ads,adb}`

---

## ⏳ Partially Implemented Features

### 1. CLI (Cerro_CLI) - 40%

**Commands Implemented**:
- ✅ `ct --help` - Show command list
- ✅ `ct version` - Show version info
- ✅ `ct keygen` - Generate signing key (partial)
- ✅ `ct pack` - Create .ctp bundle (skeleton)
- ✅ `ct verify` - Verify bundle (skeleton)

**Commands Pending**:
- ⏳ `ct fetch` - Pull from registry (wiring needed)
- ⏳ `ct push` - Push to registry (wiring needed)
- ⏳ `ct sign` - Sign bundle (crypto pending)
- ⏳ `ct import` - Import from distro packages
- ⏳ `ct export` - Export to OCI/OSTree
- ⏳ `ct run` - Execute via runtime
- ⏳ `ct policy` - Manage trust policies
- ⏳ `ct log` - Transparency log operations

**Files**: `src/cli/cerro_cli.adb`

### 2. Provenance Tracking (Cerro_Provenance) - 30%

**Implemented**:
- ✅ Provenance data structures
- ✅ Hash calculation stubs
- ✅ Basic signature verification flow

**Pending**:
- ⏳ Full signature verification (Ed25519)
- ⏳ Trust store lookup
- ⏳ Multi-hash algorithm support

**Files**: `src/core/cerro_provenance.{ads,adb}`

### 3. Trust Store (Cerro_Trust_Store) - 40%

**Implemented**:
- ✅ Trust store data structures
- ✅ Add/remove keys
- ✅ List keys
- ✅ Save/load from disk

**Pending**:
- ⏳ Key validation
- ⏳ Expiration checking
- ⏳ Revocation checking
- ⏳ Key hierarchy (root → intermediate → leaf)

**Files**: `src/core/cerro_trust_store.{ads,adb}`

---

## ❌ Not Yet Implemented

### 1. Importers (0%)

**Debian Importer** (`src/importers/debian/`):
- ❌ Parse .dsc files
- ❌ Extract source packages
- ❌ Convert to .ctp format

**Fedora Importer** (`src/importers/fedora/`):
- ❌ Parse SRPMs
- ❌ Extract spec files
- ❌ Convert to .ctp format

**Alpine Importer** (`src/importers/alpine/`):
- ❌ Parse APKBUILD
- ❌ Extract sources
- ❌ Convert to .ctp format

### 2. Exporters (0%)

**OCI Exporter** (`src/exporters/oci/`):
- ❌ Convert .ctp to OCI image layout
- ❌ Generate Dockerfile
- ❌ Export layers

**RPM-OSTree Exporter** (`src/exporters/rpm-ostree/`):
- ❌ Convert to OSTree commits
- ❌ Generate treefile
- ❌ Layering support

### 3. Policy Engine (0%)

**Trust Policies**:
- ❌ Policy definition language
- ❌ Policy evaluation
- ❌ Policy storage
- ❌ Policy updates

### 4. Runtime Integration (0%)

**Svalinn Integration**:
- ❌ Execute via Svalinn gateway
- ❌ Policy enforcement at runtime
- ❌ State tracking

**Vörðr Integration**:
- ❌ Lifecycle management
- ❌ Reversibility support

**Podman/Docker Integration**:
- ❌ OCI runtime hooks
- ❌ Image conversion

---

## 🚧 Known Blockers

### 1. Proven Library Issues (**HIGH PRIORITY**)

**Problem**: The `proven` library (formal verification) has compilation errors:
- Float range errors in `proven-safe_float.adb`
- Purity violations in `proven-safe_datetime.ads`
- Type mismatches in several modules

**Impact**:
- Cannot use formally verified URL parsing
- Cannot use formally verified digest verification
- SPARK proofs disabled

**Workaround**: Fallback implementations used (not formally verified)

**Resolution Path**:
1. Fix proven library compilation errors, OR
2. Create local SPARK-verified alternatives, OR
3. Accept non-verified implementations for MVP

### 2. Ed25519 Cryptography (**MEDIUM PRIORITY**)

**Problem**: No Ed25519 implementation linked yet.

**Options**:
1. Use libsodium (FFI bindings needed)
2. Use GNAT.Crypto (if available)
3. Implement in Ada (complex, time-consuming)
4. Use external `openssl` command (MVP workaround)

**Impact**:
- `ct sign` and `ct verify` commands non-functional
- Transparency log submissions incomplete (can upload hash, but not signature)

### 3. JSON Manifest Parsing (**LOW PRIORITY**)

**Problem**: OCI manifest JSON not fully parsed into structured types.

**Current**: Manifests stored as raw JSON strings.

**Impact**: Limited - raw JSON works for push/pull, just less type-safe.

---

## 📊 Implementation Metrics

### Code Statistics

| Metric | Value |
|--------|-------|
| **Total Lines of Code** | ~15,000 |
| **Ada Source Files** | 45 |
| **Test Files** | 4 |
| **Documentation Files** | 8 |
| **Executables** | 4 |

### Test Coverage

| Test Suite | Status | Pass Rate |
|------------|--------|-----------|
| **Crypto Tests** | ⚠ Cannot run — project does not build | unknown |
| **Parser Tests** | ✅ Ready | N/A (manual use) |
| **E2E Tests** | ✅ Passing | 40/41 (97.6%) |
| **Manual Tests** | 🔄 Script created | Pending execution |

### Build Health

| Check | Status |
|-------|--------|
| Compilation | ✅ Clean |
| Style Warnings | ⚠️ Minor (array syntax, unused vars) |
| Runtime Errors | ❌ None detected |
| Memory Leaks | ❓ Not tested yet |

---

## 🎯 MVP Roadmap

### Phase 1: Core Operations (Current - Week 1) ✅

- [x] Build system working
- [x] HTTP client operational
- [x] Registry client (push/pull)
- [x] Transparency log client (submit/get)
- [x] Basic crypto (hashing)
- [x] Integration tests passing

### Phase 2: CLI Wiring (Week 2) ⏳

- [ ] Wire `ct fetch` to Pull_Manifest
- [ ] Wire `ct push` to Push_Manifest
- [ ] Test with real registries (ghcr.io, Docker Hub)
- [ ] Manual end-to-end flow validation

### Phase 3: Signatures (Week 3) ⏳

- [ ] Implement Ed25519 signing (or external openssl workaround)
- [ ] Wire `ct sign` command
- [ ] Wire `ct verify` command
- [ ] Submit signed attestations to Rekor
- [ ] Verify Merkle inclusion proofs

### Phase 4: Trust & Policy (Week 4) 📋

- [ ] Trust store fully functional
- [ ] Policy definition language
- [ ] Policy evaluation engine
- [ ] CLI policy management

### Phase 5: Importers (Month 2) 📋

- [ ] Debian importer
- [ ] Basic .dsc parsing
- [ ] Create .ctp from Debian packages

### Phase 6: Production Hardening (Month 3) 📋

- [ ] Error handling improvements
- [ ] Performance optimization
- [ ] Security audit
- [ ] Documentation completion

---

## 🔧 Development Environment

### Prerequisites Installed

- ✅ GNAT 14 (Ada 2022 compiler)
- ✅ Alire 2.0 (package manager)
- ✅ curl (HTTP operations via GNAT.OS_Lib)
- ✅ Docker/Podman (for registry testing)

### Build Commands

```bash
# Clean build
alr build

# Run tests
./bin/ct-test-crypto
./bin/ct-test-e2e

# Manual E2E test (requires Docker)
./tests/manual-e2e-test.sh

# CLI usage
./bin/ct --help
```

---

## 📝 Next Actions (Priority Order)

### Immediate (This Session)

1. ✅ Document implementation status (this file)
2. ⏳ Run manual E2E test script
3. ⏳ Fix localhost port parsing (minor failing test)
4. ⏳ Wire CLI fetch/push commands

### Short-Term (This Week)

5. Implement Ed25519 signing (or openssl wrapper)
6. Test with real registries (ghcr.io)
7. Submit attestation to Rekor (test transparency logs)
8. Document working examples

### Medium-Term (This Month)

9. Fix or replace proven library
10. Implement Merkle proof verification
11. Complete policy engine
12. First Debian package import

---

## 🎓 Lessons Learned

### What Worked Well

- ✅ Modular architecture (CT_HTTP, CT_Registry, CT_Transparency separate)
- ✅ Type-safe auth conversion (Registry → HTTP)
- ✅ Comprehensive security defaults (TLS, DANE, ECH, DoH)
- ✅ Test-driven development (E2E tests written early)
- ✅ Clear separation of concerns (core vs CLI vs importers)

### Challenges Encountered

- ⚠️ External dependency issues (proven library compilation)
- ⚠️ Ada reserved words (Body, Entry) requiring renames
- ⚠️ Type system complexity (multiple auth credential types)
- ⚠️ Limited Ada crypto libraries (need FFI bindings)

### Improvements for Next Phase

- 📌 Mock external dependencies for testing
- 📌 Add more integration tests with live services
- 📌 Create developer documentation
- 📌 Set up continuous integration (GitHub Actions)

---

## 📚 Reference Documentation

### Specifications Implemented

- ✅ OCI Distribution Specification v2
- ✅ OCI Image Manifest Specification v1
- ⏳ Sigstore Bundle Specification (partial)
- ⏳ In-Toto Attestation Framework (partial)
- 📋 SLSA Provenance (planned)

### Standards Compliance

- ✅ RFC 3986 (URI Generic Syntax) - URL encoding
- ✅ RFC 7519 (JWT) - Token parsing
- ✅ RFC 9230 (ODoH) - Oblivious DNS-over-HTTPS
- ⏳ RFC 6962 (Certificate Transparency) - Merkle trees
- ⏳ RFC 3161 (Timestamping) - Trusted timestamps

---

## 🏆 Current Status: **READY FOR CLI WIRING & LIVE TESTING**

The foundation is solid. Core network operations are implemented and tested. Next step is to wire the CLI commands to the working backend operations and test with live registries and transparency logs.

**Recommendation**: Proceed with Phase 2 (CLI Wiring) and validate against real services.

---

**Document Version**: 1.0
**Generated**: 2026-01-25
**Maintainer**: Cerro Torre Development Team
