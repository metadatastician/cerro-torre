<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
## Machine-Readable Artefacts

The following files in `.machine_readable/` contain structured project metadata:

- `STATE.scm` - Current project state and progress
- `META.scm` - Architecture decisions and development practices
- `ECOSYSTEM.scm` - Position in the ecosystem and related projects
- `AGENTIC.scm` - AI agent interaction patterns
- `NEUROSYM.scm` - Neurosymbolic integration config
- `PLAYBOOK.scm` - Operational runbook

---

# CLAUDE.md - AI Assistant Instructions

## Language Policy (Hyperpolymath Standard)

> **2026 migration: ReScript retired → two successor languages, by role.**
> **AffineScript** is the primary *general application* language (affine-typed,
> compiled to typed-wasm via the OCaml AffineScript compiler) — it replaces
> ReScript for gateway / UI / app code. **Ephapax** owns the *linear security
> core*: exactly-once tokens, revocation ledgers, secret/handle lifecycle,
> container-lifecycle invariants, and zero-copy IPC (see `ephapax-modules/`,
> `container-stack/selur/`). The two are complementary, not competing — reach
> for AffineScript for general logic, Ephapax where linearity *is* the guarantee.
> ReScript is deprecated estate-wide (the governance banned-language gate
> enforces "use AffineScript instead"); existing `.res` are grandfathered via
> `.hypatia-baseline.json` — do not add new `.res`.

### ALLOWED Languages & Tools

| Language/Tool | Use Case | Notes |
|---------------|----------|-------|
| **AffineScript** | Primary *general* application code | Affine-typed; compiled to typed-wasm via the OCaml AffineScript compiler. Replaces ReScript for gateway/UI/app logic. |
| **Ephapax** | *Linear security core* | Linear/affine types: exactly-once tokens, revocation, secret/handle lifecycle, container-lifecycle invariants, zero-copy IPC. See `ephapax-modules/`, `container-stack/selur/`. Complements AffineScript — not a general app language. |
| **Bun** | JS/TS runtime & package management (tier 1) | Default for all new work. Executes `.ts` directly, no build step. Uses an npm-compatible `package.json` plus `bun.lock` — both are expected, not anti-patterns. |
| **Rust** | Performance-critical, systems, WASM | Preferred for CLI tools |
| **Tauri 2.0+** | Mobile apps (iOS/Android) | Rust backend + web UI |
| **Dioxus** | Mobile apps (native UI) | Pure Rust, React-like |
| **Gleam** | Backend services | Runs on BEAM or compiles to JS |
| **Bash/POSIX Shell** | Scripts, automation | Keep minimal |
| **JavaScript** | Only where AffineScript cannot | MCP protocol glue, Bun APIs |
| **Nickel** | Configuration language | For complex configs |
| **Guile Scheme** | State/meta files | STATE.scm, META.scm, ECOSYSTEM.scm |
| **Julia** | Batch scripts, data processing | Per RSR |
| **OCaml** | AffineScript compiler | Language-specific |
| **Ada** | Safety-critical systems | Where required |

### BANNED - Do Not Use

| Banned | Replacement |
|--------|-------------|
| TypeScript | AffineScript |
| ReScript | AffineScript — no new .res; existing .res grandfathered in .hypatia-baseline.json pending migration |
| Node.js | Bun |
| npm | Bun |
| pnpm/yarn | Bun |
| Go | Rust |
| Python | Julia/Rust/AffineScript |
| Java/Kotlin | Rust/Tauri/Dioxus |
| Swift | Tauri/Dioxus |
| React Native | Tauri/Dioxus |
| Flutter/Dart | Tauri/Dioxus |

### Mobile Development

**No exceptions for Kotlin/Swift** - use Rust-first approach:

1. **Tauri 2.0+** - Web UI (AffineScript) + Rust backend, MIT/Apache-2.0
2. **Dioxus** - Pure Rust native UI, MIT/Apache-2.0

Both are FOSS with independent governance (no Big Tech).

### Enforcement Rules

1. **No new TypeScript files** - Convert existing TS/ReScript to AffineScript
2. **Use `package.json` + `bun.lock` for JS runtime deps** - Bun is npm-compatible; a manifest is REQUIRED
3. **`bun install --production` for production deps** - resolved from `package.json`, pinned via `bun.lock`
4. **No Go code** - Use Rust instead
5. **No Python anywhere** - Use Julia for data/batch, Rust for systems, AffineScript for apps
6. **No Kotlin/Swift for mobile** - Use Tauri 2.0+ or Dioxus

### Package Management

- **Primary**: Guix (guix.scm)
- **Fallback**: Nix (flake.nix)
- **JS deps**: Bun (`package.json` + `bun.lock`); `bunx <tool>` for one-off tooling

### Security Requirements

- No MD5/SHA1 for security (use SHA256+)
- HTTPS only (no HTTP URLs)
- No hardcoded secrets
- SHA-pinned dependencies
- SPDX license headers on all files

