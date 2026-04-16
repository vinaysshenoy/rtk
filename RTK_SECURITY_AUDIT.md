# RTK Security Audit: Hidden Behavior & External Communication

## Executive Summary

RTK (Rust Token Killer) is a CLI proxy that filters and compresses command outputs to reduce LLM token consumption. This audit examines the codebase for hidden behavior, external data transmission, and security concerns.

**Key findings:**
- One outbound network path (optional telemetry, compile-time gated, now opt-in with GDPR consent)
- Reads Claude Code session history files locally
- Logs all commands to local SQLite database for 90 days
- Installs preToolUse hooks that intercept commands across 6 AI coding agents
- Two security fixes in v0.36.0 (compound command bypass, default verdict escalation)
- No backdoors, obfuscated code, or credential exfiltration found

---

## Changelog

| Version | Date | Auditor | Notes |
|---------|------|---------|-------|
| v0.35.0 | 2026-04-07 | Initial audit | Baseline (commit 8a7106c) |
| v0.36.0 | 2026-04-16 | Re-audit | Privacy improvements, GDPR compliance, security fixes (commit a699357) |

---

## 1. Telemetry — The Single Network Path

**File:** `src/core/telemetry.rs`, `src/core/telemetry_cmd.rs`

RTK has **two outbound network calls** via the `ureq` crate (the only network dependency in the project):

1. **Daily telemetry ping** — sends a JSON payload every ~23 hours to a URL baked in at **compile time** via `option_env!("RTK_TELEMETRY_URL")`.
2. **GDPR erasure request** *(new in v0.36.0)* — POST to `{RTK_TELEMETRY_URL}/erasure` when user runs `rtk telemetry forget`.

### Data Transmitted

```json
{
  "device_hash": "sha256(random_salt)",
  "version": "0.36.0",
  "os": "darwin",
  "arch": "aarch64",
  "install_method": "homebrew|cargo|script|nix|other",
  "commands_24h": 42,
  "top_commands": ["git", "cargo", "ls"],
  "savings_pct": 73.5,
  "tokens_saved_24h": 15000,
  "tokens_saved_total": 450000,
  "passthrough_top": [...],
  "parse_failures_24h": 2,
  "low_savings_commands": [...],
  "avg_savings_per_command": 1200,
  "hook_type": "claude",
  "custom_toml_filters": 3,
  "first_seen_days": 45,
  "active_days_30d": 22,
  "commands_total": 5000,
  "ecosystem_mix": { "git": 40.0, "rust": 25.0, ... },
  "tokens_saved_30d": 900000,
  "estimated_savings_usd_30d": 2.70,
  "has_config_toml": true,
  "exclude_commands_count": 2,
  "projects_count": 5,
  "meta_usage": { "gain": 15, "discover": 3, ... }
}
```

> **v0.36.0 change:** Payload enriched with quality, adoption, retention, ecosystem, economics, configuration, and feature usage metrics. All fields are aggregate — no PII, no command arguments, no file paths, no output content.

### Device Hash — Privacy Improvement (v0.36.0)

| Version | Hash Input | Risk |
|---------|-----------|------|
| v0.35.0 | `sha256(random_salt:hostname:username)` | Hostname/username baked into hash — stable fingerprint with PII |
| v0.36.0 | `sha256(random_salt)` | Random salt only — stored at `~/.local/share/rtk/.device_salt` (mode 0600) |

The v0.36.0 device hash is truly anonymous. Hostname and username are no longer used in its construction.

### Opt-Out Mechanisms (Triple Layer + Consent Gate)

| Level | Mechanism | Effect |
|-------|-----------|--------|
| Compile-time | `RTK_TELEMETRY_URL` not set during build | Dead code — no network path exists in binary |
| Runtime env var | `RTK_TELEMETRY_DISABLED=1` | Skips telemetry at runtime |
| Config file | `~/.config/rtk/config.toml` → `[telemetry] enabled = false` | Skips telemetry at runtime |
| **Consent gate** *(new in v0.36.0)* | `consent_given` must be explicitly `true` | **Opt-in by default** — telemetry does not send unless user runs `rtk telemetry enable` |

### GDPR Compliance (new in v0.36.0)

| Command | Purpose |
|---------|---------|
| `rtk telemetry status` | Show consent state, device hash |
| `rtk telemetry enable` | Interactive opt-in (terminal-only, cannot be piped) |
| `rtk telemetry disable` | Immediate opt-out |
| `rtk telemetry forget` | Full erasure: deletes local salt, ping marker, tracking DB, and sends server-side erasure request |

Server-side retention: 12 months with automatic purge. Erasure audit log IP addresses anonymized after 6 months.

### Risk Assessment

- If `RTK_TELEMETRY_URL` is not set at build time, **no network code activates**. Binaries built from source without this env var have inert telemetry.
- The `device_hash` is now a one-way SHA-256 hash of a random salt only. No PII is included.
- The `top_commands` field leaks which tools you use (e.g., "git", "cargo", "aws") but **not** arguments, file paths, or output.
- No command arguments, file contents, secrets, or output are transmitted.
- Fire-and-forget on a background thread with a 2-second timeout. Errors are silently ignored.
- Optional `X-RTK-Token` header for authentication (compile-time injected via `RTK_TELEMETRY_TOKEN`).

### Verification

```bash
# Check if your binary has a telemetry URL compiled in:
strings $(which rtk) | grep -i "http"

# If no URL appears, telemetry is completely inert.

# Check consent status:
rtk telemetry status
```

---

## 2. Claude Code Session History Reading

**File:** `src/discover/provider.rs`

**This is the most noteworthy finding from a privacy perspective.**

RTK's `discover` and `learn` modules **read all Claude Code session JSONL files** from `~/.claude/projects/*/`. This includes:

- **Every Bash command** Claude Code executed in your sessions
- **First 1,000 characters of each command's output** (for error detection only)
- Error status of each command
- Session IDs and timestamps
- Recursively walks into `subagents/` directories

### How It Works

```
~/.claude/projects/
  ├── -Users-vinay-Dev-myapp/
  │   ├── abc123.jsonl          <- RTK reads these
  │   ├── def456.jsonl
  │   └── subagents/
  │       └── ghi789.jsonl      <- And these
  └── -Users-vinay-Dev-rtk/
      └── ...
```

RTK parses each JSONL file, extracting `tool_use` blocks where `name == "Bash"` and correlating them with their `tool_result` blocks to get output content.

### What Uses This Data

| Command | Purpose | Data Accessed |
|---------|---------|---------------|
| `rtk discover` | Adoption analytics — which commands could benefit from RTK | Commands + output length |
| `rtk learn` | CLI correction detection — finds repeated failures | Commands + first 1000 chars of output |
| `rtk gain --history` | Session-level savings reporting | Command names only |

### Data Persistence

| Destination | When | Content |
|-------------|------|---------|
| stdout | Always | Aggregated reports only (no raw commands/output) |
| `.claude/rules/cli-corrections.md` | Only with `rtk learn --write-rules` | Aggregated correction patterns + first 500 chars of example errors |
| Network | Never | Session data is never transmitted |

### Risk Assessment

- This data is **not sent over the network** — all processing is local.
- However, RTK has read access to your full AI coding session history, which may contain sensitive command output (API keys printed to stdout, database query results, etc.).
- The 1,000-character output preview in `ExtractedCommand.output_content` is held in memory during analysis, not persisted to disk (except the 500-char examples in `--write-rules` output).
- The `--write-rules` output file could contain sensitive paths or error messages from sessions.

---

## 3. Local Command Tracking Database

**File:** `src/core/tracking.rs`

Every command routed through RTK is logged to a local SQLite database.

### Database Location

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/rtk/history.db` |
| Linux | `~/.local/share/rtk/history.db` |
| Windows | `%APPDATA%\rtk\history.db` |

> **v0.36.0 change:** Database filename is now `history.db` (was `tracking.db` in v0.35.0).

### Schema

```sql
CREATE TABLE commands (
    id              INTEGER PRIMARY KEY,
    timestamp       TEXT NOT NULL,       -- UTC RFC3339 timestamp
    original_cmd    TEXT NOT NULL,       -- e.g., "git log --oneline -50"
    rtk_cmd         TEXT NOT NULL,       -- e.g., "rtk git log"
    project_path    TEXT DEFAULT '',     -- Current working directory (new in v0.36.0)
    input_tokens    INTEGER NOT NULL,
    output_tokens   INTEGER NOT NULL,
    saved_tokens    INTEGER NOT NULL,
    savings_pct     REAL NOT NULL,
    exec_time_ms    INTEGER DEFAULT 0
);

CREATE INDEX idx_timestamp ON commands(timestamp);
CREATE INDEX idx_project_path_timestamp ON commands(project_path, timestamp);  -- new in v0.36.0

CREATE TABLE parse_failures (
    id                  INTEGER PRIMARY KEY,
    timestamp           TEXT NOT NULL,
    raw_command         TEXT NOT NULL,
    error_message       TEXT NOT NULL,
    fallback_succeeded  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_pf_timestamp ON parse_failures(timestamp);
```

> **v0.36.0 changes:**
> - New `project_path` column captures current working directory for every command
> - New `idx_project_path_timestamp` index for project-scoped queries
> - Uses GLOB pattern matching (not LIKE) for safe path filtering that correctly handles underscores and percent signs

### Risk Assessment

- **Full command text** is stored, including arguments (file paths, branch names, etc.)
- **Working directory** is captured for every command execution
- Data is retained for **90 days** before automatic cleanup
- The database is purely local — never synced or transmitted
- Treat `history.db` as sensitive; it contains a detailed development activity log
- The `rtk telemetry forget` command now deletes the entire tracking database as part of GDPR erasure

---

## 4. Hook System — Command Interception

**Files:** `src/hooks/init.rs`, `src/hooks/rewrite_cmd.rs`, `src/hooks/hook_cmd.rs`, `src/hooks/permissions.rs`

`rtk init` installs **preToolUse hooks** into AI coding agents that intercept Bash commands and rewrite them to route through RTK.

### Supported Agents (expanded in v0.36.0)

| Agent | Hook File | Format |
|-------|-----------|--------|
| Claude Code | `~/.claude/hooks/rtk-rewrite.sh` | Shell script |
| Cursor | `~/.cursor/hooks/rtk-rewrite.sh` | Shell script |
| Gemini CLI | `~/.gemini/hooks/rtk-hook-gemini.sh` | Shell script |
| OpenCode | `~/.config/opencode/plugins/rtk.ts` | TypeScript |
| Codex | `~/.codex/rtk-awareness.md` | Markdown instructions |
| Windsurf/Cline | Rules files | Markdown instructions |

> **v0.35.0** supported only Claude Code. **v0.36.0** supports 6 agents.

### Command Rewrite Flow

```
AI agent wants to run: git log --oneline -20
         |
preToolUse hook fires -> rtk-rewrite.sh
         |
Delegates to: rtk rewrite "git log --oneline -20"
         |
Permission check (deny/ask/allow rules)
         |
Exit code determines action:
  0 + stdout -> Rewrite accepted (e.g., "rtk git log --oneline -20")
  1          -> No RTK equivalent, pass through unchanged
  2          -> Deny rule matched, block command
  3 + stdout -> Rewrite, but prompt user for approval
```

### Security Features

| Feature | Detail |
|---------|--------|
| SHA-256 integrity | Hook file is hashed; tampering detected at runtime (`src/hooks/integrity.rs`) |
| No shell interpretation | Uses `Command::new()` with `.arg()`, never `sh -c` |
| Heredoc exclusion | Commands containing `<<` excluded from rewriting to prevent injection |
| Atomic writes | Uses `tempfile::NamedTempFile` for hook installation |
| Permission precedence | Deny > Ask > Allow > Default(ask) — least privilege |
| No shell config modification | Does **not** touch `.bashrc`, `.zshrc`, `.profile` |
| **Compound command fix** *(v0.36.0, issue #1213)* | All segments of `&&`/`||` chains must match Allow rule; previously one match escalated entire chain |
| **Default verdict fix** *(v0.36.0, issue #1155)* | Unrecognized commands default to exit code 3 (ask), not 0 (allow) |

### Hook Audit Logging (new in v0.36.0)

**File:** `src/hooks/hook_audit_cmd.rs`

All hook rewrite decisions are logged to `~/.local/share/rtk/hook-audit.log`:

```
timestamp | action | original_cmd | rewritten_cmd
```

Actions: `rewrite`, `skip:no_match`, `skip:already_rtk`, etc.

View with `rtk hook-audit` (shows stats, top rewritten commands, skip breakdown).

### Hook Integrity Verification

**File:** `src/hooks/integrity.rs`

- SHA-256 hash stored in `.rtk-hook.sha256` (read-only, 0444 permissions)
- Verification statuses: `Verified`, `Tampered`, `NoBaseline`, `NotInstalled`, `OrphanedHash`
- Tampering triggers exit code 1 with warning
- Hook version tracking (current version: 3) with 24-hour warning rate limiting

---

## 5. Project-Local Filter Trust System

**File:** `src/hooks/trust.rs`

RTK supports project-local filter files (`.rtk/filters.toml`) that could theoretically be used to manipulate command output. The trust system prevents this:

- **Trust-before-load**: Untrusted filters are skipped entirely, not loaded with a warning
- **Content-change detection**: SHA-256 hash of filter file; if content changes, trust is invalidated
- **CI override protection**: `RTK_TRUST_PROJECT_FILTERS=1` only works when CI env vars are also present (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `BUILDKITE`). Rejects the override if no CI indicator is detected — prevents `.envrc` injection.
- **Risk warnings**: Alerts user about `replace` rules, `match_output` rules, and catch-all patterns
- **Trust store**: `~/.local/share/rtk/trusted_filters.json`

---

## 6. Sensitive Data Handling

### Environment Variable Masking

**File:** `src/cmds/system/env_cmd.rs`

`rtk env` masks values matching these patterns:

```
key, secret, password, token, credential, auth,
private, api_key, apikey, access_key, jwt
```

Masking shows first 2 + `****` + last 2 characters (e.g., `supersecrettoken` -> `su****en`). Short values show `****`.

### Build Log Secret Redaction

**File:** `src/cmds/dotnet/binlog.rs`

RTK redacts 33+ sensitive environment variables from .NET build logs:

```
SSH_AUTH_SOCK, GH_TOKEN, GITHUB_TOKEN, GITHUB_PAT,
NUGET_API_KEY, NUGET_AUTH_TOKEN, AZURE_CLIENT_SECRET,
AZURE_DEVOPS_TOKEN, AZURE_TENANT_ID, AZURE_CLIENT_ID,
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
API_TOKEN, AUTH_TOKEN, ACCESS_TOKEN, BEARER_TOKEN, PASSWORD,
CONNECTION_STRING, DATABASE_URL, DOCKER_CONFIG, KUBECONFIG, ...
```

Redaction replaces values with `[REDACTED]` before output.

---

## 7. Unsafe Code

**v0.36.0: Zero `unsafe` blocks found in the entire Rust codebase.**

> **v0.35.0** had a single `unsafe` block in `src/main.rs` (lines 2008-2011) for SIGINT/SIGTERM signal handling via `libc::signal`. This has been removed or refactored in v0.36.0.

---

## 8. Dependencies — Network Surface

| Dependency | Purpose | Network? |
|------------|---------|----------|
| `ureq` | HTTP client | Yes — telemetry only |
| `rusqlite` | SQLite (bundled, compiled from C source) | No |
| `serde_json` | JSON parsing | No |
| `regex` | Pattern matching | No |
| `clap` | CLI argument parsing | No |
| `walkdir` | Directory traversal | No |
| `sha2` | SHA-256 hashing | No |
| `getrandom` | Cryptographic randomness | No |
| `dirs` | User directory lookup | No |
| `chrono` | Date/time handling | No |
| `flate2` | Gzip compression | No |
| `quick-xml` | XML parsing | No |
| `which` | Binary resolution | No |
| `libc` | Unix system calls (conditional) | No |

No `reqwest`, `hyper`, `tokio`, `async-std`, or other async/networking crates. 79 transitive dependencies total.

> **v0.36.0 change:** No new network-capable dependencies added since v0.35.0.

---

## 9. Environment Variables

### RTK-Specific

| Variable | Purpose | Security Note |
|----------|---------|---------------|
| `RTK_TELEMETRY_DISABLED=1` | Disable telemetry | Opt-out mechanism |
| `RTK_DISABLED` | Disable command rewriting entirely | New in v0.36.0 |
| `RTK_TRUST_PROJECT_FILTERS=1` | Auto-trust project filters | CI-only (requires CI env vars) |
| `RTK_NO_TOML=1` | Bypass TOML filter engine | Debug/escape hatch |
| `RTK_DB_PATH` | Override tracking database location | Could redirect logging |
| `RTK_TEE_DIR` | Override tee output directory | Changes where raw output is saved |
| `RTK_TOML_DEBUG` | Print TOML filter debug info | Exposes filter matching internals |
| `RTK_AUDIT_DIR` | Override hook audit directory | Changes audit log location |

### Compile-Time Variables

| Variable | Purpose |
|----------|---------|
| `RTK_TELEMETRY_URL` | Telemetry endpoint (optional) |
| `RTK_TELEMETRY_TOKEN` | Telemetry auth token (optional) |

### System Variables Read

| Variable | Purpose |
|----------|---------|
| `HOME` | Locate config/data directories |
| `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `BUILDKITE` | CI environment detection for trust system |

> **v0.36.0 change:** `USER`/`USERNAME` are **no longer read** for device hash generation (privacy improvement).

---

## 10. Summary Table

| Vector | v0.35.0 | v0.36.0 | Detail |
|--------|---------|---------|--------|
| **Outbound network** | 1 endpoint (opt-out) | 1 endpoint + erasure (opt-in) | GDPR consent gate added; telemetry now opt-in by default |
| **Device hash PII** | hostname + username | random salt only | **Fixed** — no PII in telemetry payload |
| **Session history reading** | Yes | Yes | Reads all Claude Code `.jsonl` files locally (unchanged) |
| **Command logging** | 7 columns | 8 columns (+project_path) | Full command + CWD stored in local SQLite for 90 days |
| **Hook installation** | 1 agent (Claude Code) | 6 agents | Rewrites commands across Claude, Cursor, Gemini, OpenCode, Codex, Windsurf |
| **Compound cmd security** | Vulnerable (issue #1213) | **Fixed** | All segments must match Allow; one match no longer escalates chain |
| **Default verdict** | Exit 0 (allow) | **Exit 3 (ask)** | Unrecognized commands no longer auto-allowed (issue #1155) |
| **Credential exfiltration** | No | No | Env vars masked, secrets redacted in dotnet/AWS output |
| **Backdoors** | None found | None found | No eval, no hidden endpoints, no obfuscated code |
| **Shell config modification** | No | No | Uses AI agent native hook systems only |
| **Unsafe code** | Minimal (2 lines) | **None** | Signal handler unsafe block removed |
| **Async / background tasks** | 1 thread | 1 thread | Telemetry fire-and-forget only |
| **Shell injection surface** | Clean | Clean | Zero `sh -c` / `bash -c` / `cmd /c` usage; all safe `Command::new().arg()` |

---

## 11. Recommendations

1. **Verify telemetry status in your binary:**
   ```bash
   strings $(which rtk) | grep -i "http"
   ```
   If no URL appears, telemetry is completely inert.

2. **Check consent status:**
   ```bash
   rtk telemetry status
   ```
   Telemetry is opt-in by default in v0.36.0. No data is sent without explicit consent.

3. **Be aware that `rtk discover` and `rtk learn` can read your full Claude Code session history**, including 1,000-character output snippets. If sessions contain sensitive data, consider filesystem permissions on `~/.claude/projects/`.

4. **Treat `history.db` as sensitive.** It contains 90 days of command history with full arguments and working directories. Located at:
   - macOS: `~/Library/Application Support/rtk/history.db`
   - Linux: `~/.local/share/rtk/history.db`

5. **Review project-local filters** (`.rtk/filters.toml`) in repositories you clone. The trust system provides protection, but understand that `replace` rules can alter command output shown to AI agents.

6. **Audit the installed hooks** periodically:
   ```bash
   rtk verify          # Checks SHA-256 integrity
   rtk hook-audit      # View rewrite decision history
   ```

7. **Exercise GDPR rights** if desired:
   ```bash
   rtk telemetry forget  # Full local + server-side data erasure
   ```

8. **Update from v0.35.0** to get the two security fixes (compound command bypass, default verdict escalation) and the device hash privacy improvement.

---

## 12. Bundled Binaries & Hidden Libraries

**Zero binary artifacts found** in the repository. No `.so`, `.dylib`, `.dll`, `.a`, `.o`, `.exe`, `.wasm`, `.jar`, `.zip`, `.tar.gz`, or image files exist anywhere in the source tree.

### Files Embedded into the RTK Binary

All via `include_str!()` (text only — no `include_bytes!()` used anywhere):

| Embedded File | Purpose | Auditable? |
|---|---|---|
| `hooks/claude/rtk-rewrite.sh` | Claude Code hook script | Yes, shell script |
| `hooks/cursor/rtk-rewrite.sh` | Cursor hook script | Yes, shell script |
| `hooks/opencode/rtk.ts` | OpenCode plugin | Yes, TypeScript |
| `hooks/claude/rtk-awareness.md` | Agent instructions | Yes, markdown |
| `hooks/codex/rtk-awareness.md` | Codex instructions | Yes, markdown |
| `hooks/windsurf/rules.md` | Windsurf rules | Yes, markdown |
| `hooks/cline/rules.md` | Cline rules | Yes, markdown |
| `$OUT_DIR/builtin_filters.toml` | Combined TOML filters | Yes, generated from `src/filters/*.toml` by `build.rs` |

### Build-Time Code Generation

**`build.rs`** concatenates all `src/filters/*.toml` files into a single `builtin_filters.toml`, validates it parses correctly, and checks for duplicate filter names. Also sets Windows stack size to 8MB. No downloads, no native compilation, no external code generation.

**Build dependencies:** Only `toml = "0.8"` (a TOML parser for the validation step).

### Native Code Compiled from Source

**`rusqlite` with `"bundled"` feature** — this compiles SQLite from C source at build time (vendored inside the `rusqlite` crate from crates.io). This is standard practice and the C source is auditable within the crate. No pre-compiled SQLite binary is shipped in this repository.

### FFI Surface

`libc` crate used conditionally (`cfg(unix)`) by `which`, `getrandom`, and platform-specific code. No direct `extern "C"` functions in the RTK source code (removed in v0.36.0).

### Additional Checks

| Check | Result |
|-------|--------|
| Git submodules | None — no external repos pulled in |
| `.cargo/config.toml` | Does not exist — no custom linker flags or native library paths |
| Procedural macros | `automod` for module auto-discovery; no custom proc macros |
| Vendored C/C++ code | None in this repo (SQLite is vendored inside `rusqlite` crate) |
| `include_bytes!()` | Not used anywhere — no binary data embedded |
| Pre-compiled binaries | None found in any directory |
| Archive files | None found (`.tar`, `.gz`, `.zip`, etc.) |
| Image files | None found (`.png`, `.jpg`, `.gif`, `.ico`, etc.) |

**Verdict:** The entire RTK binary is built from auditable source code. All embedded content is plain text. The only native C code involved (SQLite) is compiled from source via a well-known crates.io dependency.

---

*Initial audit performed on 2026-04-07 against RTK v0.35.0 (commit 8a7106c).*
*Updated on 2026-04-16 against RTK v0.36.0 (commit a699357).*
