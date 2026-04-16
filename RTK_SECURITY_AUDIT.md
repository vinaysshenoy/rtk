# RTK Security Audit: Hidden Behavior & External Communication

## Executive Summary

RTK (Rust Token Killer) is a CLI proxy that filters and compresses command outputs to reduce LLM token consumption. This audit examines the codebase for hidden behavior, external data transmission, and security concerns.

**Key findings:**
- One outbound network path (optional telemetry, compile-time gated)
- Reads Claude Code session history files locally
- Logs all commands to local SQLite database for 90 days
- Installs a preToolUse hook that intercepts Claude Code commands
- No backdoors, obfuscated code, or credential exfiltration found

---

## 1. Telemetry — The Single Network Path

**File:** `src/core/telemetry.rs`

RTK has **one outbound network call** via the `ureq` crate (the only network dependency in the project). It sends a JSON payload every ~23 hours to a URL baked in at **compile time** via `option_env!("RTK_TELEMETRY_URL")`.

### Data Transmitted

```json
{
  "device_hash": "sha256(random_salt:hostname:username)",
  "version": "0.35.0",
  "os": "darwin",
  "arch": "aarch64",
  "install_method": "homebrew|cargo|script|nix|other",
  "commands_24h": 42,
  "top_commands": ["git", "cargo", "ls"],
  "savings_pct": 73.5,
  "tokens_saved_24h": 15000,
  "tokens_saved_total": 450000
}
```

### Opt-Out Mechanisms (Triple Layer)

| Level | Mechanism | Effect |
|-------|-----------|--------|
| Compile-time | `RTK_TELEMETRY_URL` not set during build | Dead code — no network path exists in binary |
| Runtime env var | `RTK_TELEMETRY_DISABLED=1` | Skips telemetry at runtime |
| Config file | `~/.config/rtk/config.toml` → `[telemetry] enabled = false` | Skips telemetry at runtime |

### Risk Assessment

- If `RTK_TELEMETRY_URL` is not set at build time, **no network code activates** (line 21). Binaries built from source without this env var have inert telemetry.
- The `device_hash` is a one-way SHA-256 hash. Hostname and username cannot be recovered from it, but it is **stable across runs**, enabling device tracking over time.
- The `top_commands` field leaks which tools you use (e.g., "git", "cargo", "aws") but **not** arguments, file paths, or output.
- No command arguments, file contents, secrets, or output are transmitted.
- Fire-and-forget on a background thread with a 2-second timeout. Errors are silently ignored.

### Verification

```bash
# Check if your binary has a telemetry URL compiled in:
strings $(which rtk) | grep -i "http"

# If no URL appears, telemetry is completely inert.
```

---

## 2. Claude Code Session History Reading

**File:** `src/discover/provider.rs`

**This is the most noteworthy finding from a privacy perspective.**

RTK's `discover` and `learn` modules **read all Claude Code session JSONL files** from `~/.claude/projects/*/`. This includes:

- **Every Bash command** Claude Code executed in your sessions
- **First 1,000 characters of each command's output** (line 208–209)
- Error status of each command
- Session IDs and timestamps
- Recursively walks into `subagents/` directories (line 98–99)

### How It Works

```
~/.claude/projects/
  ├── -Users-vinay-Dev-myapp/
  │   ├── abc123.jsonl          ← RTK reads these
  │   ├── def456.jsonl
  │   └── subagents/
  │       └── ghi789.jsonl      ← And these
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

### Risk Assessment

- This data is **not sent over the network** — all processing is local.
- However, RTK has read access to your full AI coding session history, which may contain sensitive command output (API keys printed to stdout, database query results, etc.).
- The 1,000-character output preview in `ExtractedCommand.output_content` is held in memory during analysis, not persisted to disk.

---

## 3. Local Command Tracking Database

**File:** `src/core/tracking.rs`

Every command routed through RTK is logged to a local SQLite database.

### Database Location

| Platform | Path |
|----------|------|
| macOS | `~/Library/Application Support/rtk/tracking.db` |
| Linux | `~/.local/share/rtk/tracking.db` |
| Windows | `%APPDATA%\rtk\tracking.db` |

### Schema

```sql
CREATE TABLE commands (
    id              INTEGER PRIMARY KEY,
    timestamp       TEXT,           -- UTC timestamp
    original_cmd    TEXT,           -- e.g., "git log --oneline -50"
    rtk_cmd         TEXT,           -- e.g., "rtk git log"
    project_path    TEXT,           -- Current working directory
    input_tokens    INTEGER,
    output_tokens   INTEGER,
    saved_tokens    INTEGER,
    savings_pct     REAL,
    exec_time_ms    INTEGER
);

CREATE TABLE parse_failures (
    timestamp           TEXT,
    raw_command         TEXT,
    error_message       TEXT,
    fallback_succeeded  INTEGER
);
```

### Risk Assessment

- **Full command text** is stored, including arguments (file paths, branch names, etc.)
- **Working directory** is captured for every command execution
- Data is retained for **90 days** before automatic cleanup
- The database is purely local — never synced or transmitted
- Treat `tracking.db` as sensitive; it contains a detailed development activity log

---

## 4. Hook System — Command Interception

**Files:** `src/hooks/init.rs`, `src/hooks/rewrite_cmd.rs`, `src/hooks/hook_cmd.rs`

`rtk init` installs a **preToolUse hook** into Claude Code that intercepts every Bash command the AI tries to run and rewrites it to route through RTK.

### Hook Installation

```
~/.claude/hooks/rtk-rewrite.sh    ← Shell hook (thin wrapper)
~/.claude/hooks/.rtk-hook.sha256  ← Integrity hash (read-only, 0444)
~/.claude/settings.json           ← Modified to register the hook
```

### Command Rewrite Flow

```
Claude Code wants to run: git log --oneline -20
         ↓
preToolUse hook fires → rtk-rewrite.sh
         ↓
Delegates to: rtk rewrite "git log --oneline -20"
         ↓
Permission check (deny/ask/allow rules)
         ↓
Exit code determines action:
  0 + stdout → Rewrite accepted (e.g., "rtk git log --oneline -20")
  1          → No RTK equivalent, pass through unchanged
  2          → Deny rule matched, block command
  3 + stdout → Rewrite, but prompt user for approval
```

### Security Features

| Feature | Detail |
|---------|--------|
| SHA-256 integrity | Hook file is hashed; tampering detected at runtime |
| No shell interpretation | Uses `Command::new()` with `.arg()`, never `sh -c` |
| Heredoc exclusion | Heredocs/redirects excluded from rewriting to prevent injection |
| Atomic writes | Uses `tempfile::NamedTempFile` for hook installation |
| Permission precedence | Deny > Ask > Allow > Default(ask) — least privilege |
| No shell config modification | Does **not** touch `.bashrc`, `.zshrc`, `.profile` |

---

## 5. Project-Local Filter Trust System

**File:** `src/hooks/trust.rs`

RTK supports project-local filter files (`.rtk/filters.toml`) that could theoretically be used to manipulate command output. The trust system prevents this:

- **Trust-before-load**: Untrusted filters are skipped entirely, not loaded with a warning
- **Content-change detection**: SHA-256 hash of filter file; if content changes, trust is invalidated
- **CI override protection**: `RTK_TRUST_PROJECT_FILTERS=1` only works when CI env vars are also present (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `BUILDKITE`). Rejects the override if no CI indicator is detected — prevents `.envrc` injection.
- **Risk warnings**: Alerts user about `replace` rules, `match_output` rules, and catch-all patterns

---

## 6. Sensitive Data Handling

### Environment Variable Masking

**File:** `src/cmds/system/env_cmd.rs`

`rtk env` masks values matching these patterns:

```
key, secret, password, token, credential, auth,
private, api_key, apikey, access_key, jwt
```

### Build Log Secret Redaction

**File:** `src/cmds/dotnet/binlog.rs` (lines 113–147)

RTK redacts 35+ sensitive environment variables from .NET build logs:

```
SSH_AUTH_SOCK, GH_TOKEN, GITHUB_TOKEN, GITHUB_PAT,
NUGET_API_KEY, NUGET_AUTH_TOKEN, AZURE_CLIENT_SECRET,
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
API_TOKEN, AUTH_TOKEN, ACCESS_TOKEN, BEARER_TOKEN, PASSWORD,
CONNECTION_STRING, DATABASE_URL, DOCKER_CONFIG, KUBECONFIG, ...
```

---

## 7. Unsafe Code

**File:** `src/main.rs` (lines 2008–2011)

Single `unsafe` block in the entire codebase:

```rust
unsafe {
    libc::signal(libc::SIGINT, handle_signal as libc::sighandler_t);
    libc::signal(libc::SIGTERM, handle_signal as libc::sighandler_t);
}
```

- Purpose: Trap SIGINT/SIGTERM to cleanly terminate child processes
- Minimal scope, well-justified, standard pattern for CLI signal forwarding

---

## 8. Dependencies — Network Surface

| Dependency | Purpose | Network? |
|------------|---------|----------|
| `ureq` | HTTP client | Yes — telemetry only |
| `rusqlite` | SQLite | No |
| `serde_json` | JSON parsing | No |
| `regex` | Pattern matching | No |
| `clap` | CLI argument parsing | No |
| `walkdir` | Directory traversal | No |
| `sha2` | SHA-256 hashing | No |
| `hostname` | Get system hostname | No (syscall only) |
| `getrandom` | Cryptographic randomness | No |

No `reqwest`, `hyper`, `tokio`, `async-std`, or other async/networking crates.

---

## 9. Environment Variables

### RTK-Specific

| Variable | Purpose | Security Note |
|----------|---------|---------------|
| `RTK_TELEMETRY_DISABLED=1` | Disable telemetry | Opt-out mechanism |
| `RTK_TRUST_PROJECT_FILTERS=1` | Auto-trust project filters | CI-only (requires CI env vars) |
| `RTK_NO_TOML=1` | Bypass TOML filter engine | Debug/escape hatch |
| `RTK_DB_PATH` | Override tracking database location | Could redirect logging |
| `RTK_TEE_DIR` | Override tee output directory | Changes where raw output is saved |
| `RTK_TOML_DEBUG` | Print TOML filter debug info | Exposes filter matching internals |
| `RTK_AUDIT_DIR` | Override hook audit directory | Changes audit log location |

### System Variables Read

| Variable | Purpose |
|----------|---------|
| `USER` / `USERNAME` | Device hash generation (hashed, not transmitted raw) |
| `HOME` | Locate config/data directories |
| `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`, `BUILDKITE` | CI environment detection for trust system |

---

## 10. Summary Table

| Vector | Status | Detail |
|--------|--------|--------|
| **Outbound network** | 1 endpoint (telemetry) | Compile-time gated, triple opt-out, anonymized |
| **Session history reading** | Yes | Reads all Claude Code `.jsonl` files locally |
| **Command logging** | Yes | Full command + CWD stored in local SQLite for 90 days |
| **Hook installation** | Yes | Rewrites Claude Code commands to route through RTK |
| **Credential exfiltration** | No | Env vars masked, secrets redacted in dotnet/AWS output |
| **Backdoors** | None found | No eval, no hidden endpoints, no obfuscated code |
| **Shell config modification** | No | Uses Claude Code's native hook system only |
| **Unsafe code** | Minimal | Signal handling only (2 lines) |
| **Async / background tasks** | 1 thread | Telemetry fire-and-forget only |

---

## 11. Recommendations

1. **Verify telemetry status in your binary:**
   ```bash
   strings $(which rtk) | grep -i "http"
   ```
   If no URL appears, telemetry is completely inert.

2. **Be aware that `rtk discover` and `rtk learn` can read your full Claude Code session history**, including 1,000-character output snippets. If sessions contain sensitive data, consider filesystem permissions on `~/.claude/projects/`.

3. **Treat `tracking.db` as sensitive.** It contains 90 days of command history with full arguments and working directories. Located at:
   - macOS: `~/Library/Application Support/rtk/tracking.db`
   - Linux: `~/.local/share/rtk/tracking.db`

4. **Review project-local filters** (`.rtk/filters.toml`) in repositories you clone. The trust system provides protection, but understand that `replace` rules can alter command output shown to AI agents.

5. **Audit the installed hook** periodically:
   ```bash
   cat ~/.claude/hooks/rtk-rewrite.sh
   rtk verify  # Checks SHA-256 integrity
   ```

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

**`build.rs`** does only one thing: concatenates all `src/filters/*.toml` files into a single `builtin_filters.toml`, validates it parses correctly, and checks for duplicate filter names. No downloads, no native compilation, no external code generation.

**Build dependencies:** Only `toml = "0.8"` (a TOML parser for the validation step).

### Native Code Compiled from Source

**`rusqlite` with `"bundled"` feature** — this compiles SQLite from C source at build time (vendored inside the `rusqlite` crate from crates.io). This is standard practice and the C source is auditable within the crate. No pre-compiled SQLite binary is shipped in this repository.

### FFI Surface

One `extern "C"` function in `src/main.rs:1998` for Unix signal handling (`SIGINT`/`SIGTERM`). Uses the `libc` crate. No other FFI calls exist.

### Additional Checks

| Check | Result |
|-------|--------|
| Git submodules | None — no external repos pulled in |
| `.cargo/config.toml` | Does not exist — no custom linker flags or native library paths |
| Procedural macros | None — no compile-time code generation beyond `build.rs` |
| Vendored C/C++ code | None in this repo (SQLite is vendored inside `rusqlite` crate) |
| `include_bytes!()` | Not used anywhere — no binary data embedded |
| Pre-compiled binaries | None found in any directory |
| Archive files | None found (`.tar`, `.gz`, `.zip`, etc.) |
| Image files | None found (`.png`, `.jpg`, `.gif`, `.ico`, etc.) |

**Verdict:** The entire RTK binary is built from auditable source code. All embedded content is plain text. The only native C code involved (SQLite) is compiled from source via a well-known crates.io dependency.

---

*Audit performed on 2026-04-07 against RTK v0.35.0 (commit 8a7106c).*
