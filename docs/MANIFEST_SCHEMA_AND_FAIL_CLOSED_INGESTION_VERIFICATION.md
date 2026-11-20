# Project Moray: Manifest Schema Hardening & Fail-Closed Ingestion Verification

## 1. Executive Summary

Milestone 4 of the [canonical development roadmap](file:///root/home/projects/project-moray/anotherroadmap.md) mandates:
> *"Treat the profiler as a policy suggestion, not an authority. Keep profiler output reviewable. Validate manifests against a schema instead of assuming they are well-formed. Don't automatically treat inferred commands or network posture as safe policy. Done when the manifest schema is documented and enforced, and the profiler output can be accepted, rejected, or edited safely."*

Prior to Milestone 4, manifest ingestion in `morayd` relied on simple string scanning (`strstr`), and the workspace profiler emitted policies directly intended for immediate enforcement. This presented three architectural risks:
1. **Loose Ingestion Vulnerability:** Malformed JSON, truncated fields, or superstring keywords (e.g. matching `"REQUIRE_WAN_EXTENDED"`) could lead to ambiguous or undefined policy states.
2. **Kernel Boundary Comm Overflow:** The Linux kernel task struct limits process comm names (`TASK_COMM_LEN`) to 16 bytes (15 printable ASCII characters + null terminator). Manifests containing binary names $> 15$ characters would be silently truncated in Ring 0, causing policy mismatch and false positive or false negative strikes.
3. **Unreviewed Heuristic Ingestion:** Profilers infer policy from static AST scanning and build configuration heuristics. Ingesting profiler output directly into Ring 0 enforcement without an explicit human review gate violates the Principle of Least Privilege and human engineering verification.

Milestone 4 resolves these risks across the entire stack:
- **Strict Zero-Dependency C Schema Validator ([`src/morayd.c`](file:///root/home/projects/project-moray/src/morayd.c)):** Pure C11 JSON parser and validator enforcing schema contracts, exact enum matching, and task comm bounds ($1 \le \text{len} \le 15$).
- **Fail-Closed Ingestion Gate:** Corrupted, malformed, or out-of-spec manifests fail closed immediately with non-zero exit codes.
- **Reviewable Policy Separation:** Profilers emit `"policy_state": "SUGGESTION"` by default with heuristic confidence markers and audit notices. Unreviewed manifests are rejected by `morayd` and Python bridges unless the `--enforce-unreviewed` override is explicitly specified.
- **Standalone Validation CLI:** `morayd --validate-manifest <file>` and `python3 bridge/lobster_hook.py --validate-manifest <file>` provide preflight CI/CD linting gates.
- **Live KVM MicroVM Test Expansion:** Kernel tests expanded from 90 to 100 steps (Domain 12: Steps 91–100), passing 100% cleanly.

---

## 2. Manifest Schema Contract

The canonical boundary manifest schema (`moray_boundary.json`) is strictly specified and validated:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "version": "1.0.0",
  "target_name": "moray_workload_a",
  "policy_state": "ENFORCED",
  "network_posture": "ALLOW_LOOPBACK",
  "strike_policy": "AUTONOMOUS_STRIKE",
  "allowed_comms": [
    "python3",
    "sh",
    "git",
    "cargo",
    "rustc",
    "morayd"
  ],
  "audit_notice": "Canonical reviewed boundary manifest for autonomous workload governance."
}
```

### 2.1 Schema Invariants

| Field | Type | Validation Rules | Default / State Behavior |
| :--- | :--- | :--- | :--- |
| `version` | string | Exact match `"1.0.0"` | Mandatory. Reject mismatched versions. |
| `target_name` | string | Non-empty string ($1 \le \text{len} \le 63$) | Target cgroup name or workload identifier. |
| `policy_state` | string | `"SUGGESTION"`, `"PROPOSED"`, `"ENFORCED"` | Default from profiler: `"SUGGESTION"`. `morayd` rejects unreviewed unless `--enforce-unreviewed`. |
| `network_posture` | string | `"ALLOW_LOOPBACK"`, `"DENY_ALL_NET"`, `"REQUIRE_WAN"` | Strict enum match. Reject unknown postures fail-closed. |
| `strike_policy` | string | Exact match `"AUTONOMOUS_STRIKE"` | Rejects undefined or passive strike modes. |
| `allowed_comms` | list[str] | Non-empty array; $1 \le \text{count} \le 64$. Each comm: $1 \le \text{len} \le 15$; allowed chars: `^[a-zA-Z0-9_.-]+$` | Enforces Linux `TASK_COMM_LEN` bounds. Rejects overlong comms. |
| `confidence` | string | `"HEURISTIC"`, `"VERIFIED"`, `"STATIC"` | Informational audit telemetry. |
| `audit_notice` | string | Free-form audit guidance string | Emitted by profiler to prompt human sign-off. |

---

## 3. Dual-Layer Implementation: C Daemon & Python Bridge

### 3.1 Zero-Dependency C11 Validator (`src/morayd.c`)

To maintain zero runtime library dependencies, `morayd` implements a bounded, secure C11 JSON parser:
- `json_get_string(json, key, out, max_len)`: Safely extracts string values bounded by quotes, skipping whitespace and colons.
- `json_get_object_bounds(json, key, ...)`: Identifies boundaries of nested objects and arrays (`[` and `]`).
- `validate_and_parse_manifest(manifest_path, out_manifest, allow_unreviewed)`:
  - Validates file existence and reads into memory.
  - Verifies exact version `"1.0.0"`.
  - Parses and checks `target_name`.
  - Evaluates `policy_state`: if `"SUGGESTION"` or `"PROPOSED"` and `!allow_unreviewed`, returns `-EPERM` with error log.
  - Matches `network_posture` against exact strings (`"ALLOW_LOOPBACK"`, `"DENY_ALL_NET"`, `"REQUIRE_WAN"`).
  - Validates `strike_policy` as `"AUTONOMOUS_STRIKE"`.
  - Iterates over `allowed_comms` array: validates comm count $\ge 1$, verifies comm length $\le 15$ (`TASK_COMM_LEN - 1`), rejects invalid characters, and populates `out_manifest->comms`.
- **CLI Ingestion & Standalone Validation Flags:**
  - `morayd --auto-harden <manifest> [--enforce-unreviewed]`: Ingests and enforces manifest.
  - `morayd --validate-manifest <manifest> [--enforce-unreviewed]`: Standalone validation preflight; exits 0 on valid, 1 on invalid.

### 3.2 Python Sovereign Bridge (`bridge/lobster_hook.py`, `bridge/moray_hook.py`)

- `validate_boundary_manifest(manifest_data, allow_unreviewed=False)`:
  - Accepts Python `dict` or JSON file path.
  - Validates all schema fields, types, and bounds matching C validator behavior.
  - Validates comm regex `^[a-zA-Z0-9_.-]+$` and length limit.
  - Enforces `policy_state` review gate: raises `ValueError("Unreviewed policy suggestion...")` unless `allow_unreviewed=True`.
- **CLI Interface:**
  - `python3 bridge/lobster_hook.py --validate-manifest <path> [--allow-unreviewed]`

### 3.3 Workspace Profiler (`bridge/moray_profiler.py`)

- Updated `generate_manifest()`:
  - Generates `"policy_state": "SUGGESTION"` by default.
  - Marks `"confidence": "HEURISTIC"`.
  - Injects audit notice: `"Heuristic policy generated by moray_profiler. Review allowed_comms and network_posture before promoting to ENFORCED."`
  - Auto-includes `morayd` in `allowed_comms` to ensure control-plane tasks are never struck.
- CLI Flags:
  - `--approve` / `--enforce`: Promotes generated manifest to `"policy_state": "ENFORCED"`.
  - `--validate <path>`: Runs preflight validation on an existing manifest.

---

## 4. Hermetic Test Coverage

The hermetic test suite (`tests/test_manifest_schema.py`) includes 22 tests verifying all edge cases:
- `test_valid_manifest_passes_validation`: Baseline valid schema passes cleanly.
- `test_missing_required_keys_fails`: Rejects manifests missing `version`, `target_name`, `network_posture`, `strike_policy`, or `allowed_comms`.
- `test_invalid_version_fails`: Rejects non-1.0.0 versions.
- `test_invalid_network_posture_fails`: Rejects undefined postures (e.g. `OPEN_WORLD`).
- `test_invalid_strike_policy_fails`: Rejects non-autonomous policies.
- `test_empty_or_nonlist_allowed_comms_fails`: Rejects empty lists or scalar strings.
- `test_comm_length_overflow_fails`: Rejects comms $> 15$ characters (e.g. `excessively_long_executable_name`).
- `test_comm_invalid_characters_fails`: Rejects comms with spaces or special characters.
- `test_unreviewed_policy_state_fails_by_default`: Rejects `SUGGESTION` and `PROPOSED` without override.
- `test_unreviewed_policy_state_allowed_with_flag`: Accepts `SUGGESTION` when `allow_unreviewed=True`.
- `test_enforced_policy_state_passes`: Accepts `ENFORCED` manifests unconditionally.
- `test_morayd_validate_manifest_cli_valid`: Tests `morayd --validate-manifest` exit code 0 on valid manifest.
- `test_morayd_validate_manifest_cli_invalid_posture`: Tests exit code 1 on invalid posture.
- `test_morayd_validate_manifest_cli_unreviewed_rejected`: Tests exit code 1 when unreviewed manifest lacks override.
- `test_morayd_validate_manifest_cli_unreviewed_accepted_with_flag`: Tests exit code 0 when `--enforce-unreviewed` is provided.
- `test_morayd_validate_manifest_cli_comm_overflow`: Tests exit code 1 on comm length overflow.
- `test_morayd_validate_manifest_cli_malformed_json`: Tests exit code 1 on corrupted JSON.
- `test_lobster_hook_validate_manifest_cli`: Tests CLI validation in Python bridge.
- `test_moray_profiler_generates_suggestion_by_default`: Tests profiler defaults to `SUGGESTION` and `HEURISTIC`.
- `test_moray_profiler_approve_flag_generates_enforced`: Tests `--approve` generates `ENFORCED` manifest.
- `test_moray_boundary_json_passes_strict_schema`: Verifies project canonical manifest is valid and enforced.

---

## 5. Live MicroVM Kernel Verification Suite (Domain 12: Steps 91–100)

Implemented in [`tests/run_live_kernel_test.sh`](file:///root/home/projects/project-moray/tests/run_live_kernel_test.sh#L1590-L1750), Domain 12 proves the manifest schema gate and fail-closed ingestion in hardware-isolated QEMU/KVM microVM:

| Step | Test Action | Expected Result | Return Code | Verification Invariant |
| :---: | :--- | :--- | :---: | :--- |
| **91** | Manifest validation gate: unreviewed `SUGGESTION` under `morayd --auto-harden` | Unreviewed suggestion rejected fail-closed | `1` | Heuristic Review Invariant |
| **92** | Malformed manifest ingestion rejection (corrupted JSON syntax) | Malformed manifest rejected fail-closed | `1` | Fail-Closed Parser Invariant |
| **93** | Comm length overflow rejection ($> 15$ characters in `allowed_comms`) | Excess comm length rejected fail-closed | `1` | `TASK_COMM_LEN` Boundary |
| **94** | Manifest activation with explicit `--enforce-unreviewed` override flag | Unreviewed manifest approved; daemon starts | `0` | Operator Override Gate |
| **95** | Manifest activation with reviewed & approved `ENFORCED` manifest | Clean schema validation; sentinel live | `0` | Approved Policy Ingestion |
| **96** | Ring 0 boundary enforcement under validated manifest | Unlisted binary (`unlisted_worker`) severed with `-EPERM` | `42` | Ring 0 Execution Severance ($I_8$) |
| **97** | Standalone C daemon CLI schema gate (`morayd --validate-manifest`) | Exits 0 on valid, 1 on invalid manifest | `0` | Standalone CLI Verification |
| **98** | Workspace profiler `--approve` integration & schema verification | Generates compliant `ENFORCED` manifest | `0` | Profiler-to-Policy Bridge |
| **99** | Sovereign Python bridge schema verification (`lobster_hook.py`) | Exits 0 on valid, 1 on invalid | `0` | Zero-Dependency Cross-Language |
| **100** | Clean shutdown & kernel map state verification | Sentinel detached; cgroup unlinked cleanly | `0` | Complete Lifecycle Teardown |

---

## 6. Zero-Nomenclature Inflation & Boundary Truth

In accordance with Rule 5 and the Zero Nomenclature Inflation Invariant, the guarantees of Milestone 4 are stated with precision:
1. **No Heuristic Authority:** The profiler is an advisory scanner, not a policy enforcement engine. Outputs are explicitly marked `SUGGESTION` and rejected by default in production.
2. **Deterministic Fail-Closed Parser:** The C parser does not invoke dynamic libraries or complex regex engines. Any token, key, or delimiter mismatch results in immediate execution termination before BPF map mutation.
3. **Hardware & Kernel Name Alignment:** Comm names are clamped to the exact 15-character limit enforced by the Linux kernel's `TASK_COMM_LEN - 1`. Overlong comms are caught at manifest validation rather than being silently truncated in the BPF ring buffer.
4. **Non-Destructive Integration:** The schema validation layer adds 0 runtime overhead to kernel fast-paths; validation executes strictly once during userspace daemon startup or offline preflight inspection.

---

## 7. Invariant Conformance

- **$I_1$ Ring 0 Kernel Enforcement:** Manifest schema validation guarantees that Ring 0 BPF maps receive only well-formed, reviewed comm hashes and valid network postures.
- **$I_2$ Zero Overhead & Non-Interference:** Schema validation executes entirely in userspace preflight; zero overhead is introduced into kernel fast-paths.
- **$I_8$ Autonomous Boundary Governance:** Fail-closed ingestion ensures that invalid or unreviewed policies can never place the system into an undefined or partially governed state.
- **$I_9$ Cgroup v2 Workload Jurisdiction:** Manifests bind strict comm whitelists and network postures to specific cgroup v2 targets with explicit review status tracking.
