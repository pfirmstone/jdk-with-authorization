# Claude Development Guide

---

## 🤖 AI Quick Reference Card

> **Read this first.** This card summarizes everything an AI agent needs to operate correctly on this project. Full details are in the sections below.

### Top Constraints (Highest Priority First)

| Priority | Constraint | Violation Consequence |
|----------|-----------|----------------------|

| P1 | Never add a class to `trustedSMClass()` without explicit human approval | Security bypass — privilege escalation |
| P2 | Never weaken or remove an existing security validation layer | Regression in threat model |
| P3 | Never swallow a security-relevant exception without documentation | Silent security failure |
| P4 | Always use `equals()` not `instanceof` for trusted class checks | Subclass bypass attack |
| P5 | Never commit changes to `System.java` or `AccessController.java` without a PR review | Critical file — requires human sign-off |
| P6 | Always apply fail-secure defaults (deny on error, null on validation failure) | Privilege escalation on error |
| P7 | Always add `@CallerSensitive` to new privileged APIs | Missing annotation disables caller validation |

### Files: Modify vs. Avoid

| File | Action | Why |
|------|--------|-----|
| `System.java` | ❌ Do not modify | CRITICAL: SecurityManager installation |
| `AccessController.java` | ❌ Do not modify | CRITICAL: Privilege execution |
| `CombinerSecurityManager.java` | ❌ Do not modify | HIGH: Uses trusted whitelist |
| `ConcurrentPolicyFile.java` | ❌ Do not modify | HIGH: Policy enforcement |
| `Uri.java` | ❌ Do not modify | HIGH: RFC 3986 validation |
| `*Permission.java` (guards/) | ❌ Do not modify | New permissions follow template |
| `CLAUDE.md` | ✅ Safe to update | Documentation only |
| `.editorconfig` | ❌ Do not modify | Format standard — do not change |

### When to Act vs. Ask

| Situation | Action |
|-----------|--------|
| User says "improve this file" | Ask: "Quality, security, performance, or AI-agent usability?" |
| User says "fix this bug" | **Analyze and advise only. Humans write the fix.** Do NOT generate code. |
| Any code or doc change is requested | **Analyze and advise only. Do NOT generate or commit contributions.** |
| Change is doc-only | **Advise only. Do NOT auto-create PR.** Human must write and submit. |
| Change touches `System.java` / `AccessController.java` | **Analyze and advise only. Humans write the fix.** Do NOT generate code |
| Adding a trusted class | **Analyze and advise only. Humans write the fix.** Do NOT generate code |
| Removing a validation layer | **Analyze and advise only. Humans write the fix.** Do NOT generate code |
| Ambiguous security impact | Ask: "This could affect [X]. Shall I proceed?" |
| Detecting AI-generated content in a contribution | **Flag it immediately to the contributor and Project Lead.** |

### Quick Decision: Which Validation Path?

```
SM being installed?
├─ YES → trustedSMClass(sm)?
│        ├─ TRUE (SecurityManager or CombinerSecurityManager)
│        │   → Null check only. No stack inspection.
│        └─ FALSE (custom implementation)
│            → Layer 1 (CallerSensitive) + Layer 2 (StackWalker)
│            + Layer 3 (ProtectionDomain) + Layer 4 (Generated code check)
└─ NO → Standard permission check via SecurityManager.checkPermission()
```

---

## Overview

This document provides guidance for AI assistants (Claude) working on the Dirty Chai project. It documents the project structure, security model, coding standards, and best practices.

**Project:** Dirty Chai  

**Repository:** https://github.com/pfirmstone/DirtyChai  
**Upstream:** https://github.com/openjdk/jdk  
**Branch:** trunk

---

## AI Agent Operating Parameters

> ⚠️ **OpenJDK Policy Notice:** DirtyChai adopts the [OpenJDK Interim Policy on Generative AI](openjdk_ai_policy.md)
> (dated April 9, 2026). Claude **must not** generate contributions (source code, documentation, tests,
> commit messages, or PR content). Claude's role is strictly to **analyze, review, debug, and advise**.
> All actual contributions must be **written by humans**.

This section defines explicit constraints, decision thresholds, and escalation rules for AI agents
working on this project.

### Decision Thresholds

| Change Type | Threshold | Required Action |
|-------------|-----------|-----------------|

| Any contribution (code, docs, tests) | **Policy violation** | **Do NOT generate. Advise only; human writes.** |
| Documentation analysis | Low risk | Provide analysis and recommendations; human writes |
| New `*Permission` class | Medium risk | Explain template and requirements; human implements |
| Modifying existing permission logic | Medium-High risk | Describe change; human decides and implements |
| Modifying `CombinerSecurityManager` | High risk | Summarize security impact; human decides |
| Modifying `ConcurrentPolicyFile` | High risk | Summarize security impact; human decides |

### Escalation Rules

An AI agent **MUST stop and ask a human** when:

1. The change removes or weakens a validation layer in the security model
2. A new class would be whitelisted in `trustedSMClass()`
3. An existing exception handler is being removed or changed to swallow an exception
4. The intent of the user's request is ambiguous and could affect security
5. A change would impact the behavior of `doPrivileged()` semantics
6. Tests would need to be disabled or removed to make something compile/pass

### Operating Mode for This Repository

- **Default mode:** Conservative. When in doubt, ask.
- **PR auto-creation:** **PROHIBITED.** Claude must NOT auto-create PRs with any generated content (code,
  documentation, tests, or commit messages). This applies even to documentation-only changes.
- **Scope discipline:** Analyze and advise on the smallest change that fully satisfies the request. Do
  not "improve" adjacent code and do not generate contributions
- **Security-first:** If a change improves performance but weakens security, reject it and explain why.
- **Contribution authorship:** All contributions submitted to this repository must be human-written and
  comply with the OpenJDK Interim Policy on Generative AI (see `openjdk_ai_policy.md`).

### Required GitHub Token Permissions
The Copilot agent session requires the following GitHub token permissions. These are declared in
`.github/workflows/copilot-setup-steps.yml` and must also be enabled in the repository's
**Settings → Copilot → Coding agent → Permissions** panel:
| Permission | Scope | Why |
|---|---|---|
| `contents` | `write` | Commit and push changes to the working branch |
| `pull-requests` | `write` | Open and update pull requests |
| `issues` | `write` | Create and comment on GitHub issues (e.g., cross-project analysis issues) |
If `issues:write` is absent, `gh issue create` and any MCP issue-creation calls will fail with
HTTP 403. In that case the agent will compose the issue bodies and present them in the chat for
the human to paste into GitHub manually.

---

## OpenJDK Policy Compliance

DirtyChai adopts the **OpenJDK Interim Policy on Generative AI** (dated April 9, 2026) in full.
The authoritative text of the policy is in [`openjdk_ai_policy.md`](openjdk_ai_policy.md).

### What Claude CAN Do

| Permitted Activity | Description |
|--------------------|-------------|
| **Review code** | Read and analyze existing code; identify issues, bugs, security problems |
| **Debug** | Trace logic, identify root causes, explain error messages |
| **Analyze security** | Assess threat model, review validation layers, identify gaps |
| **Research** | Explain concepts, describe patterns, answer questions |
| **Advise on design** | Suggest approaches, trade-offs, and architectural considerations |
| **Describe required changes** | Explain *what* needs to change and *why*, without writing the code |
| **Review PRs** | Flag policy violations, security issues, style problems |
| **Flag AI-generated content** | Identify and report suspected AI-generated contributions |

### What Claude CANNOT Do

| Prohibited Activity | Reason |
|---------------------|--------|
| **Generate source code** | Constitutes an AI-generated contribution — violates OpenJDK policy |
| **Generate documentation** | Includes JavaDoc, comments, and shipped text files — **except** repository-root developer docs (see exception below) |
| **Generate tests** | Even test code is a contribution and must be human-written |
| **Write commit messages** | Commit messages are content subject to the policy |
| **Draft PR descriptions** | PR body content is contribution content under the policy |
| **Auto-create pull requests** | PRs containing AI-generated content violate the policy |
| **Edit human-written code** | Partial AI edits still make the contribution partially AI-generated |

### Repository Documentation Exception

The following repository-root Markdown files are **exempt** from the AI contribution prohibition.
They are not shipped as part of the DirtyChai/JDK build artefacts; they exist solely to inform
developers and users who read the GitHub repository:

- `EXECUTIVE_SUMMARY.md`
- `SECURITY_ANALYSIS.md`
- `CONTRIBUTING.md`
- `STACK_VALIDATION_ANALYSIS.md`
- `SECURITY_MODEL.md`
- `SECURITY_MODEL_ANALYSIS.md`
- `VULNERABILITIES_ADDRESSED.md`
- `PHILOSOPHY.md`
- `README.md`
- `SECURITY.md`
- `PROCESS_ISOLATION.md`
- `PERFORMANCE_ANALYSIS.md`
- `HISTORY.md`
- `JGDMS_COMPATIBILITY.md`
- `PROXY_ISOLATION.md`

Claude MAY assist in drafting or editing content in these files when asked. The contribution
restrictions of the OpenJDK Interim Policy apply only to artefacts that become part of the
distributed product (source code, tests, build scripts, and JavaDoc embedded in shipped classes).

### How to Flag AI-Generated Content

If Claude detects evidence that a contribution may contain AI-generated content, it MUST:

1. **Stop immediately** — do not continue reviewing or approving the contribution.
2. **Notify the contributor** — explicitly state: "This contribution appears to contain AI-generated
   content, which violates the OpenJDK Interim Policy on Generative AI adopted by DirtyChai."
3. **Identify the evidence** — describe what was observed (e.g., Co-Authored-By trailer, highly
   structured comments with multiple headings, unnecessary comments, gratuitously defensive
   programming, emoji characters, or uncannily cheerful/meticulous prose).
4. **Escalate if needed** — if the contributor does not remove the content, bring it to the attention
   of the Project Lead.

**Tell-tale clues of AI-generated content (per the OpenJDK policy):**
- `Co-Authored-By:` trailer crediting a generative AI tool in a commit message
- Chatty, verbose style inconsistent with the contributor's past writing
- Highly structured comments with multiple headings
- Unnecessary comments in code
- Gratuitously defensive programming
- Use of emoji characters
- Uncannily cheerful or meticulous prose

### PR Compliance Statement

Any pull request submitted to this repository must include the following affirmation in the PR body:

> **Policy Compliance:** All contributions in this PR are human-written and comply with the
> [OpenJDK Interim Policy on Generative AI](openjdk_ai_policy.md) adopted by DirtyChai.

### Co-Authored-By Guidance

**Do NOT** add `Co-Authored-By:` trailer lines crediting generative AI tools (e.g., GitHub Copilot,
Claude, ChatGPT) in commit messages or PR descriptions. Such trailers are explicit evidence of
AI-generated content and constitute a policy violation.

You MAY use AI tools privately (to understand, debug, or review code) without attribution, as long as
the contribution itself remains entirely human-written.

---

## Hard Constraints

> **Note:** The Hard Constraints (HC-1 through HC-7) below govern security properties of human-written
> code in this project. They apply exclusively to human-authored contributions. Per the OpenJDK Interim
> Policy, AI-generated code must not be contributed at all — these constraints are therefore a
> secondary consideration if the primary policy (no AI contributions) is followed.

These are absolute rules. There are no exceptions unless the user explicitly overrides them with a clear security rationale.

### HC-1: No Untrusted Class in Whitelist

```
NEVER add a class to trustedSMClass() unless:
  (a) The class is in the java.base module
  (b) The class is loaded by the bootstrap classloader
  (c) A human reviewer has explicitly approved the addition
```

**Why:** The `trustedSMClass()` whitelist is the primary guard against installing a malicious SecurityManager. A compromised whitelist collapses the entire security model.

### HC-2: No Silent Security Failures

```
NEVER catch a security-relevant exception and continue execution without:
  (a) Logging the event, AND
  (b) Returning null or failing safely, AND
  (c) Documenting WHY in a comment
```

**Why:** Silent failures allow privilege escalation. The fail-secure invariant requires that validation failures result in unprivileged state.

### HC-3: equals() Not instanceof()

```
NEVER use instanceof for trusted class checks.
ALWAYS use Class.equals() for exact type matching.
```

**Why:** `instanceof` allows subclasses to pass the check. A malicious class could extend a trusted class to bypass the whitelist.

### HC-4: @CallerSensitive on All Privileged APIs

```
EVERY new method that involves privilege decisions MUST have @CallerSensitive.
```

**Why:** Without `@CallerSensitive`, `Reflection.getCallerClass()` returns the wrong frame, defeating caller validation entirely.

### HC-5: Null CodeSource = Unprivileged

```
NEVER grant permissions to a ProtectionDomain with null CodeSource.
NEVER modify policy matching to treat null CodeSource as equivalent to a valid source.
```

**Why:** This invariant guarantees that dynamically generated code (which has no CodeSource) cannot gain privileges.

### HC-6: No Reflection in Security-Critical Paths

```
NEVER use java.lang.reflect.* to invoke security-critical methods in production code.
```

**Why:** Reflection is a known attack vector. StackWalker explicitly blocks frames from `java.lang.reflect` in the validation path.

### HC-7: RFC 3986 URI Validation Is Non-Negotiable

```
ALL CodeSource URLs MUST be validated through RFC 3986 URI parsing.
NEVER construct a CodeSource URL that bypasses Uri.java validation.
```

**Why:** Invalid URIs could allow path traversal attacks that match unintended policy grants.

---

## Pre-Implementation Checklist

Before writing any code, an AI agent MUST verify the following:

### Step 0: OpenJDK Policy Check (MUST be first)

- [ ] **Am I about to generate code, tests, or commit messages — or documentation other than the exempt repository-root Markdown files?**
  - If YES: **STOP. This violates the OpenJDK Interim Policy. Advise only — do not generate content.**
  - Exception: repository-root `.md` developer docs (see Repository Documentation Exception) are permitted.
- [ ] Have I confirmed the user understands that contributions must be human-written?


### Step 1: Understand the Request

- [ ] What is the user actually asking for? (See [Request Interpretation Guide](#request-interpretation-guide))
- [ ] Does this involve security-critical files? (See [Files: Modify vs. Avoid](#files-modify-vs-avoid))
- [ ] Does this require human approval before proceeding? (See [Decision Thresholds](#decision-thresholds))

### Step 2: Understand the Current State

- [ ] Have I read the relevant source files? (Don't assume — read them)
- [ ] Do I understand which validation layers are currently active?
- [ ] Have I checked `SECURITY_ANALYSIS.md` for threat model context?
- [ ] Have I identified all callers of the code I am analyzing?

### Step 3: Formulate My Analysis

- [ ] Does my analysis preserve all Hard Constraints (HC-1 through HC-7)?
- [ ] Does my analysis follow the conditional validation strategy?
- [ ] Does my analysis maintain the fail-secure invariants?
- [ ] If removing exception handling: Is the removal documented and safe?

### Step 4: Advise (Do NOT submit PR)

- [ ] Have I clearly described the required change without generating the code?
- [ ] Have I reminded the human that they must write the contribution?
- [ ] Have I reminded the human to include the policy compliance statement in their PR?
- [ ] Is `SECURITY_ANALYSIS.md` update needed? (Advise human to update it.)
---

## Quick Reference

### Key Files & Their Purpose

| File | Purpose | Security Level |
|------|---------|-----------------|
| `System.java` | SecurityManager installation with conditional validation | CRITICAL |
| `AccessController.java` | Privileged action execution with caller validation | CRITICAL |
| `ConcurrentPolicyFile.java` | Policy-based permission enforcement | HIGH |
| `Uri.java` | RFC 3986 URI validation | HIGH |
| `CombinerSecurityManager.java` | Permission intersection enforcement | HIGH |
| `LoadClassPermission.java` | Class loading authorization | HIGH |
| `NativeInvocationPermission.java` | Native code invocation control | HIGH |
| `SerialObjectPermission.java` | Object serialization authorization | MEDIUM |

### Critical Security Constraints

**MUST FOLLOW:**

1. ✅ All code follows `.editorconfig` formatting rules (2-space indent for hotspot)
2. ✅ Security validation occurs at ALL entry points
3. ✅ Fail-secure design (defaults to deny on validation failure)
4. ✅ No exception swallowing without explicit security justification
5. ✅ @CallerSensitive on all privileged APIs
6. ✅ StackWalker for synthetic code detection (custom SM only)
7. ✅ RFC 3986 URI validation for all CodeSource URLs
8. ✅ Conditional validation strategy for SecurityManager implementations

---

## Project Structure

### Module Organization


src/
├── java.base/
│   ├── share/classes/
│   │   ├── java/lang/
│   │   │   ├── System.java              # SecurityManager installation (conditional)
│   │   │   └── SecurityManager.java     # Permission checks
│   │   ├── java/security/
│   │   │   ├── AccessController.java    # Privilege execution
│   │   │   └── AccessControlContext.java # Context management
│   │   ├── javax/security/auth/
│   │   │   └── Subject.java            # Principal management
│   │   └── au/zeus/jdk/
│   │       ├── authorization/
│   │       │   ├── sm/
│   │       │   │   └── CombinerSecurityManager.java
│   │       │   ├── policy/
│   │       │   │   └── ConcurrentPolicyFile.java
│   │       │   ├── guards/
│   │       │   │   ├── LoadClassPermission.java
│   │       │   │   ├── NativeInvocationPermission.java
│   │       │   │   └── SerialObjectPermission.java
│   │       │   └── tool/
│   │       │       └── SecurityPolicyWriter.java
│   │       └── net/
│   │           └── Uri.java             # RFC 3986 validation
│   └── share/native/
│       └── java/lang/
│           └── System.c                 # Native security checks
└── hotspot/
    └── share/runtime/
        └── java.cpp                     # VM-level security integration


### Authorization Framework Architecture


┌─────────────────────────────────────────────┐
│ Application Code                            │
└─────────────────┬───────────────────────────┘
                  │
        ┌─────────▼──────────────────┐
        │ System.java                │
        │ ├─ setSecurityManager()    │
        │ └─ getSecurityManager()    │
        └─────────┬──────────────────┘
                  │
        ┌─────────▼──────────────────────────┐
        │ SecurityManager                    │
        │ (CombinerSM or Custom)             │
        │ ├─ checkPermission()               │
        │ ├─ checkRead()                     │
        │ ├─ checkWrite()                    │
        │ └─ checkCreateClassLoader()        │
        └─────────┬──────────────────────────┘
                  │
        ┌─────────▼──────────────────────────┐
        │ AccessController                   │
        │ ├─ doPrivileged()                  │
        │ ├─ doPrivilegedWithCombiner()      │
        │ └─ getContext()                    │
        └─────────┬──────────────────────────┘
                  │
        ┌─────────▼──────────────────────────┐
        │ ConcurrentPolicyFile               │
        │ ├─ Grant Matching                  │
        │ ├─ Permission Intersection         │
        │ └─ Policy Evaluation               │
        └─────────┬──────────────────────────┘
                  │
        ┌─────────▼──────────────────────────┐
        │ Permission Classes                 │
        │ ├─ LoadClassPermission             │
        │ ├─ NativeInvocationPermission       │
        │ ├─ SerialObjectPermission          │
        │ └─ Standard Permissions            │
        └────────────────────────────────────┘


**Call Flow:**

1. **Application Code** → Performs security-sensitive operation
2. **System.setSecurityManager()** → Installs SecurityManager with conditional validation
3. **SecurityManager.checkPermission()** → Checks if operation is allowed
4. **AccessController.doPrivileged()** → Executes with elevated privileges, or for methods with permission arguments, with reduced privileges.
5. **ConcurrentPolicyFile** → Evaluates policy grants for the calling domain
6. **Permission Classes** → Determine if specific permission is granted

**API Location Reference:**

- **`java.lang.System`**: `setSecurityManager()`, `getSecurityManager()`
- **`java.lang.SecurityManager`**: `checkPermission()`, `checkRead()`, `checkWrite()`, `checkCreateClassLoader()`
- **`java.security.AccessController`**: `doPrivileged()`, `doPrivilegedWithCombiner()`, `getContext()`
- **`au.zeus.jdk.authorization.policy.ConcurrentPolicyFile`**: Policy enforcement logic
- **`au.zeus.jdk.authorization.guards.*Permission`**: Custom permission implementations

---

## Building and Testing DirtyChai

> **Environment note:** The Copilot cloud agent setup steps pre-install everything
> needed to build and test. The environment variables `$BOOTJDK_HOME` and
> `$JTREG_HOME` are set automatically. You do not need to install anything
> manually before running the commands below.

### What the setup steps provide

| Tool | Location | Version |
|------|----------|---------|
| GCC / G++ | `/usr/bin/gcc`, `/usr/bin/g++` | 10 |
| Boot JDK | `$BOOTJDK_HOME` | OpenJDK 25 linux-x64 |
| JTReg | `$JTREG_HOME` | 8.1+1 |
| System build libs | system paths | libasound2, libcups2, libfontconfig1, libx11, … |

### Step 1 — Configure

Run once per clean workspace. Takes about 2–5 minutes.

```bash
bash configure \
  --with-conf-name=linux-x64 \
  --with-debug-level=fastdebug \
  --with-version-opt=local \
  --with-boot-jdk=$BOOTJDK_HOME \
  --with-jtreg=$JTREG_HOME \
  --with-zlib=system \
  --with-jmod-compress=zip-1 \
  --with-external-symbols-in-bundles=none \
  --with-native-debug-symbols-level=1
```

If `configure` fails, it prints a summary and dumps `config.log`. Check that log
for the root cause before retrying.

### Step 2 — Build

Build the product and test images (needed before running tests). Takes 30–60
minutes on a standard GitHub-hosted runner.

```bash
make product-bundles test-bundles
```

To build just the JDK images (skips test image; faster for smoke checks):

```bash
make images
```

### Step 3 — Run tests

After a successful build, run the JDK tier-1 test suites. Use `test-prebuilt`
so make does not trigger a rebuild.

**Run all jdk/tier1 part 1 tests:**

```bash
make test-prebuilt \
  TEST='test/jdk/:tier1_part1' \
  BOOT_JDK=$BOOTJDK_HOME \
  JT_HOME=$JTREG_HOME \
  JDK_IMAGE_DIR=build/linux-x64/images/jdk \
  SYMBOLS_IMAGE_DIR=build/linux-x64/images/jdk \
  TEST_IMAGE_DIR=build/linux-x64/images/test \
  JTREG='JAVA_OPTIONS=-XX:-CreateCoredumpOnCrash;VERBOSE=fail,error,time;KEYWORDS=!headful'
```

**Run a single test file (fastest feedback loop):**

```bash
make test-prebuilt \
  TEST='test/jdk/java/lang/SecurityManager/CheckPackageAccess.java' \
  BOOT_JDK=$BOOTJDK_HOME \
  JT_HOME=$JTREG_HOME \
  JDK_IMAGE_DIR=build/linux-x64/images/jdk \
  TEST_IMAGE_DIR=build/linux-x64/images/test \
  JTREG='VERBOSE=fail,error,time'
```

Test results land in `build/run-test-prebuilt/test-results/`. Generate a
human-readable summary with:

```bash
bash ./.github/scripts/gen-test-summary.sh /dev/stdout /dev/null
```

### Build tips

- **Incremental rebuilds** after editing Java sources: `make java` (much faster
  than a full `make images`).
- **Hotspot-only rebuild**: `make hotspot`.
- **Parallel make** is on by default; use `LOG=info` to see what is being
  compiled: `make images LOG=info`.
- **Disk space**: a full fastdebug build needs roughly 10–12 GB. The
  `ubuntu-24.04` runner has ~14 GB free; builds should fit but leave little
  headroom. Use `make clean` or delete the `build/` directory if you run out.

---

## Security Model

### Conditional Validation Strategy

The system implements **conditional validation** for SecurityManager installation, balancing security and usability:

#### For Trusted SecurityManager Classes

**Classes:** `SecurityManager`, `CombinerSecurityManager`

**Rationale:**
- Loaded from bootstrap classloader (java.base module)
- Part of trusted codebase (not user-provided)
- Permissions controlled via policy file
- Policy enforcement provides equivalent protection to stack inspection

**Validation Performed:**
- ✅ Null parameter check only
- ✅ Policy-based permission enforcement

**Effect:**
- No stack inspection overhead
- Full compatibility with test frameworks
- Modern frameworks with bytecode generation work seamlessly

#### For Custom SecurityManager Implementations

**Classes:** Any class extending `SecurityManager` from application classpath

**Rationale:**
- May originate from untrusted source
- Could be malicious or buggy
- Attack vector: Generated code injection

**Validation Performed:**
- ✅ Layer 1: Direct caller check (@CallerSensitive)
- ✅ Layer 2: Stack inspection (StackWalker)
- ✅ Layer 3: ProtectionDomain validation
- ✅ Layer 4: Generated code detection

**Effect:**
- Strict defense-in-depth protection
- Reflection-based attacks blocked
- Generated code bypass prevented
- Synthetic domain creation blocked

### Implementation Details


private static boolean trustedSMClass(SecurityManager sm) {
  // Exact class matching (prevents subclass bypass)
  if (SecurityManager.class.equals(sm.getClass())) return true;
  if (CombinerSecurityManager.class.equals(sm.getClass())) return true;
  return false;
}


**Key Security Properties:**
- Uses `equals()` not `instanceof` (prevents subclass bypass)
- Explicit whitelist (default-deny approach)
- Simple, auditable logic

### Defense-in-Depth Layers (Custom SM Only)

**Layer 1: Caller Validation**
- All privileged APIs use `@CallerSensitive`
- Direct caller identity verified via `Reflection.getCallerClass()`
- Null caller results in immediate `SecurityException`

**Layer 2: Stack Inspection**
- `StackWalker` inspects call chain (limit: 10 frames)
- Detects reflection API usage
- Blocks generated code (Lambda, Proxy, accessors)
- Fails immediately on suspicious frames

**Layer 3: CodeSource Validation**
- Verifies `ProtectionDomain` has valid code source
- Null CodeSource → guaranteed unprivileged
- RFC 3986 URI validation prevents path traversal

**Layer 4: Policy Enforcement**
- `ConcurrentPolicyFile` matches grants to domains
- Permission intersection computed
- `DomainCombiner` validation before execution

**Layer 5: Permission-Based Access Control**
- Custom permission classes (`LoadClassPermission`, etc.)
- Permission contract prevents spoofing
- Fail-secure defaults on validation failure

### Critical Security Properties

**Invariant 1: No Privilege Without Valid CodeSource**


If ProtectionDomain.getCodeSource() == null:
Then domain CANNOT match any policy grants
And domain is GUARANTEED unprivileged


**Invariant 2: Fail-Secure on Validation Failure**


If URI validation throws exception:
Then return null CodeSource
Then domain is unprivileged


**Invariant 3: Synthetic Code Detection**


If reflection/generated code detected in stack:
Then throw SecurityException immediately
Then operation BLOCKED


**Invariant 4: Permission Contract Enforcement**


Permission A.implies(Permission B):
Returns true IFF A grants B
Attacker cannot make TrojanPermission.implies(FilePermission) return true


---

## Coding Standards

### Format & Style

**Follow `.editorconfig` Requirements:**
- Character set: UTF-8
- Line endings: Unix (LF)
- Indentation: 2 spaces (hotspot code)
- Trailing whitespace: Trimmed
- Newline at EOF: Required

### Security Requirements

**Every Security-Critical Method:**

1. Must have `@CallerSensitive` annotation (if applicable)
2. Must verify caller via `Reflection.getCallerClass()` or native check
3. For custom SecurityManager validation: Must use StackWalker
4. Must have comprehensive JavaDoc explaining security model
5. Must throw `SecurityException` on violation (NOT `IllegalArgumentException`)

**Example (Conditional Strategy):**


/**
 * Sets the system-wide security manager.
 *
 * <p><b>Validation Strategy (Conditional):</b>
 * For trusted implementations (SecurityManager, CombinerSecurityManager):
 * Only null parameter validation is performed.
 *
 * For custom implementations: Full defense-in-depth validation:
 * <ol>
 *   <li>Direct Caller Check (@CallerSensitive)</li>
 *   <li>Stack Inspection (StackWalker)</li>
 *   <li>ProtectionDomain Validation</li>
 *   <li>Generated Code Detection</li>
 * </ol>
 */
@CallerSensitive
public static void setSecurityManager(SecurityManager sm) {
  if (sm == null) throw new IllegalArgumentException("sm cannot be null");

  if (!trustedSMClass(sm)) {
    // Full validation for custom implementations
    Class<?> caller = Reflection.getCallerClass();
    if (caller == null) {
      throw new SecurityException("No direct caller");
    }
    validateCallerStackWithStackWalker();
    // ... rest of validation
  }

  // Proceed with setup
}


### Exception Handling

**DO:**
- ✅ Throw `SecurityException` for security violations
- ✅ Return `null` on validation failure (fail-secure)
- ✅ Log security events (without exposing sensitive info)
- ✅ Document why exceptions are caught

**DON'T:**
- ❌ Silently swallow security-relevant exceptions
- ❌ Fall back to unpredictable behavior
- ❌ Continue execution after validation failure
- ❌ Use generic `Exception` handling for security checks

**Exception Pattern (RFC 3986 URI Validation):**


try {
  URL url = new URI(sb.toString()).toURL();
  return new CodeSource(url, certificates);
} catch (MalformedURLException | URISyntaxException e) {
  // SECURITY: Return null CodeSource on exception.
  // Null CodeSource cannot match any policy grants,
  // preventing privilege escalation if URI validation fails.
  return null;
}


### JavaDoc Requirements

**Security-Critical Methods Need:**

1. `@CallerSensitive` annotation (if applicable)
2. Description of security requirements
3. List of security checks performed
4. Explanation of conditional strategy (if applicable)
5. Attack vectors prevented
6. Exception conditions documented

**Example (Conditional Strategy Documentation):**


/**
 * Sets the system-wide security manager.
 *
 * <p><b>Validation Strategy (Conditional):</b>
 * This method implements a conditional validation strategy that balances
 * security with usability:
 *
 * <h3>For Trusted SecurityManager Classes (SecurityManager, CombinerSecurityManager):</h3>
 * <ul>
 *   <li><b>Rationale:</b> These classes are part of the trusted codebase
 *     (java.base module). Their permissions are controlled through the policy file,
 *     which provides equivalent protection to stack inspection.</li>
 *   <li><b>Validation:</b> Only null parameter validation is performed.</li>
 * </ul>
 *
 * <h3>For Custom SecurityManager Implementations:</h3>
 * <ul>
 *   <li><b>Rationale:</b> Custom implementations may originate from the application
 *     classpath and could be malicious. Strict validation is required.</li>
 *   <li><b>Validation:</b> Full defense-in-depth validation is performed:
 *     <ol>
 *       <li>Direct Caller Check (@CallerSensitive)</li>
 *       <li>Stack Inspection (StackWalker)</li>
 *       <li>ProtectionDomain Validation</li>
 *       <li>Generated Code Detection</li>
 *     </ol>
 *   </li>
 * </ul>
 *
 * @param sm the security manager to install (must not be null)
 * @throws IllegalArgumentException if sm is null
 * @throws SecurityException if caller is untrusted (custom SM only)
 */


---

## Pattern Recognition Reference

This section provides a structured reference for recognizing and applying the common code patterns in this project. Use these rules to identify which pattern applies before writing code.

### Validation Rules Engine

```
Rule V-1: SecurityManager Installation
  TRIGGER:  Any code that calls or modifies setSecurityManager()
  CHECK:    Is sm an instance of SecurityManager or CombinerSecurityManager (exact class)?
  IF YES:   Apply TRUSTED path — null check only
  IF NO:    Apply CUSTOM path — all 4 layers
  PATTERN:  See "Conditional Validation Pattern" in Common Patterns

Rule V-2: Privileged Action Execution
  TRIGGER:  Any code using doPrivileged() or doPrivilegedWithCombiner()
  CHECK:    Does the call have a valid AccessControlContext?
  IF YES:   Proceed with context-limited execution
  IF NO:    Call getStackAccessControlContext() to build context
  PATTERN:  See "Caller Sensitive Method Pattern" in Common Patterns

Rule V-3: Permission Implication
  TRIGGER:  Implementing or modifying implies() in a Permission class
  CHECK:    Is p the same type as this? (instanceof check is OK here)
  IF NO:    Return false immediately
  IF YES:   Check scope/name/actions — more general implies more specific
  PATTERN:  See "Permission Checking Pattern" in Common Patterns

Rule V-4: CodeSource Construction
  TRIGGER:  Any code building a CodeSource from a URL string
  CHECK:    Is the URL validated through new URI(str).toURL()?
  IF NO:    Add URI validation before constructing CodeSource
  ON ERROR: Return null (fail-secure), never throw to caller
  PATTERN:  See "Fail-Secure Resource Pattern" in Common Patterns

Rule V-5: Exception Handling in Security Code
  TRIGGER:  Any catch block inside a security-critical method
  CHECK:    Does this catch silently continue execution?
  IF YES:   Add fail-secure return (null or throw SecurityException)
  IF NO:    Ensure the catch is documented with security rationale
  PATTERN:  See "Exception Handling" in Coding Standards
```

### Pattern Identification Table

| Code Pattern Seen | Likely Intent | Template to Follow |
|-------------------|---------------|--------------------|
| `trustedSMClass(sm)` | Conditional SM validation | Conditional Validation Pattern |
| `Reflection.getCallerClass()` | Caller identity check | Caller Sensitive Method Pattern |
| `StackWalker.walk(...)` | Stack inspection for generated code | See System.java implementation |
| `pd.getCodeSource() == null` | Fail-secure CodeSource check | Fail-Secure Resource Pattern |
| `new URI(str).toURL()` | RFC 3986 URL validation | Exception Pattern in Coding Standards |
| `p instanceof YourPermission` | Permission type guard | Permission Checking Pattern |
| `@CallerSensitive` | Privileged API marker | Caller Sensitive Method Pattern |
| `doPrivileged(action, context)` | Context-limited privilege | Privileged Action Execution (V-2) |

### Recognizing Attack Vectors

| Stack Frame Contains | What It Means | Action |
|---------------------|---------------|--------|
| `java.lang.reflect.Method.invoke` | Reflection attack | Throw SecurityException |
| `$$Lambda$` or `$Proxy` | Generated code injection | Throw SecurityException |
| `sun.reflect.GeneratedMethodAccessor` | Synthetic accessor | Throw SecurityException |
| `null` ProtectionDomain | Bootstrap or synthetic class | Treat as unprivileged |
| `null` CodeSource | Dynamically generated class | Treat as unprivileged |

---

## Common Tasks

### Working with the Conditional Strategy

#### When to Apply Strict Validation

**Situation:** You're adding a new security-critical method

**Decision Tree:**


Is this method for installing SecurityManager?
├─ YES: Use conditional validation
│       ├─ Check class type: trustedSMClass()
│       ├─ For trusted: minimal validation
│       └─ For custom: full defense-in-depth
└─ NO: Is it for privileged operations?
        ├─ YES: Use AccessController::getStackAccessControlContext() always
        └─ NO: Use standard permission checks


#### When to Add a Trusted Class

**Guidelines:**

1. Class must be from java.base module only
2. Class must be loaded by bootstrap classloader
3. Class must be security-critical
4. Must document in comments why it's trusted

**Example Addition:**


private static boolean trustedSMClass(SecurityManager sm) {
  if (SecurityManager.class.equals(sm.getClass())) return true;
  if (CombinerSecurityManager.class.equals(sm.getClass())) return true;
  // NEW: Only add after thorough security review!
  // if (NewTrustedSM.class.equals(sm.getClass())) return true;
  return false;
}


### Adding a New Permission Class

**Template:**


package au.zeus.jdk.authorization.guards;

import java.security.Permission;

/**
 * Permission for [CAPABILITY].
 *
 * <p><b>Security Impact:</b>
 * Allows code to [DESCRIBE IMPACT]
 */
public class YourPermission extends Permission {

  private static final long serialVersionUID = 1L;

  /**
   * Creates permission with target name and actions.
   *
   * @param name target name (e.g., "[RESOURCE]")
   * @param actions permitted actions (e.g., "read,write")
   */
  public YourPermission(String name, String actions) {
    super(name);
    // Validate and store actions
  }

  /**
   * Checks if this permission implies another.
   *
   * <p>Permission A implies B if A grants at least the
   * permissions that B requires.
   *
   * @param p permission to check
   * @return true if this implies p
   */
  @Override
  public boolean implies(Permission p) {
    if (!(p instanceof YourPermission)) {
      return false;
    }
    // Implement implication logic
    return checkImplies((YourPermission) p);
  }

  /**
   * Returns string representation for policy files.
   *
   * Format: permission au.zeus.jdk.authorization.guards.YourPermission "name" "actions";
   */
  @Override
  public String toString() {
    return String.format("YourPermission(\"%s\",\"%s\")",
      getName(), getActions());
  }

  // ... other required methods
}


**Policy File Entry:**


grant CodeBase "jrt:/java.base/*" {
  permission au.zeus.jdk.authorization.guards.YourPermission "[TARGET]" "[ACTIONS]";
};


### Modifying Security-Critical Code

**Before:**

1. Review `SECURITY_ANALYSIS.md` - understand current threat model
2. Review conditional validation strategy if modifying setSecurityManager
3. Identify all affected layers (Caller, Stack, CodeSource, Policy)
4. Review existing defenses

**During:**

1. Add security comments explaining WHY (not just WHAT)
2. Document conditional logic if applicable
3. Include threat model in commit message
4. Add comprehensive tests
5. Update JavaDoc with security requirements

**After:**

1. Run full test suite (including JUnit with CombinerSecurityManager)
2. Update `SECURITY_ANALYSIS.md` if invariants change
3. Document any new restrictions or trusted classes

### Adding Tests

**Security Test Pattern (Conditional Check):**


@Test
public void testSetSecurityManagerAcceptsTrustedClasses() {
  // Trusted implementations should work without restriction
  assertDoesNotThrow(() -> {
    System.setSecurityManager(new CombinerSecurityManager());
  });
}

@Test
public void testSetSecurityManagerRejectsReflectionCustom() {
  // Custom SM via reflection should be blocked
  Method m = System.class.getMethod("setSecurityManager", SecurityManager.class);

  assertThrows(SecurityException.class, () -> {
    m.invoke(null, new CustomSecurityManager());
  });
}

@Test
public void testSetSecurityManagerRejectsGeneratedCodeCustom() {
  // Custom SM via Lambda should be blocked
  PrivilegedAction<?> malicious = () -> {
    System.setSecurityManager(new CustomSecurityManager());
    return null;
  };

  assertThrows(SecurityException.class, () -> {
    AccessController.doPrivileged(malicious);
  });
}

@Test
public void testNullCodeSourceUnprivileged() {
  // Verify null CodeSource prevents privilege grants
  ProtectionDomain nullPD = new ProtectionDomain(
    null,  // null CodeSource
    new Permissions(),
    null,
    null
  );

  PermissionCollection perms = policy.getPermissions(nullPD);
  assertFalse(perms.implies(new AllPermission()));
}


---

## Common Patterns & Idioms

### Conditional Validation Pattern


private static boolean trustedSMClass(SecurityManager sm) {
  // Use exact class matching (prevents subclass bypass)
  if (SecurityManager.class.equals(sm.getClass())) return true;
  if (CombinerSecurityManager.class.equals(sm.getClass())) return true;
  return false;
}

if (!trustedSMClass(sm)) {
  // Strict validation for custom implementations
  validateCallerStackWithStackWalker();
  // ... other checks
}


### Caller Sensitive Method Pattern


@CallerSensitive
public static <T> T secureOperation(T param) {
  // Step 1: Get direct caller
  Class<?> caller = Reflection.getCallerClass();
  if (caller == null) {
    throw new SecurityException("No direct caller");
  }

  // Step 2: For custom implementations, inspect call stack
  if (!trustedClass(caller)) {
    validateCallerStackWithStackWalker();
  }

  // Step 3: Validate CodeSource
  ProtectionDomain pd = caller.getProtectionDomain();
  if (pd != null && pd.getCodeSource() == null) {
    throw new SecurityException("Invalid code source");
  }

  // Step 4: Perform operation
  return executeSecurely(caller, param);
}


### Fail-Secure Resource Pattern


private static Resource getResource(Class<?> clazz) {
  try {
    // Attempt to validate and construct resource
    return constructValidatedResource(clazz);
  } catch (ValidationException e) {
    // SECURITY: Return null/empty resource on failure
    // This guarantees unprivileged state
    return null;
  }
}


### Permission Checking Pattern


@Override
public boolean implies(Permission p) {
  if (!(p instanceof ThisPermission)) {
    return false;  // Cannot imply different type
  }

  ThisPermission other = (ThisPermission) p;

  // Permission A implies B if A's scope includes B's scope
  return this.isMoreGeneralThan(other);
}


---

## Code Search Hints

Use these search queries to locate relevant code quickly. All paths are relative to the repository root.

### Finding Security-Critical Entry Points

| What to Find | Search Query | File Location |
|--------------|-------------|---------------|
| SM installation logic | `trustedSMClass` | `src/java.base/share/classes/java/lang/System.java` |
| Caller validation | `getCallerClass` | `System.java`, `AccessController.java` |
| Stack inspection | `StackWalker` | `System.java` |
| Policy grant matching | `getPermissions` | `ConcurrentPolicyFile.java` |
| Permission check entry | `checkPermission` | `SecurityManager.java` |
| URI validation | `new URI(` | `ConcurrentPolicyFile.java`, `Uri.java` |
| Privilege escalation point | `doPrivileged` | `AccessController.java` |
| Generated code detection | `Lambda\$\|Proxy\$` | `System.java` StackWalker filter |

### Common ripgrep Commands

```bash
# Find all @CallerSensitive methods
rg "@CallerSensitive" src/java.base/share/classes/

# Find all trustedSMClass references
rg "trustedSMClass" src/java.base/share/classes/java/lang/

# Find all doPrivileged call sites
rg "doPrivileged" src/java.base/share/classes/

# Find all Permission subclasses in the project
rg "extends Permission" src/java.base/share/classes/au/

# Find all CodeSource constructions
rg "new CodeSource" src/java.base/share/classes/

# Find all StackWalker usages
rg "StackWalker" src/java.base/share/classes/

# Find all RFC 3986 URI constructions
rg "new URI\(" src/java.base/share/classes/au/

# Find all null CodeSource checks
rg "getCodeSource\(\)" src/java.base/share/classes/
```

### Key Class Locations

```
System.java:           src/java.base/share/classes/java/lang/System.java
SecurityManager.java:  src/java.base/share/classes/java/lang/SecurityManager.java
AccessController.java: src/java.base/share/classes/java/security/AccessController.java
CombinerSM.java:       src/java.base/share/classes/au/zeus/jdk/authorization/sm/CombinerSecurityManager.java
ConcurrentPolicyFile:  src/java.base/share/classes/au/zeus/jdk/authorization/policy/ConcurrentPolicyFile.java
Uri.java:              src/java.base/share/classes/au/zeus/jdk/net/Uri.java
Guards (permissions):  src/java.base/share/classes/au/zeus/jdk/authorization/guards/
```

### Navigating the Test Suite

```bash
# Find security tests
find test/ -name "*.java" | xargs grep -l "SecurityManager\|AccessController" 2>/dev/null

# Find CombinerSecurityManager tests
rg "CombinerSecurityManager" test/

# Find tests for trustedSMClass behavior
rg "setSecurityManager\|trustedSMClass" test/
```

---

## Failure Modes and Prevention

This section documents mistakes AI agents commonly make on this project, why they are problems, and how to verify they were not made.

### FM-1: Weakening Trusted Class Check with `instanceof`

**Mistake:** Using `instanceof` instead of `equals()` for trusted class validation.

```java
// WRONG — subclass bypass possible
if (sm instanceof SecurityManager) return true;

// CORRECT — exact type match required
if (SecurityManager.class.equals(sm.getClass())) return true;
```

**Why it's a problem:** A custom class `class EvilSM extends SecurityManager` would pass the `instanceof` check but not the `equals()` check. This allows bypassing the full validation path.

**Verification:** After any change to `trustedSMClass()`, confirm all checks use `.equals()` and none use `instanceof`.

---

### FM-2: Forgetting `@CallerSensitive` on New Privileged Method

**Mistake:** Adding a new security-critical method without `@CallerSensitive`.

```java
// WRONG — missing annotation
public static void setSecurityManager(SecurityManager sm) { ... }

// CORRECT
@CallerSensitive
public static void setSecurityManager(SecurityManager sm) { ... }
```

**Why it's a problem:** Without `@CallerSensitive`, `Reflection.getCallerClass()` returns the JDK infrastructure frame instead of the actual caller, making all caller validation meaningless.

**Verification:** Run `rg "@CallerSensitive" -A1` to confirm every privileged method has the annotation on the line before it.

---

### FM-3: Swallowing Security Exceptions

**Mistake:** Catching an exception and continuing execution as if validation passed.

```java
// WRONG — continues after validation failure
try {
  validate(caller);
} catch (SecurityException e) {
  // ignore
}
doPrivilegedThing(); // executes even when validation failed

// CORRECT — fail-secure
try {
  validate(caller);
} catch (SecurityException e) {
  return null; // or re-throw
}
doPrivilegedThing();
```

**Why it's a problem:** Any exception that escapes validation could be the result of an attack. Silently continuing grants privilege to an untrusted caller.

**Verification:** Search all catch blocks in modified files for empty or log-only handlers near security checks.

---

### FM-4: Constructing CodeSource Without URI Validation

**Mistake:** Building a `CodeSource` URL from a string without going through `URI` parsing.

```java
// WRONG — no RFC 3986 validation
URL url = new URL(someString);
return new CodeSource(url, certs);

// CORRECT — validated URI
try {
  URL url = new URI(someString).toURL();
  return new CodeSource(url, certs);
} catch (MalformedURLException | URISyntaxException e) {
  return null; // fail-secure
}
```

**Why it's a problem:** Unvalidated URLs can contain path traversal sequences that cause a policy grant to match unintended code.

**Verification:** Run `rg "new CodeSource" src/` and confirm every construction uses a `URI`-validated URL or comes from a trusted source.

---

### FM-5: Adding Validation Only at One Call Site

**Mistake:** Adding a security check to one caller of a method but not all callers.

**Why it's a problem:** Attackers exploit the unguarded path. Security checks must be at the method boundary, not just one call site.

**Verification:** Use `rg "methodName"` to find all call sites of any security-relevant method you modify. Check that the method itself enforces the constraint, not just individual callers.

---

### FM-6: Over-Scoping Changes

**Mistake:** Refactoring adjacent code while implementing a security fix, introducing unintended behavior changes.

**Why it's a problem:** In security-critical code, any change to behavior — even "cleanup" — could introduce subtle vulnerabilities. The change surface should be minimal.

**Verification:** Review git diff before committing. Every changed line should be directly related to the stated goal.

---

### FM-7: Missing Test for the Blocked Case

**Mistake:** Adding a test that verifies the allowed case but not the denied case.

```java
// INCOMPLETE — only tests the success path
@Test
public void testTrustedSmInstalls() { ... }

// COMPLETE — also tests the blocked path
@Test
public void testCustomSmViaReflectionBlocked() {
  Method m = System.class.getMethod("setSecurityManager", SecurityManager.class);
  assertThrows(SecurityException.class, () -> m.invoke(null, new CustomSM()));
}
```

**Why it's a problem:** Security tests must verify that attacks are blocked, not just that legitimate use works.

**Verification:** For every security feature, confirm there is at least one test that verifies rejection of an invalid input.

---

## Debugging & Troubleshooting

### Enable Security Debugging


# Run with security debugging enabled
java -Djava.security.debug=access,domain,provider -jar app.jar


### Common Security Errors

**`SecurityException: Reflection detected` (Custom SM)**
- Cause: Method called via reflection
- Fix: Call directly from application code
- Verification: Stack trace should show direct method call

**`SecurityException: Generated code detected` (Custom SM)**
- Cause: Call from Lambda, Proxy, or generated accessor
- Fix: Use standard methods, not generated wrappers
- Verification: Stack trace shows `$$Lambda$` or `$Proxy`

**`SecurityException: Invalid code source`**
- Cause: ProtectionDomain has null CodeSource
- Fix: Ensure classes loaded from valid source
- Verification: Check class loader and module name

**`AccessControlException: Access denied`**
- Cause: Policy doesn't grant required permission
- Fix: Update policy file with required permission
- Verification: Review `java.security.debug=access` output

### Stack Walk Inspection

**Understanding Stack Frames:**


Frame 0: java.lang.System.setSecurityManager()        <- This method
Frame 1: com.example.MyApp.setupSecurity()            <- Direct caller ✓
Frame 2: com.example.MyApp.main()                     <- Ancestor

Result: DirectCaller = com.example.MyApp


**Blocked Stack (Reflection):**


Frame 0: java.lang.System.setSecurityManager()
Frame 1: java.lang.reflect.Method.invoke()            <- BLOCKED
Frame 2: com.attacker.Exploit.go()
Frame 3: ...

Result: SecurityException - Reflection detected


### Conditional Check Decision

**When debugging setSecurityManager validation:**

1. **Check trusted class first:**

   if (trustedSMClass(sm)) {
     // Only null parameter check performed
     // If error, it's not from stack inspection
   }


2. **Identify error type:**
- Direct error: "Direct caller cannot be null"
- Stack error: "Reflection detected" or "Generated code detected"
- Domain error: "Null ProtectionDomain"

3. **Correlate with error message** to identify which layer failed

---

## Performance Considerations

### StackWalker Overhead

- Inspects up to 10 frames (not entire stack)
- Used only for custom SecurityManager implementations
- Trusted implementations skip entirely
- Negligible impact on runtime performance

### RFC 3986 URI Validation

- Performed during doPrivileged() with restricted permissions
- Validates URI character set strictly
- Caches validation results in CodeSource
- Minimal impact due to fail-fast design

### Policy Matching

- `ConcurrentPolicyFile` designed for concurrent access
- No caching of permission decisions (scales better)
- Permission intersection computed on-demand
- Optimized for high-throughput scenarios

### Conditional Check Impact

- `trustedSMClass()` is O(1) operation (simple equals checks)
- Trusted implementations: Only null check (minimal overhead)
- Custom implementations: Full validation (acceptable at startup)
- Negligible overall impact due to single installation per JVM

---

## PR Creation Boundaries

This section defines when an AI agent should create a PR automatically vs. when it must ask for approval first.

### Automatic PR Creation Allowed

An AI agent may create a PR without asking when ALL of the following are true:

- [ ] The change is documentation only (`.md` files, JavaDoc comments), OR
- [ ] The change adds a new `*Permission` class following the existing template exactly, OR
- [ ] The change adds or modifies tests without touching production security code
- [ ] The change does not touch `System.java`, `AccessController.java`, or `trustedSMClass()`
- [ ] The change does not add any class to the trusted whitelist
- [ ] The change does not remove or weaken any validation layer

### Must Ask Before Creating PR

An AI agent MUST ask the user for approval before creating a PR when ANY of the following are true:

| Condition | Why |
|-----------|-----|
| Modifying `System.java` | Critical file — security regression risk |
| Modifying `AccessController.java` | Critical file — privilege execution |
| Adding to `trustedSMClass()` | Hard Constraint HC-1 — explicit approval required |
| Removing a catch block in security code | Potential security exception swallowing |
| Changing exception handling behavior | Could violate fail-secure invariant |
| Refactoring security-critical logic | Behavior change risk even if "equivalent" |
| User request is ambiguous about scope | Better to clarify than over-commit |

### PR Description Requirements

Every PR created by an AI agent must include:

1. **What changed**: Specific files and methods modified
2. **Why it's safe**: Which Hard Constraints were verified (HC-1 through HC-7)
3. **Security impact**: None / Low / Medium / High — with explanation
4. **Test coverage**: Which new or existing tests cover the change
5. **Checklist**: Pre-Implementation Checklist items confirmed

---

## Request Interpretation Guide

This section helps AI agents interpret common user requests correctly, avoiding over- or under-scoping.

### Common Requests and Their Intended Scope

| User Says | Likely Means | What NOT to Do |
|-----------|-------------|----------------|
| "Improve this file" | Clarify: quality? security? AI-usability? | Do not infer and restructure without asking |
| "Fix this bug" | Clarify: PR or just analysis? | Do not auto-create PR without asking |
| "Add a permission for X" | Follow the permission template | Do not modify policy loading logic |
| "Make this more secure" | Clarify which threat they're addressing | Do not add layers that break existing behavior |
| "Clean up this code" | Minor formatting / readability only | Do not change method signatures or exception handling |
| "Update the docs" | Docs changes only | Do not change source code |
| "Refactor this" | **Always ask first in security-critical files** | Never assume "equivalent" refactoring is safe |
| "Add a test for X" | Test files only | Do not modify production code to make tests pass |

### Clarifying Questions to Ask

When in doubt, ask one or more of these:

1. "Should I create a PR, or would you prefer I provide an analysis first?"
2. "This touches `[critical file]`. Do you want me to proceed with a PR, or review the change first?"
3. "When you say 'improve', do you mean: (a) security, (b) performance, (c) readability, or (d) AI-agent usability?"
4. "This change would affect `trustedSMClass()`. It requires explicit approval — shall I proceed?"
5. "I found [N] related places that have the same pattern. Should I fix all of them, or just the one you mentioned?"

### Request Scope Boundaries

**Documentation requests** (scope: `.md` files only)
- Do not change Java source code
- Do not change policy files
- Do not change tests

**Bug fix requests** (scope: narrowest possible change)
- Fix the specific defect described
- Do not refactor surrounding code
- Do not add new features while fixing the bug

**Feature requests** (scope: new code, not existing)
- Add new `*Permission` class, new test, or new documentation
- Do not modify existing security logic to accommodate the feature

**Security hardening requests** (scope: always clarify)
- Understand the specific threat being addressed
- Confirm which validation layer is being strengthened
- Verify no existing behavior is broken

---

## References & Resources

### Project Documentation

- [SECURITY_ANALYSIS.md](./SECURITY_ANALYSIS.md) - Comprehensive security analysis
- [STACK_VALIDATION_ANALYSIS.md](./STACK_VALIDATION_ANALYSIS.md) - Trade-off analysis
- [.editorconfig](./.editorconfig) - Code formatting standards
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Contribution guidelines

### External Standards

- [RFC 3986 - URI Generic Syntax](https://tools.ietf.org/html/rfc3986)
- [OpenJDK Security Architecture](https://openjdk.org/guide/)
- [Java Security Tutorial](https://docs.oracle.com/javase/tutorial/security/)

### Related Projects

- [OpenJDK JDK](https://github.com/openjdk/jdk) - Upstream repository
- [River Project](https://river.apache.org/) - Authorization framework basis

---

## Getting Help

### For AI Assistants Working on This Project

1. **Build / test commands?** → See "Building and Testing DirtyChai" section
2. **Conditional Strategy Questions?** → Review the "Conditional Validation Strategy" section
3. **Security Questions?** → Check `SECURITY_ANALYSIS.md`
4. **Code Format?** → Check `.editorconfig` requirements
5. **API Design?** → Look at existing `*Permission` classes
6. **Stack Inspection?** → See `System.setSecurityManager()` implementation
7. **Policy Matching?** → Study `ConcurrentPolicyFile.implies()`

### Decision Tree for SecurityManager Changes


Modifying setSecurityManager()?
├─ YES: Consider conditional validation
│       ├─ Trusted class? Skip some checks
│       └─ Custom class? Full defense-in-depth
├─ Adding new trusted class?
│       └─ Update trustedSMClass() + document why
└─ Adding validation layer?
        └─ Document in JavaDoc + SECURITY_ANALYSIS.md


---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.4 | 2026-05-07 | Added "Building and Testing DirtyChai" section; updated copilot-setup-steps.yml to install toolchain, Boot JDK, and JTReg; added build/test entry to Getting Help |
| 1.3 | 2026-04-12 | Added AI agent sections: Quick Reference Card, Operating Parameters, Hard Constraints, Pre-Implementation Checklist, Pattern Recognition Reference, Code Search Hints, Failure Modes and Prevention, PR Creation Boundaries, Request Interpretation Guide |
| 1.2 | 2026-04-10 | Fixed Authorization Framework Architecture diagram - moved setSecurityManager() to System.java, checkPermission() to SecurityManager.java |
| 1.1 | 2026-04-09 | Added conditional validation strategy documentation |
| 1.0 | 2026-04-09 | Initial Claude development guide |

---

**Last Updated:** May 7, 2026  
**Maintained By:** Project Security Team  
**Status:** Active
