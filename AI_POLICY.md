# DirtyChai AI Engagement Policy

> **Status: PARTIALLY ADOPTED — v1.0, ratified 2026-07-31 by the Project Lead.**
> Successor to the blanket adoption of the OpenJDK Interim Policy on Generative AI recorded in
> [`openjdk_ai_policy.md`](openjdk_ai_policy.md) and operationalized in [`CLAUDE.md`](CLAUDE.md).
> What is and is not in force:
>
> - **§8 Phase 1 + Phase 2 (decision 1a) are ADOPTED and IN FORCE.** Inbound upstream-tracking
>   (mechanical tag-to-tag merges, whose merged lines remain upstream-authored) and the Phase-2
>   merge security-impact assessment (analysis producing a punch-list, not code) are confirmed
>   permitted. This required no partition — it clarifies the existing policy rather than changing it.
> - **The Zone-D partition (§4, decision 1b) is NOT ADOPTED.** The divergent security core remains
>   **advise-only**: AI does not originate source, tests, or shipped documentation there. §8 Phase 3
>   remediation is human-authored — a human writes every `doPrivileged` block and guard from the
>   agent's punch-list. §4, the Zone-D half of §6, and §7 are retained below as a *ratified-in-waiting*
>   design: they describe what would take effect **if and only if** 1b is later adopted, and they
>   confer no authority today.
> - **§5 posture, ratified for any future 1b adoption:** AI-draft-permitted-behind-the-gate, rather
>   than a blanket AI-free rule for §5 files. `System.java` and `AccessController.java` remain
>   human-authored regardless. This records the risk posture; it does **not** activate Zone D.
> - **§5 applies today irrespective of AI**, because it is a standing engineering rule that predates
>   and outlives this policy.
>
> Where this document and [`SECURITY_MODEL.md`](SECURITY_MODEL.md) diverge on the trust model,
> `SECURITY_MODEL.md` is authoritative and this document is the bug.
>
> **Authorship note:** produced with AI assistance under the *Repository Documentation Exception*
> (repo-root developer `.md`, not a shipped build artefact), and amended at explicit Project Lead
> direction per the governance-document rule in [`CLAUDE.md`](CLAUDE.md).

---

## 1. Why this proposal exists

DirtyChai currently adopts the OpenJDK Interim Policy on Generative AI **in full**, repository-wide.
That was a deliberate, conservative choice — made to keep the door open for OpenJDK to incorporate
DirtyChai's work upstream. The cost of that choice, however, is **misallocated**:

- **The interim policy governs *outbound contributions to OpenJDK*, not the fork's private life.**
  Its stated rationale is the Oracle Contributor Agreement: a contributor must own and be able to
  grant Oracle unrestricted IP rights in each contribution, and AI output has unsettled IP status.
  That reasoning binds **what we send *to* OpenJDK** (PRs, JBS, mailing lists). It says nothing
  about code that never leaves the fork.

- **Most of DirtyChai's security core will never be upstreamed.** The revived River authorization
  model — `ConcurrentPolicyFile`, the `org.apache.river.api.security` contracts re-exported from
  `java.base`, SPIFFE/digest stamping, the `CombinerSecurityManager` whitelist strategy — is a
  *deliberate divergence* from the direction OpenJDK took when it removed the Security Manager.
  Blanket advise-only over that code buys **zero** upstream-ability: it can never be a contribution
  to OpenJDK, so the contribution-eligibility rationale simply does not apply to it.

- **Inbound ≠ outbound.** Cherry-picking or merging an upstream OpenJDK change *into* the fork is not
  a contribution *to* OpenJDK. The interim policy never restricted it. Blanket adoption swept it in
  anyway — and this matters because the dominant recurring cost of the fork is not the merge itself
  but *assessing the security impact of each merge*: re-adding the `doPrivileged` blocks and guard
  checks that SM-free upstream omits (§8). That assessment is pure analysis — the very use the interim
  policy most endorses — and is available *without any policy change*.

This proposal does two **separable** things: (1) it **clarifies** that inbound upstream-tracking is
already permitted under the existing policy — no partition required (§8); and (2) it **proposes** a
partition that additionally lets AI *originate* new code in the never-upstreamed divergent core
(Zone D — §4). The second is the bigger, more contentious step; the first stands on its own and is
the higher-value, lower-risk of the two.

---

## 2. Scope

- **Applies to:** the DirtyChai repository (the OpenJDK fork).
- **Does not apply to:** JGDMS, Rio, Blitz, Survey-zoot, or any other repository in this program.
  Those are not OpenJDK projects, are not bound by the OpenJDK Interim Policy, and are governed by
  normal engineering practice. They are mentioned here only to make the boundary explicit: the
  constraints below exist *because* DirtyChai is an OpenJDK fork that hopes to stay upstream-eligible
  in part. Where the same code matters across repos (e.g. the authorization contracts), the
  DirtyChai-side rules in this document govern the DirtyChai copy.

> **Standing recommendation (outside this policy's scope, recorded because the asymmetry is real).**
> The repositories excluded above carry, in practice, *more* AI-authored security code than DirtyChai
> does — JGDMS in particular, where a large fraction of recent trust-core work was agent-authored —
> and they have no AI policy at all. Being unbound by the OpenJDK Interim Policy removes the
> *upstream-eligibility* constraint; it does not remove the need for provenance and corroboration.
> Those repositories should adopt, at minimum, the §6 provenance-trailer discipline and a §5-style
> gate over their own trust cores. Nothing in this document imposes that — it is a recommendation to
> the Project Lead, not a rule.

---

## 3. The three distinctions the policy is built on

The policy is a function of three independent axes. Read them before the matrix in §4.

**Axis A — Direction: inbound vs outbound.**
*Outbound* = anything we submit to OpenJDK (PRs to `openjdk/jdk`, JBS issues, dev-list mail).
*Inbound/internal* = anything that lives only in the DirtyChai fork, including cherry-picks *from*
upstream. The interim policy's IP/OCA rationale applies to **outbound only**.

**Axis B — Provenance destiny: upstream-able vs divergent.**
*Upstream-able* = a change that could plausibly be offered to OpenJDK (bug fixes, performance,
virtual-thread work, `Subject`/`ScopedValue` evolution, anything not tied to the revived authz
model). *Divergent* = the permanently-forked security core OpenJDK will not take back. A change is
**upstream-able by default**; it is divergent only when it is clearly bound to fork-only machinery.
When in doubt, treat it as upstream-able (the conservative choice for eligibility).

> **Axis B is a prediction, not a property.** "Upstream-able" is a forecast about OpenJDK's future
> direction, made at authoring time with imperfect information. Forecasts fail: code classified
> divergent today may become genuinely upstream-able later (or a fix in divergent code may turn out
> to be a general one). Two consequences. First, the *when in doubt, upstream-able* default is
> load-bearing, not a formality — it is what makes a wrong guess cheap. Second, the §6 provenance
> ledger exists precisely because the classification is revisable: the standing `git log` query over
> §5 paths MUST be run **before any outbound submission and before any release**, so that a change
> whose classification has since changed is caught while a human rewrite is still possible rather
> than after it has been offered upstream.

**Axis C — Blast radius: security-critical vs ordinary.**
*Security-critical* = the silent-over-grant surface where a plausible-but-wrong change grants
authority that should have been denied. This axis is **orthogonal** to A and B: a change can be
divergent *and* security-critical (most of the authz core is), and the security gate in §5 applies
regardless of who or what wrote the code.

---

## 4. Engagement matrix

| | **Upstream-able (Axis B)** | **Divergent (Axis B)** |
|---|---|---|
| **Ordinary (Axis C)** | **Zone U — Advise-only.** AI may analyze, review, debug, explain, and describe required changes. Humans author all source, tests, JavaDoc, commit messages, and PR bodies. (= today's interim policy, scoped to where it matters.) | **Zone D — AI-permitted.** AI may draft and edit source, tests, and docs, subject to §6 provenance and §7 review. This is where AI *originates* new divergent-core code — distinct from inbound upstream-tracking, which is advise-only (§8). |
| **Security-critical (Axis C)** | **Zone U + §5 gate.** Advise-only *and* the security gate. | **Zone D + §5 gate.** AI may draft/propose, but the §5 gate (named human owner, differential + property tests, HC-1…HC-7) is mandatory before merge. AI-only merge is prohibited here. |

**Boundary rule.** Classify by Axis B first. If a change is even plausibly upstream-able, it is
Zone U — advise-only — to preserve OpenJDK contribution eligibility. Only changes clearly bound to
the divergent core are Zone D. Mixed changes split: the upstream-able hunks are Zone U (human-written),
the divergent hunks may be Zone D. Do not let a Zone-D edit smuggle an upstream-able change into
AI authorship.

---

## 5. The security-critical gate (applies in every zone)

Independent of AI involvement, changes to the silent-over-grant surface require human accountability.
This gate is **not** a consequence of the AI policy; it is a standing engineering rule that the AI
policy must not erode.

> **Authoritative source.** The trust model this gate protects — the invariants below, the
> multi-principal / subject model, content-addressed (digest) trust, SPIFFE stamping, and the
> security level of each surface — is defined in [`SECURITY_MODEL.md`](SECURITY_MODEL.md) (with the
> per-file security levels also tabulated in [`CLAUDE.md`](CLAUDE.md)). This section does **not**
> restate or override that model; it only names which AI activities the model's guarantees constrain.
> If the two ever diverge, `SECURITY_MODEL.md` is authoritative and this section is the bug.

**Files / surfaces in scope (non-exhaustive; canonical security levels in
[`SECURITY_MODEL.md`](SECURITY_MODEL.md) / [`CLAUDE.md`](CLAUDE.md); expand as the core grows):**

- `java/lang/System.java` — Security Manager installation (`trustedSMClass`, conditional validation)
- `java/security/AccessController.java` — privilege execution / `doPrivileged` semantics
- `au/zeus/jdk/authorization/sm/CombinerSecurityManager.java`
- `au/zeus/jdk/authorization/policy/ConcurrentPolicyFile.java` — grant matching / `implies`
- SPIFFE/digest stamping in `SecureClassLoader`, `DigestCodeSource`, `DigestGrant`
- `au/zeus/jdk/net/Uri.java` — RFC 3986 validation
- `au/zeus/jdk/authorization/guards/*Permission.java`

**Gate requirements (all mandatory):**

1. **Named human owner.** A specific human maintainer authors *or* takes ownership of, and is
   accountable for, the change. AI may draft; a human signs off on substance, not just formatting.
2. **Differential testing** against stock OpenJDK behaviour where applicable (does the change alter
   an externally observable security decision? prove which, and why intended).
3. **Property tests for the invariants**, re-run on every change: deny-by-default; null CodeSource ⇒
   unprivileged; conjunctive multi-principal grants (all listed principals present, every stack
   digest authorized, truncated at the nearest `doPrivileged`); fail-secure on validation error.
   Each invariant is stated authoritatively in [`SECURITY_MODEL.md`](SECURITY_MODEL.md); these tests
   exist to defend those statements, not to re-derive them.

   **Each such test MUST be demonstrated to be load-bearing.** A test is load-bearing only if it has
   been shown to **fail when its invariant is deliberately broken** — a negative control, recorded
   once per invariant (test name, the mutation applied, the observed failure). A test that passes
   whether or not the guard is present supplies **zero** corroboration, and a green suite of such
   tests is worse than no suite because it manufactures unearned confidence. This requirement is not
   hypothetical: the sibling JGDMS repository has produced at least two live instances of the failure
   mode — a `verify`-phase gate script that exits 0 when its analysis tool is unbuilt, and a jtreg
   configuration that reported `Passed` without ever running the test body. **Green is not evidence;
   a demonstrated failure on mutation is.** Where the corroboration side of §5 rests on tests, this
   clause is what makes that rest on anything at all.
4. **HC-1 … HC-7 preserved** (the existing Hard Constraints in CLAUDE.md). In particular: never add
   to `trustedSMClass()` without explicit human approval (HC-1); `equals()` not `instanceof` (HC-3);
   `@CallerSensitive` on privileged APIs (HC-4).
5. **No AI-only landing.** In Zone D + §5, AI may open the change and run the gate, but a human must
   approve before it lands on the integration branch. `System.java` and `AccessController.java`
   remain human-authored regardless.

> **Conceptual frame (why this shape).** This program treats *provenance as authority* and scores
> trust on two independent axes — **attestation strength × corroboration strength**. The codebase's
> own authorship is the same problem: *who wrote a line* (attestation: human vs AI, recorded by §6
> trailers) is independent of *whether it is correct* (corroboration: human review + property +
> differential tests). Weak attestation (AI-drafted) is acceptable in the core **only** when
> corroboration is strong (the §5 gate). Strong attestation (a senior human) still does not exempt a
> change from corroboration. The security gate is the corroboration layer for source code.

---

## 6. Provenance and attribution

DirtyChai's thesis is that lineage is a first-class, machine-checkable property. The AI policy eats
its own dog food: **every change carries honest provenance about how it was authored**, and that
provenance is what makes the partition auditable.

**Zone D (AI authorship permitted): trailers REQUIRED.**

- Each AI-assisted commit MUST carry a `Co-Authored-By:` trailer naming the model, plus a
  machine-readable role trailer, e.g.:

  ```
  Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
  AI-Assisted: model=claude-opus-4-8; role=drafted; zone=D
  ```

  `role` ∈ {`drafted`, `edited`, `reviewed`}. `zone` records the classification under §4.
- **The commit body MUST also record the Axis-B justification in one line** — why this change was
  classified divergent rather than upstream-able. Without it, §9's prohibition on silent
  reclassification is unenforceable: the trailer records *that* a change was called Zone D, never
  *why*, so a reclassification cannot be distinguished after the fact from a correct call. One line
  is enough; it is the difference between an auditable claim and an assertion.
- This **inverts** the current CLAUDE.md rule ("do NOT add `Co-Authored-By` for AI"). That rule is
  correct *under blanket advise-only*, where a trailer is evidence of a prohibited contribution.
  Under this policy, in Zone D where AI authorship is *permitted*, the trailer is required honesty,
  not a confession. The rule does not change — its precondition does.
- **Missing provenance is itself a defect.** AI-authored content in Zone D **without** the required
  trailer MUST be treated as a provenance violation and corrected before merge — not waved through
  because the authorship was permitted. Permission to author is not permission to author *silently*;
  an unrecorded Zone-D line is indistinguishable, to every later audit, from an undetected Zone-U
  violation, and it silently poisons the outbound-eligibility query in §3.
- **Detection procedure, reworded for the partition.** The existing "detecting AI-generated content
  → flag it immediately" rule assumes AI content is always prohibited. Under an adopted Zone D that
  is no longer true and a literal reading would flag legitimate work. The rule becomes: AI content in
  **Zone U or outbound** is a policy violation (flag per the existing procedure); AI content in
  **Zone D** is legitimate *if trailered* and a provenance defect *if not*. **Until 1b is adopted the
  original rule stands unchanged**, because there is no Zone D and all AI-authored content in the
  divergent core remains prohibited.

**Zone U (advise-only): trailers FORBIDDEN, because AI content is forbidden.**

- In Zone U there must be no AI-authored content, so an AI trailer there signals a policy violation
  and MUST be treated as one (flag to the contributor and Project Lead, per the existing detection
  procedure). The prohibition on AI trailers is retained *for Zone U / outbound* exactly as today.

**Outbound to OpenJDK: human-only, affirmatively.**

- No outbound contribution may contain AI-generated content, and each carries the existing PR
  compliance affirmation. The point of the §6 ledger is to make it *cheap to prove* a given outbound
  patch is clean: a change with any Zone-D provenance in its history is ineligible for outbound
  submission without a human rewrite.

**Inbound merges: no AI authorship trailer (because there is none).**

- An inbound merge/cherry-pick from upstream introduces no AI-authored content: the merged lines are
  upstream's human-authored work, and git preserves their original `Author:`. The agent is the
  *committer/applier*, not the author. A `Co-Authored-By: <AI>` trailer here would assert authorship
  that did not occur — it is therefore **wrong**, not required. To record that an agent ran the
  mechanical merge, use a committer/tooling note (e.g. an optional `Merged-by:` line), never
  `Co-Authored-By:`. Human-authored conflict resolutions are attributed to the human who wrote them.
  See §8.

**Auditability.** Because provenance lives in trailers, `git log` over the security-critical paths
reconstructs which lines have AI provenance — a standing query the security team can run before any
upstream submission or release.

---

## 7. Reviewer burden (the interim policy's first concern)

The interim policy's leading worry is reviewer burden: AI makes it cheap to produce large volumes of
plausible-looking, hard-to-review code. This policy answers that directly rather than ignoring it:

- **The dominant AI use *reduces* reviewer burden, not increases it.** The major recurring task is the
  Phase-2 merge security-impact assessment (§8): it turns "read the whole merged diff against the
  trust model by hand" into "review a targeted punch-list of missing `doPrivileged`/guards." That is
  analysis, not generation — the interim policy's own preferred use of AI.
- **Scope discipline carries over.** AI changes follow the smallest-change rule; no opportunistic
  refactoring of adjacent code (existing FM-6).
- **Tests are the price of AI authorship in the core.** In Zone D + §5, the burden shifts from
  "review every line by eye" to "review the invariants and read the property/differential tests."
  A change that cannot be covered by such tests is, by that fact, not a good candidate for AI
  authorship in the core.
- **Volume cap by review capacity, not generation capacity.** AI origination in the divergent core
  (§8) is throttled to what humans can actually corroborate; unreviewed Zone-D backlog is a smell,
  logged, not landed.

---

## 8. Agent-assisted maintenance — the real cost is merge security-impact analysis

The dominant, recurring cost of maintaining DirtyChai is **not** applying upstream merges, and it is
**not** the authorization architecture itself (that was a comparatively simple, largely one-time
effort). It is **assessing the security impact of every upstream merge, and repairing it** — because
upstream OpenJDK has removed the Security Manager and is increasingly written with no awareness of
permission checks or privilege. Each merge therefore tends to introduce code that, under DirtyChai's
restored authorization model, is **missing a `doPrivileged` block** (a legitimate JDK operation gets
needlessly denied when an under-privileged frame sits deeper on the stack) or **missing a guard
check** (a security-sensitive operation runs unmediated — a hole). Re-adding, on every merge, what
upstream deleted is the treadmill.

This is *good news* for AI engagement, because the work splits cleanly along the authored/analysed
line — and the expensive part is the analysed part.

**Phase 1 — Apply the merge (mechanical; advise-only; authors nothing).**
The unit of work is **one upstream build tag** (`jdk-NN+B` → `jdk-NN+B+1`), not master-tip or an
arbitrary commit range. Each tag is an already-CI-validated integration point, so a tag-to-tag merge
is a coherent, pre-tested, bounded delta — and advancing one tag at a time keeps a proper *advancing
merge base*, which holds conflicts down to genuine divergence. (Skipping ahead to a far commit
manufactures spurious context-drift conflicts that are not real divergence — so the tag cadence is a
correctness property of the merge, not just a convenience.) The agent merges to the next tag, builds,
runs tests, reports. Merged lines keep upstream's `Author:`; the agent is committer, not author; no AI
authorship trailer (§6). Conflicts → the agent reports and a human authors the reconciling edit.
*(committer ≠ author; running `git` is not generating content — see §6.)*

**Phase 2 — Security-impact assessment (the major task; advise-only; AI's strongest fit).**
For each tag delta, the agent reviews every merged change against [`SECURITY_MODEL.md`](SECURITY_MODEL.md)
— using the operation→guard/`doPrivileged` catalog in
[`MERGE_SECURITY_ASSESSMENT_RUBRIC.md`](MERGE_SECURITY_ASSESSMENT_RUBRIC.md) — and produces a precise
punch-list scoped to that tag (bounded to a human-reviewable size; one audit record per tag —
`assessed: current to jdk-NN+B`):
- **Privileged operations now needing `doPrivileged`** — merged code performs an action that must
  succeed for the JDK to function but would be denied under stack-based permission intersection if any
  deeper frame is under-privileged. Identify the operation, the narrowest privilege it needs, and
  where the block belongs (placement rule: authority decisions on the live stack; `doPrivileged` only
  for narrow local mechanics).
- **Security-sensitive operations now needing a guard** — file / network / native / reflection /
  class-load / serialization / property access that upstream performs with no permission check because
  the SM is gone. Name the operation, the guard/permission that should mediate it, and the call sites.
  Includes **native-backed VM control/monitoring** ops whose only viable gate is a Java-side check
  (generally `ManagementPermission`), since the privileged action itself happens in native code.
- **Behavioural deltas on a §5 surface** — upstream changed a security-relevant decision.
- **Removed or weakened mediation** — a *deleted* `checkPermission`/`doPrivileged`, or a changed
  permission/AC class (the Security-Manager-removal direction). Scan the diff's `-` lines, not just
  `+`: a removal in a file DirtyChai did not fork **auto-merges silently** and strips a guard with no
  flag — the highest-priority case (rubric Catalog R).

This phase is **pure analysis/review** — precisely what the interim policy says AI is *best* at and
explicitly permits ("analysis of existing code … is where generative AI tools shine"). It is also the
phase that consumes the most human time today, because it requires holding the entire trust model and
the whole merged diff in view at once. An agent doing this assessment — and only this — is the single
highest-leverage use of AI on the project, and it needs **no policy change**: it produces a report,
not code.

**Phase 3 — Remediation: author the `doPrivileged` blocks and guards (Zone-D + §5).**
This is the authored, security-critical part. The added blocks and guards are *divergent* (OpenJDK
removed the SM and will not take guard checks back) **and** security-critical (they are the
authorization mechanism itself) — the archetypal **Zone-D + §5** work, the most-gated cell in §4.
- **Under current policy / (1a) only:** a human authors every `doPrivileged` block and guard from the
  agent's Phase-2 punch-list. AI does not write them.
- **Under (1b) / Zone D:** the agent may *draft* them behind the full §5 gate (named human owner +
  differential + property tests + no AI-only landing) and with §6 provenance. Drafting from a precise,
  human-reviewed punch-list is a far narrower and more checkable task than open-ended generation —
  which is what makes AI drafting tolerable in the core at all.

**Why this reweights the partition decision.** Most of the value lives in Phase 2, which is available
today under advise-only — so adopting (1a) alone captures the bulk of the benefit. (1b) changes only
*who first drafts* the Phase-3 edits; the human accountability, tests, and §5 gate are identical
either way. The architecture work the partition might once have seemed aimed at is largely done; the
standing cost it actually addresses is the Phase-2/3 merge treadmill.

**Partition maintenance (optional, only if Zone D is adopted).** Consider physically separating the
tree so the boundary is mechanical, not judgemental: an agent-touchable divergent core vs a
human-written upstream-able subset, so classification (§4) is by location, not per-change argument.

---

## 9. Hard prohibitions (even in Zone D)

These hold regardless of zone or authorship:

- **No AI-only change to a §5 security-critical surface.** Human owner + gate required.
- **No weakening of an invariant**: deny-by-default, null-CodeSource-unprivileged, conjunctive
  multi-principal evaluation, fail-secure-on-error, the HC-1…HC-7 constraints.
- **No addition to `trustedSMClass()` by AI** under any circumstances (HC-1).
- **No AI content in any outbound OpenJDK submission**, and no submission of code with Zone-D
  provenance in its history without a clean human rewrite.
- **No silent reclassification** of an upstream-able change into Zone D to enable AI authorship.
  Enforced by the one-line Axis-B justification required in the commit body (§6): a reclassification
  that cannot be justified in writing at authoring time is one that should not be made.

---

## 10. Ratification record

Ratified 2026-07-31 by the Project Lead. Status of each decision:

| # | Decision | Outcome |
|---|---|---|
| 1a | Inbound upstream-tracking + Phase-2 merge assessment permitted (§8) | **ADOPTED — in force** |
| 1b | Zone-D partition: AI may originate divergent-core code (§4) | **NOT adopted** — divergent core stays advise-only; §4/§7/Zone-D §6 are ratified-in-waiting only |
| 2 | Where the Axis-B line falls | **Open** — only bites if 1b is adopted; the §10.2 seed below stands as the proposal |
| 3 | Security-critical posture | **Ratified: AI-draft-permitted-behind-the-§5-gate** (not fully AI-free). Records the posture for a future 1b; does not activate Zone D. `System.java` / `AccessController.java` human-authored regardless |
| 4 | Provenance trailer schema | **Open** — only bites if 1b is adopted; schema in §6 stands as the proposal |
| 5 | IP posture for Zone D | **Not yet accepted** — required before 1b can be adopted, not before 1a |
| 6 | Update operative files | **Done 2026-07-31** — see §11 |

**What changed in force on ratification:** only decision 1a, which *clarifies* the existing policy
rather than relaxing it. No new authority to author code was granted anywhere. Adopting 1b later
requires ratifying decisions 2, 4 and 5 first.

The original text of the judgement calls is retained below, since 2, 4 and 5 remain open:

1. **Two separable decisions, smallest first:**
   - **(1a) Clarify that inbound upstream-tracking + merge security-impact assessment is permitted
     (§8)?** Needs no partition: an agent may perform the mechanical git operations of an inbound
     merge (result is upstream-authored), advise on conflicts (a human authors them), and — most
     valuably — produce the Phase-2 security-impact punch-list (missing `doPrivileged`/guards) as
     analysis. This captures the bulk of the achievable benefit, since assessment is the dominant
     cost. Low-risk, high-value; adoptable on its own; the recommended minimum.
   - **(1b) Adopt the Zone-D partition (§4)?** The bigger step: let AI *originate* new code in the
     divergent core. Or keep blanket advise-only there (status quo) for simplicity. You can take
     (1a) without (1b).
2. **Where exactly is the Axis-B line?** A concrete file/package list for "divergent core" makes §4
   mechanical. Proposed seed: everything under `au/zeus/jdk/authorization/**` plus the
   fork's edits to `System.java`/`AccessController.java`/`Subject.java` is divergent; the rest is
   upstream-able by default.
3. **Security-critical core: AI-draft-permitted-with-gate (this draft) vs fully AI-free?** The draft
   permits AI drafting behind the §5 gate. A stricter alternative bars AI from §5 files entirely,
   even drafting. Choose the risk posture.
4. **Provenance trailer format** — confirm the `AI-Assisted:` trailer schema (or substitute an
   existing convention) so tooling can parse it.
5. **IP posture for Zone D.** The interim policy flags AI-output IP as unsettled (active litigation).
   The fork's divergent core ships under OpenJDK's GPLv2+CE and is never offered to Oracle, so the
   OCA concern does not apply — but the project must affirmatively accept the residual,
   unsettled-IP risk for Zone-D code. Confirm.
6. **Update the operative files on adoption** — fold the ratified rules into `CLAUDE.md`, supersede
   the blanket-adoption language in `openjdk_ai_policy.md` with a pointer to this policy for
   internal/inbound work (retaining the verbatim interim text for outbound), and add this file to
   the documentation-exception list.

---

## 11. Status & history

| Version | Date | Status | Notes |
|---|---|---|---|
| 0.1-draft | (unset) | DRAFT — not in force | Initial proposal. AI-assisted under the Repository Documentation Exception. Awaiting human review/ratification. |
| 1.0 | 2026-07-31 | **PARTIALLY ADOPTED** | Decision 1a adopted (§8 Phase 1+2 in force). 1b NOT adopted — divergent core remains advise-only. §5 posture ratified for a future 1b. Amendments this revision: load-bearing/negative-control requirement on §5 property tests; Zone-D missing-provenance treated as a defect and detection procedure reworded; one-line Axis-B justification required in commit bodies (makes §9 enforceable); Axis B documented as a revisable prediction with the §6 query bound to submission/release; standing recommendation recorded for the unbound sibling repositories (§2). |

**§10.6 rollout performed 2026-07-31:**
- `CLAUDE.md` — decision table and policy notice updated to record that inbound merges and Phase-2
  security-impact assessment are permitted, and that Zone D is not adopted.
- `openjdk_ai_policy.md` — a DirtyChai adoption preamble now points here for internal/inbound work.
  **The verbatim OpenJDK Interim Policy text below that preamble is unmodified**, per the
  governance rule that this file tracks its external upstream source rather than being rewritten.
- The file was additionally renamed from `‎openjdk_ai_policy.md` to `openjdk_ai_policy.md`: the
  original name carried a leading invisible U+200E LEFT-TO-RIGHT MARK, so every markdown link to it
  in this document and in `CLAUDE.md` — all of which spell the clean name — was silently broken, and
  any name-matching tooling would have mismatched without error.

Governing documents: this policy for internal/inbound work, [`openjdk_ai_policy.md`](openjdk_ai_policy.md)
for outbound contributions to OpenJDK, and [`CLAUDE.md`](CLAUDE.md) for day-to-day agent operation.
Where they conflict on the trust model, [`SECURITY_MODEL.md`](SECURITY_MODEL.md) is authoritative.
