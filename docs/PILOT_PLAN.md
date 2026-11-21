# iDO controlled pilot plan

## Pilot objective

Validate that iDO can safely prepare, reconcile, explain exceptions, and route decisions for a narrow, representative process before broader adoption. The pilot is for a local controlled environment, not an internet-facing production service.

## Scope

- One finance or operations team, one named process, and one to three data owners.
- Two source exports for a selected bank-to-ledger or equivalent reconciliation.
- Analysts, at least one independent approver, and one administrator.
- Synthetic or explicitly approved data; no automatic posting of entries into a ledger.
- Daily/weekly automation only against reviewed workflows and fixed imported snapshots.

## Readiness gates

1. **Governance:** name sponsor, process owner, data owner, approver, and incident contact; approve the draft handling policy.
2. **Environment:** install locally, restrict the host account, enable disk encryption, keep the listener on localhost, and document backup and recovery steps.
3. **Configuration:** approve source definitions, column mappings, amount/date rules, duplicate policy, and exception ownership. Save a versioned workflow name.
4. **Baseline:** compare at least two prior periods manually. Record source row counts, known matches, known exceptions, time spent, and reviewer corrections.
5. **Training:** rehearse import preview, invalid row handling, matching, exception investigation, approvals, audit history, exports, and automation recovery.

## Six-week schedule

- **Week 1 — Setup:** confirm controls, install, users, policy, and synthetic-data dry run.
- **Week 2 — Mapping:** prepare sample exports, agree mappings and tolerances, and approve a workflow.
- **Weeks 3–4 — Shadow operation:** run alongside the existing process; do not replace books or payment controls. Compare outcomes and classify every material difference.
- **Week 5 — Controlled automation:** enable schedules only for the reviewed workflow and imported snapshot; require approval for each scheduled run.
- **Week 6 — Evaluation:** review metrics, incidents, reviewer feedback, operational costs, and gaps; decide to stop, extend, or prepare a separate production-readiness phase.

## Measures and proposed exit criteria

- At least 3 representative periods reconciled in shadow mode.
- 100% of rejected approvals have a reason and every completed approval identifies a different reviewer from the requester.
- 100% of high-value or material exceptions have an assigned disposition.
- Match precision is measured from reviewer-confirmed matches; do not use raw match rate as an accuracy claim.
- Every invalid import row is explained, and the team signs off on skipped-row treatment before dataset save.
- No unresolved critical security or data-loss issue; backup restore and run/audit export are demonstrated.
- Process owner documents time saved, remaining manual work, and go/no-go recommendation.

## Pilot controls and stop conditions

Pause the pilot on unexplained source omissions, a suspected unauthorized disclosure, missing audit or approval records, repeated unexplained automation failures, a material false match, or inability to restore the local data backup. Continue the existing approved reconciliation process until the issue is understood and the sponsor authorizes resumption.

## Production transition is separate

A successful pilot does not authorize cloud or production use. Before that phase, plan and independently review HTTPS, managed secrets, MFA, tenant/workspace isolation, PostgreSQL and migration strategy, access and retention enforcement, monitored backups, observability, incident response, deployment hardening, performance, accessibility, and security testing.
