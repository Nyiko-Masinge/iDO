# iDO onboarding guide

## Purpose

iDO helps finance and operations teams compare two datasets, identify likely matches, review exceptions, request independent approval, and retain an activity record. This guide describes the local pilot workflow; it is not a production security certification.

## Before the first run

1. Install the supported Python version and start iDO using the repository README.
2. Keep the service bound to `127.0.0.1`; do not expose this pilot server to a LAN or the public internet.
3. Sign in with the bootstrap administrator, change the bootstrap password using the supported account flow, and create named accounts for each participant.
4. Assign the least privilege role needed: analyst for imports and reconciliation, approver for independent approval, viewer for read-only review, admin for local administration.
5. Agree which source exports, accounting period, owner, and reviewer will be used. Use synthetic or approved pilot data until the organization has approved data handling.

## Standard reconciliation cycle

1. Open **Data imports**, name the source, and select a CSV or XLSX file.
2. Review the preview, sample rows, and invalid-row explanations. Rename destination fields to a consistent naming scheme or leave a destination field blank to exclude it. Confirm that skipped-row counts are acceptable.
3. Save the prepared dataset. Repeat for the second source.
4. Open **Reconciliation**, select both datasets, map corresponding keys, and configure amount tolerance and any date, duplicate, or partial-match controls. Save a workflow only after a reviewer confirms the mapping.
5. Run the reconciliation. Review exception categories and source rows. Do not approve a run while material exceptions remain unexplained.
6. Request approval. An approver other than the requester records the decision. Rejections require a reason.
7. Review the approval and audit history; export run or exception detail if needed.

## Roles and responsibilities

- **Analyst:** prepares imports, configures and runs reconciliations, investigates exceptions, and requests approval.
- **Approver:** independently reviews results and records approval or a reasoned rejection.
- **Viewer:** reviews available reports and outcomes without changing them.
- **Admin:** manages local accounts and workspace setup; should not replace independent approval controls.

## Support and recovery

- Keep a dated backup of the local `data` directory while the application is stopped.
- Record the application version, workflow name, dataset source period, and run ID when escalating an issue. Do not attach real financial records to an unsecured support message.
- If an import preview expires, upload the source again and repeat the preview. An expired preview is not a saved dataset.
- If the server reports an automation failure, open **Automation → Execution history** and capture its failure code and details.
