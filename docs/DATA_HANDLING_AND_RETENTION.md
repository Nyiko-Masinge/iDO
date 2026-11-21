# iDO data handling and retention policy (pilot draft)

**Status:** Draft for pilot review. The organization operating the pilot must approve this policy, assign a data owner, and validate applicable legal and regulatory requirements before using live financial or personal data.

## Data categories and purpose

iDO may store imported financial or operational rows, column names, file names, reconciliation results, reviewer feedback, approval comments, automation run details, user account identifiers, and audit events. The data is used only to prepare and reconcile the selected sources, investigate exceptions, support approvals, produce reports, and trace user actions.

## Collection and minimization

- Import only the columns and accounting periods needed for the reconciliation.
- Use the import preview to exclude unnecessary fields and correct destination column names.
- Do not import passwords, access tokens, or unrelated personal data into source files.
- Use named individual accounts and the lowest role that permits the person's task.

## Storage and access

During the local pilot, application data is stored in the local `data` directory and SQLite database. Access is controlled through application roles and the local operating-system account. Keep the server bound to localhost, protect the computer with disk encryption and a screen lock, and do not copy the data directory to consumer cloud storage without approval. Backups contain the same sensitive data and require equivalent protection.

## Retention proposal

- Temporary import previews: automatically removed after 24 hours.
- Pilot datasets, run results, feedback, approvals, and audit events: retain only for the period approved by the data owner; proposed pilot default is 90 days after pilot close, then securely delete or de-identify them.
- Backups: proposed maximum rolling retention of 30 days after the corresponding live data is deleted.
- Legal hold, dispute, or statutory requirements override the proposed schedule only when documented by the responsible organization.

**Implementation note:** the application currently expires import staging after 24 hours. It does not yet enforce deletion of saved datasets, runs, approvals, audit history, or backups. Until automated retention and deletion are implemented, the data owner must apply an approved manual retention procedure and document each deletion.

## Data subject, correction, and incident requests

Route access, correction, export, deletion, or suspected exposure requests to the designated pilot data owner and security contact. Preserve relevant records while investigating an incident; restrict access, stop the local service if needed, retain incident facts, and follow the organization's incident response and notification process.

## Approval checklist before live data

- Confirm lawful purpose and data owner.
- Approve allowed fields, users, retention period, and backup location.
- Verify workstation encryption and access controls.
- Review the current security limitations and obtain an independent security review.
- Record approval date, approver, and review date for this policy.
