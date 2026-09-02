<!-- Generic reference sheet. Replace it with the real inventory of your workspace via
     scripts/generate_knowledge.py, so the agent only targets tables and columns that
     exist in your environment. -->
Common Log Analytics tables carrying Microsoft Sentinel, with their key columns.
The time column is always `TimeGenerated`.

**Identity and authentication**

- `SigninLogs`: Entra ID interactive sign-ins. Columns: `UserPrincipalName`,
  `IPAddress`, `AppDisplayName`, `ResultType` (0 = success), `Location`, `DeviceDetail`.
  Non-interactive sign-ins are in `AADNonInteractiveUserSignInLogs`, service ones in
  `AADServicePrincipalSignInLogs`.
- `AuditLogs`: directory changes. Columns: `OperationName`, `InitiatedBy`,
  `TargetResources`.

**Workstations and servers (if ingested)**

- `SecurityEvent`: Windows logs. Columns: `EventID`, `Account`, `Computer`,
  `CommandLine`, `LogonType`. Useful EventIDs: 4624/4625, 4672, 4688, 4720, 7045.
- `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`: if the Defender
  tables are exported to Sentinel.

**Network and proxy**

- `CommonSecurityLog` (CEF), `DnsEvents`, `W3CIISLog` depending on the active connectors.

Note: table availability depends on each tenant's connectors. Check your real
inventory before concluding that data is missing.
