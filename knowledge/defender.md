<!-- Generic sheet. Replace it with the real inventory of your tenant via
     scripts/generate_knowledge.py. -->
Microsoft Defender tables (Advanced Hunting). The time column is `Timestamp`.
The API only returns the last 30 days: every query must carry its own time
filter (`where Timestamp > ago(30d)`).

- `DeviceProcessEvents`: process creations. `DeviceName`, `AccountName`,
  `FileName`, `ProcessCommandLine`, `SHA256`, `SHA1`, `MD5`,
  `InitiatingProcessFileName`, `InitiatingProcessCommandLine`.
- `DeviceNetworkEvents`: network connections. `RemoteIP`, `RemoteUrl`, `RemotePort`,
  `InitiatingProcessFileName`.
- `DeviceFileEvents`: file operations. `FileName`, `FolderPath`, `SHA256`,
  `ActionType`.
- `DeviceRegistryEvents`: registry. `RegistryKey`, `RegistryValueName`,
  `RegistryValueData`.
- `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents`: as needed.
- `AlertInfo` / `AlertEvidence`: alerts and associated entities.

Hashes exist as `MD5`, `SHA1` and `SHA256`: compare each hash against the column
of its algorithm, and cover all three in the same query when needed.
