<!-- Generic sheet. Replace it with the real inventory of your tenant via
     scripts/generate_knowledge.py. -->
UDM search on Google SecOps. Events are normalized: each event carries a
`metadata.event_type` and entity names (principal, target, src).

- `PROCESS_LAUNCH`: `principal.hostname`, `principal.user.userid`,
  `target.process.file.full_path`, `target.process.command_line`,
  `target.process.file.sha256`.
- `NETWORK_CONNECTION`: `principal.ip`, `target.ip`, `target.port`,
  `network.application_protocol`.
- `NETWORK_DNS`: `network.dns.questions.name`.
- `NETWORK_HTTP`: `network.http.method`, `target.url`.
- `FILE_CREATION` / `FILE_MODIFICATION`: `target.file.full_path`,
  `target.file.sha256`.
- `USER_LOGIN`: `principal.user.userid`, `principal.ip`, `security_result.action`.

Filter first by `metadata.event_type` or `metadata.log_type`. Field availability
depends on the log types actually ingested in your environment: check your inventory.
