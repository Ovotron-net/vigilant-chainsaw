# Security Policy

## Responsible use

Operate this monitor only on networks and systems you own or are explicitly authorized to inspect. The default implementation records packet metadata and does not persist payloads.

## Reporting vulnerabilities

Do not publish exploit details in a public issue. Use a private security advisory in the GitHub repository or contact the repository owner through an agreed private channel.

## Operational recommendations

- Bind health and metrics endpoints to localhost or a protected management network.
- Keep webhook URLs in environment variables or a secrets manager.
- Limit the service to `CAP_NET_RAW`; grant `CAP_NET_ADMIN` only where required.
- Protect event logs because IP addresses and connection metadata can be sensitive.
- Test firewall rules using `nft --check` and maintain out-of-band access.
