# DraFRP implementation and validation record

Status: active implementation. Design documents describe intended behavior; they are not evidence of completed features.

## Work areas

| Area | Owner | Evidence / status |
| --- | --- | --- |
| Shared contracts, integration, environment, release validation | root | Go model and API contract created; tests pending |
| Cloud API, MySQL, optional Redis/memory, business authorization | cloud agent | In progress |
| Edge/client, independent transport, TCP/UDP/HTTP forwarding | transport agent | In progress |
| React/TypeScript/MUI console and embed integration | frontend agent | In progress |
| Linux TUN native source identity | root | Not implemented or verified; strict rules must fail closed |

## Acceptance evidence

No completed runtime validations yet. Record commands, actual results and limitations as each integration check completes. Never equate a connected carrier with target health, persisted configuration with applied state, or an installed TUN interface with source identity support.

Three binaries are required. MySQL is mandatory for cloud. Redis is optional and must degrade only temporary storage. No concrete ACL templates or region lists are preloaded. No PROXY v2 headers are prepended to application streams.
