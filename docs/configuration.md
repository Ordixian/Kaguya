# Configuration

Everything has a built-in default; `config/config.yaml` just exposes the
common knobs. Environment overrides (handy in containers):
`CS_API_HOST`, `CS_API_PORT`, `CS_TIER`, `CS_DATABASE`.

## Tiers (planned)

Tier limits (retention, max events) are read from `tier:` in `config/config.yaml` or `CS_TIER`. Only the free **community** tier is implemented today; the table below is a **planned** roadmap, not shipped behaviour.

| | **Community** (free) | **Pro** | **Enterprise** |
|--|--|--|--|
| Hosts | 1 | 25 | unlimited |
| Retention | 7 days | 90 days | 365 days |
| Max events | 100k | 5M | unlimited |
| Collectors | all | all | all |
| Detection engine | full | full | full |

## Docker

```bash
docker compose up --build
```

`docker-compose.yml` uses `network_mode: host` and `pid: host` so collectors
see the real host (drop these for a sandboxed, container-only view), and
mounts `/var/log` read-only for auth-log collection.
