# Useful-Commands

Personal reference collection — commands and queries worth keeping, documented
well enough to be reused months later without re-deriving them.

## Contents

| Path | What's in it |
| --- | --- |
| [Grafana/KQL/](Grafana/KQL/) | Kusto (KQL) queries for investigating suspicious traffic in Azure App Service HTTP logs — suspicious-IP triage, request timelines, write/upload hunting, webshell checks. Runs in Log Analytics, Grafana (Azure Monitor datasource), or `az monitor log-analytics query`. |

## Conventions

- One directory per tool or platform.
- Each directory has a `README.md` explaining what the commands do, when to
  reach for them, and **which parts to change** to adapt them.
- Runnable files live next to the docs (e.g. `KQL/queries/*.kql`) so they can be
  copy-pasted or `cat`'d directly, and each carries its own header comment.
- Prefix filenames with a number when order matters.
