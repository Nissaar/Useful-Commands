# KQL — Azure App Service HTTP log investigation

Kusto (KQL) queries for investigating suspicious traffic in `AppServiceHTTPLogs`
(Azure App Service access logs shipped to a Log Analytics workspace).

Runnable copies live in [queries/](queries/) — each file is self-contained and
carries its own header comment, so you can open one and paste it straight into
Log Analytics or a Grafana panel. This README is the map: what each query is
for, the order to run them in, and every knob worth turning.

## Where to run these

| Target | Notes |
| --- | --- |
| **Azure Portal** → Log Analytics workspace → *Logs* | Paste as-is. Watch the time-picker: it ANDs with your `where TimeGenerated` clause, so set it to a range that contains your window or you get an empty result. |
| **Azure Portal** → App Service → *Logs* | Same, scoped to the one app — drop any `CsHost` filter. |
| **Grafana** (Azure Monitor datasource) | Paste as-is, or parameterise — see [Grafana usage](#grafana-usage). |
| `az monitor log-analytics query` | `az monitor log-analytics query -w <workspace-id> --analytics-query "$(cat queries/01-suspicious-ips-summary.kql)" -o table` |

Prerequisite: App Service diagnostic setting must send **HTTPLogs** to the
workspace. No diagnostic setting, no `AppServiceHTTPLogs` table.

## The workflow

The queries are meant to be run in order — each narrows the field for the next.

```
01  suspicious-ips-summary     7 days, all IPs      →  gives you IPs + timestamps
     │
     ├── 02  request-timeline-window     20 min, everything      →  reads the story
     ├── 03  writes-in-window            20 min, POST/PUT only   →  what could change
     └── 06  wordpress-activity-window   15 min → widen          →  what they did

04  php-upload-probes           7 days, standing hygiene check
05  timestamp-timezone-check    diagnostic — run when a window comes back empty
```

| # | File | Answers |
| --- | --- | --- |
| 01 | [01-suspicious-ips-summary.kql](queries/01-suspicious-ips-summary.kql) | Which IPs are behaving abnormally, and when? |
| 02 | [02-request-timeline-window.kql](queries/02-request-timeline-window.kql) | What exactly happened, request by request? |
| 03 | [03-writes-in-window.kql](queries/03-writes-in-window.kql) | Did anything try to write/upload? Did it succeed? |
| 04 | [04-php-upload-probes.kql](queries/04-php-upload-probes.kql) | Is there a webshell in the upload directories? |
| 05 | [05-timestamp-timezone-check.kql](queries/05-timestamp-timezone-check.kql) | Are my timestamps UTC or local? |
| 06 | [06-wordpress-activity-window.kql](queries/06-wordpress-activity-window.kql) | What did they touch on wp-admin / wp-content? |

## Field reference — `AppServiceHTTPLogs`

The columns these queries use, plus the ones worth adding.

| Column | Meaning | Investigation value |
| --- | --- | --- |
| `TimeGenerated` | Request timestamp, **UTC** | Every window filter. See [timezones](#timezones-the-trap). |
| `CIp` | Client IP | The actor. Note: behind a CDN/WAF this may be the proxy — check `X-Forwarded-For` if you log it. |
| `CsMethod` | HTTP verb | `POST`/`PUT` = can change state. |
| `CsUriStem` | Path, no query string | What was targeted. |
| `CsUriQuery` | Query string | Where SQLi / LFI / traversal payloads show up. |
| `ScStatus` | HTTP status returned | `200` on an attack path = bad news. `404` = probing. `401`/`403` = blocked. |
| `CsBytes` | **Request** bytes (inbound) | Large value on a `POST` = file upload. |
| `ScBytes` | **Response** bytes (outbound) | Large value = data leaving. Exfiltration signal. |
| `UserAgent` | Client UA | `curl`, `python-requests`, `sqlmap`, `Go-http-client`, empty = tooling, not a browser. |
| `TimeTaken` | Duration, ms | Outliers = expensive endpoint, or a blind-injection time delay. |
| `CsHost` | Host header | Filter when several hostnames share one app. |
| `Referer` | Referrer | Absent on scripted requests. |
| `Cookie` | Request cookies | Session correlation; **contains secrets — handle carefully.** |
| `Result` | `Success` / `Failed` | Quick coarse filter. |
| `ComputerName` | Serving instance | Which instance on a scaled-out plan. |

Not sure what a column holds? Run:

```kql
AppServiceHTTPLogs | take 5
```

## Tunables — what to change and how

### The time window

Two forms are used, and they are not interchangeable.

```kql
| where TimeGenerated > ago(7d)        // relative — sweeps, dashboards, standing checks
| where TimeGenerated between (datetime(2026-09-02 00:05) .. datetime(2026-09-02 00:25))
                                       // absolute — a specific incident
```

- `ago()` accepts `30m`, `6h`, `1d`, `7d`, `30d`.
- `datetime()` accepts `2026-09-02`, `2026-09-02 00:05`, `2026-09-02 00:05:30`,
  and ISO `2026-09-02T00:05:30Z`. **Unqualified values are UTC.**
- Absolute windows are inclusive on both bounds.
- Match window size to query shape: **aggregated** queries (01, 04) tolerate
  days; **per-request** queries (02, 03, 06) should start at 15–30 minutes or
  you drown in rows. Widen only once you know what you're following.

Retention caps your lookback — the workspace default is 30 days unless someone
raised it. `ago(90d)` against a 30-day workspace returns 30 days, silently.

### The noise floor (query 01)

```kql
| where posts > 5 or erreurs > 30
```

These thresholds are the only part of query 01 that is site-specific, and the
defaults suit a low-traffic site. Calibrate rather than guess: comment the line
out, look at the distribution of `posts` and `erreurs` for your normal traffic,
and set the cut just above it.

- **Busy site / drowning in rows** → raise (`posts > 50 or erreurs > 500`).
- **Quiet site / seeing nothing** → lower (`posts > 0 or erreurs > 5`).
- **Change what "abnormal" means** → the `urls` column is often the sharpest
  signal: `| where urls > 100` catches scanners doing wide path fan-out even
  when they keep their request count polite.

Reorder results with `sort by`: `posts desc` (write attempts first),
`erreurs desc` (brute-force / scanning first), `urls desc` (widest scanners
first), `requetes desc` (sheer volume first).

### Path filters

`contains` is a case-insensitive substring match — convenient, and the right
default here. Sharper alternatives when you need them:

| Operator | Use when |
| --- | --- |
| `contains "/wp-admin/"` | Substring anywhere. Case-insensitive. Default choice. |
| `startswith "/api/"` | Anchored at the start — faster, fewer false hits. |
| `endswith ".php"` | Extension match. |
| `has "admin"` | Whole-token match — indexed, so faster than `contains`, but won't match inside a longer word. |
| `== "/wp-login.php"` | Exact path. |
| `in ("/a", "/b")` | Exact, several values. |
| `matches regex @"\.(php\|asp\|jsp)$"` | Several extensions at once. Slowest — use last. |
| `!contains "/assets/"` | Exclude known-noisy paths. |

Common targets to swap in for non-WordPress apps: `/admin/`, `/api/`,
`/actuator/`, `/.env`, `/.git/`, `/phpmyadmin/`, `/xmlrpc.php`,
`/.well-known/`, `/config`, `/backup`.

### Operator precedence — the mistake that bites

KQL binds `and` tighter than `or`, exactly like most languages. So this:

```kql
| where CIp == "1.2.3.4" and CsUriStem contains "/wp-admin/" or CsMethod == "POST"
```

reads as `(CIp and wp-admin) or (POST)` — it returns **every** POST from every
IP on the internet. Either parenthesise:

```kql
| where CIp == "1.2.3.4" and (CsUriStem contains "/wp-admin/" or CsMethod == "POST")
```

or, clearer, use a separate pipe stage — successive `| where` stages are ANDed:

```kql
| where CsUriStem contains "/wp-admin/" or CsMethod == "POST"
| where CIp == "1.2.3.4"
```

Prefer the second form. It is the reason the queries here keep the OR group on
its own line.

### `project` — choosing columns

`project` picks and orders the output columns. Add from the field table above;
`UserAgent` and `ScBytes` are the two most often worth adding.

- `project-away Cookie, Referer` — keep everything except these.
- `project-rename ip = CIp` — output with a friendlier name.
- `extend` — add a computed column without dropping the others.

### `summarize` — aggregation

```kql
| summarize hits = count(), ips = make_set(CIp, 10) by CsUriStem
```

- `by` sets the grouping. `by CIp` = per attacker; `by CsUriStem` = per target;
  `by CIp, CsUriStem` = per pair; `by bin(TimeGenerated, 1h)` = per hour.
- `make_set(col, N)` collects up to N **distinct** values into an array; the cap
  is a display convenience, so raise it if the samples look truncated.
  `make_list` keeps duplicates and their order.
- `count()` vs `countif(cond)` vs `dcount(col)` (distinct, approximate) vs
  `dcountif(col, cond)`.
- Add `bin(TimeGenerated, 1h)` to a `by` clause to turn any of these into a
  time series — that is what makes them chartable in Grafana.

## Timezones — the trap

**`TimeGenerated` is stored in UTC. Always.** The Azure Portal may *render* it
in your browser's local timezone, and Grafana renders it in the dashboard
timezone. So a timestamp you copied off a chart is probably local, and pasting
it into `datetime()` shifts your window by your UTC offset — two hours in
summer for `Europe/Paris`, one in winter. That is the usual cause of "the window
should have data and it's empty".

Query 05 exists to settle this before you trust a timeline. To read results in
local time, convert for **display only**:

```kql
| extend heure_locale = datetime_utc_to_local(TimeGenerated, "Europe/Paris")
```

Keep filtering on raw `TimeGenerated`. Filtering on a converted column forces a
full scan instead of using the ingestion-time index — correct, but slow and
expensive.

## Grafana usage

Paste any of these into an Azure Monitor **Logs** query and they work unchanged.
To make a panel follow the dashboard controls, replace the hardcoded window:

```kql
AppServiceHTTPLogs
| where $__timeFilter(TimeGenerated)      // binds to the dashboard time picker
```

Other macros: `$__timeFrom` / `$__timeTo` (window bounds as datetimes) and
`$__interval` (auto bin size — `bin(TimeGenerated, $__interval)`).

Dashboard variables interpolate directly, so a `$ip` variable becomes:

```kql
| where CIp == "$ip"                       // single value
| where CIp in ($ips)                      // multi-value, "Multi-value" format
```

For a **time series** panel, aggregate into buckets and the first datetime
column becomes the x-axis:

```kql
| summarize requetes = count() by bin(TimeGenerated, $__interval), CIp
```

For **table** panels (queries 01–06 as written) set the panel's Format to
*Table*. Aggregated queries chart well; per-request queries are for reading, so
keep those as tables or logs panels.

## Adapting to other log sources

Same investigative shape, different table and column names.

| Source | Table | Time | Client IP | Path | Status |
| --- | --- | --- | --- | --- | --- |
| App Service (these queries) | `AppServiceHTTPLogs` | `TimeGenerated` | `CIp` | `CsUriStem` | `ScStatus` |
| App Service, legacy diag | `AzureDiagnostics`, `Category == "AppServiceHTTPLogs"` | `TimeGenerated` | `CIp_s` | `CsUriStem_s` | `ScStatus_d` |
| IIS / VM | `W3CIISLog` | `TimeGenerated` | `cIP` | `csUriStem` | `scStatus` |
| App Gateway / WAF | `AzureDiagnostics` (`ApplicationGatewayAccessLog`) | `TimeGenerated` | `clientIP_s` | `requestUri_s` | `httpStatus_d` |
| Front Door | `AzureDiagnostics` (`FrontdoorAccessLog`) | `TimeGenerated` | `clientIp_s` | `requestUri_s` | `httpStatusCode_s` |
| App Service stdout | `AppServiceConsoleLogs` | `TimeGenerated` | — | — | — |
| App Service platform | `AppServicePlatformLogs` | `TimeGenerated` | — | — | — |

In `AzureDiagnostics`, the `_s` / `_d` / `_g` suffixes are types (string /
double / guid) — a numeric comparison like `ScStatus_d >= 400` needs the `_d`
column, and the string column won't compare the way you expect.

Worth correlating alongside these:

- `AppServiceAuditLogs` — FTP/Kudu publishing logins. A successful one you don't
  recognise, near a suspicious upload, escalates the whole incident.
- `AppServiceFileAuditLogs` — file writes on the app filesystem. Direct evidence
  that a dropped file landed, not just that it was requested.
- `AppServiceAntivirusScanAuditLogs` — AV verdicts, where enabled.

## Adding a query here

Copy an existing file in [queries/](queries/) and keep the header block:
purpose, when to use it, the table, and the tunables. Number it in workflow
order, and add a row to the table above.
