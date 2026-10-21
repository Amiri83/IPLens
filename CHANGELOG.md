# Changelog

## 1.0.1 – unreleased

### Changed

- `iplens` now serves the UI with **waitress** (8 threads, no `Server` header) instead of the
  Flask development server, which is only used with `--debug`.
- Clean startup: one line `IPLens <version> running at http://127.0.0.1:<port>  (Ctrl+C to stop)
  · data: <dir> · log: <file>` instead of the Flask / Werkzeug banner; the UI opens in the web
  browser when a desktop session is available (`--no-browser` to skip).
- Graceful shutdown on Ctrl+C / SIGTERM: the scheduled Refresh stops, running jobs are cancelled
  and any terraform process left is stopped.

### Fixed

- A fresh install no longer creates a placeholder account ("Account 1") on first start: the
  account list and inventory start empty, with an empty state that links to adding an account.
  Existing databases keep their accounts; a legacy single-account install still migrates.
- EC2 instances: each ENI is mapped to its instance (instance id and the instance's **Name**
  tag, via the optional `ec2:DescribeInstances`), and the attachment's secondary private IPs are
  included next to the primary. IP List search matches the instance id, Name tag and every IP.
- IP List search is a live filter: results update as you type (and when a filter changes)
  without a submit, with one clear (×) control (also Esc); the Filter button is only a
  no-JavaScript fallback.
- A hidden progress box no longer pops back up when switching tabs: Hide is remembered
  server-side (session) until the box is reopened, and a small "Discovery running…" badge
  shows on every page meanwhile.
- Refresh no longer runs unbounded when one resource type is slow. Settings → **Discovery
  timeouts**: a per-resource timeout (default 120 s, 10–3600) and an overall limit (default
  15 min, 1–240), applied from the next Refresh without a restart. A resource type past its
  timeout is skipped ("skipped (timeout after 120s)") and the others still run; VPCs,
  subnets and ENIs are required, so their timeout fails the Refresh. Collection clients get
  botocore connect / read timeouts so an abandoned call stops. Each resource type's rows are
  written in their own savepoint: a failed write never leaves part of a resource type behind.
- The Refresh progress box shows the timeouts in force (with a link to Settings), a row per
  resource type (pending / running / done / skipped, elapsed vs. timeout), the overall elapsed
  time vs. the limit and, at the end, the skipped resource types with their reason and a
  **Retry skipped** button; the same summary goes to the app log. Cancel now also stops a
  resource type that is stuck in an AWS call.
- **Retry skipped** collects only the skipped resource types (plus what they need, e.g. load
  balancers for target health), the account identity and VPCs / subnets / ENIs, instead of
  re-running the whole Refresh; the new snapshot says which types it holds. A skipped write
  that spans every type (resource tags) still retries everything.
- Hide / reopen of the progress box is no longer lost when you navigate right after
  clicking (the request is sent with `keepalive`).
- Refresh AWS calls use 2 retries (standard mode) with a read timeout sized so that all
  attempts fit in the per-resource timeout: an abandoned call no longer keeps retrying.
- A resource type abandoned at its timeout no longer writes log lines or progress into the
  job after it has been marked skipped.

### Security

- A non-loopback `--host` is refused unless `--allow-remote` is passed; IPLens then prints a
  warning that there is no authentication and accepts IP-address `Host` headers (hostnames other
  than `localhost` stay rejected as DNS-rebinding protection).

## 1.0.0 – unreleased

First public release, published to PyPI as `aws-iplens` (command `iplens`).

### Added

- **Discovery**: read-only snapshots of VPCs, subnets, ENIs and private IPs; VPC → subnet tree,
  per-subnet address grid, snapshot history with delete / clear (latest per account kept).
- **Multi-account**: per-account auth (default chain, named profile incl. SSO, access keys,
  temporary credentials), encrypted or memory-only secrets, account selector, per-account scope
  filters, account alias / display name in the header.
- **IP List**: flat table of every private IP with filters (VPC, subnet, type, status,
  environment, owner) and Excel export.
- **Visual**: per-VPC diagram with vendored AWS icons, collapsible groups, shared layout selector
  (Grid, Hierarchy, Circle, Concentric, Breadthfirst), per-account preferences and positions,
  SVG and draw.io export.
- **Extended view**: optional-source crawl of regional services, IAM, network, Route 53, AWS
  Config, Resource Explorer, X-Ray and MSK / Kafka; evidence-ranked edges, decluttering (edge
  dedupe, groups, focus mode, swimlanes), Not linked panel, opt-in flow log analysis.
- **Background jobs**: Refresh, crawl and Terraform sync with a progress modal, re-attach and
  Cancel; one job per account.
- **Environments**: derived from Terraform root × environment or configurable environment tags;
  filter and group by environment.
- **Ownership**: AWS-first (CloudFormation > IaC tag > optional Terraform state > opt-in
  CloudTrail creator > unmanaged), configurable tag keys and CI role patterns, tag gaps.
- **Terraform (optional)**: repo discovery, allowlisted read-only sync (S3 backends read
  directly, local state files, `terraform init` / `show -json` otherwise), drift and "managed
  elsewhere" markers; off by default.
- **Rules & Suggestions**: rule kinds `lambda_vpc_required`, `internal_only`, `subnet_reserved`,
  `min_free_pct`, `protected_eni`; GUI and YAML import / export; blocked suggestions greyed out.
- **Trends**: scheduled per-account Refresh, snapshot retention with daily downsampling, used-IP
  charts per subnet / VPC with a linear forecast and a Discovery badge.
- **Diff**: compare two snapshots – added / removed / changed ENIs and IPs, net delta per subnet,
  top consumers.
- **CIDR planner**: per-VPC CIDR map with free blocks and fragmentation score, Fit tool,
  secondary-CIDR candidates with AWS restriction checks, overlap check across accounts, Transit
  Gateway and peering routes, and Terraform snippets.
- **Report**: self-contained printable HTML report per account with an option to redact
  identifiers.
- **Release**: `iplens --version`, favicon, data directory `--home` / `$IPLENS_HOME` /
  `~/.iplens`, GitHub Actions tests and PyPI Trusted Publishing.

### Security

- Every AWS call passes a read-only guard (`Describe` / `List` / `Get` plus an explicit
  allowlist); secret-returning calls are refused.
- Local-only server with DNS-rebinding protection, CSRF tokens, `HttpOnly` / `SameSite=Strict`
  cookies, no external front-end requests.
