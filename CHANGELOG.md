# Changelog

## 1.6.0 – 2026-10-29

### Added

- **Effective access** on the Visual page (IP, Logical and Extended view): only connections that
  are really allowed are drawn. Network check (from the snapshot's security group rules, no new
  AWS call): the source's groups must allow the egress and the target's groups the ingress, by
  security group reference or a CIDR covering the peer's IP, every group of an ENI evaluated as a
  union, with at least one port both sides allow; VPC endpoint edges included (a resource whose
  egress names an endpoint's group is a candidate, and the endpoint's ingress decides). IAM check:
  the Extended crawl calls `iam:SimulatePrincipalPolicy` for each Lambda execution role / ECS task
  role (task execution role for ECR image pulls) and the actions its connections need
  (`sqs:SendMessage`, `sns:Publish`, `sqs:ReceiveMessage`, `ecr:GetAuthorizationToken`,
  `ecr:BatchGetImage`), and evaluates SQS / SNS resource policies; the VPC endpoint policy is
  evaluated when the page is built. A connection is drawn only if both checks allow it;
  connections without data to check against (no crawl yet, rules not collected) are not blocked.
- **Show blocked** toggle (URL `blocked=1`): blocked connections drawn dashed red; clicking a
  connection lists why it is effective or blocked (the security group side and groups, or the IAM
  role / resource / endpoint policy). Per-type counts show the blocked ones.
- Multi-AZ badge (`3 AZ`) in the IP view too: an ENI of a resource spanning several AZs shows its
  resource's AZ count, as in the Logical view.
- The read-only guard allowlists `iam:SimulatePrincipalPolicy` by name (a simulation, it changes
  nothing; it carries no `Describe` / `List` / `Get` prefix).

### Changed

- A Refresh also stores the security groups' egress CIDR rules (`sg_egress_cidr_rules`) and the
  VPC endpoint policy. Snapshots from before 1.6.0 lack the egress CIDR rules: their egress side
  is not checked.
- Simulation results and principal roles are cached per snapshot (`iam_principals`, `iam_sims`;
  only ids and decisions, never policy documents); a crawl reuses them, and *Retry skipped*
  copies them (and the egress rules) into the new snapshot.

## 1.5.0 – 2026-10-29

### Added

- **Visual → Logical view** tab, next to the IP view (`/visual?view=logical`; the IP view is
  unchanged). Multi-AZ duplicates collapse into one node per logical resource, grouped by the
  stored ENI owner: Lambda function (the functions sharing its ENIs are one node), ECS service
  (`cluster/service`), load balancer, VPC endpoint, NAT gateway, TGW attachment, RDS /
  ElastiCache / OpenSearch cluster or instance, EC2 instance. ENIs without an owner reference
  (and "ENI/other") stay one node each. Nodes are drawn in the VPC box without subnet boxes and
  show name, type icon and an AZ count (`3 AZ`) – no IPs or ENI ids (the tooltip lists the AZs).
  Connections between two collapsed nodes are merged into one edge per connection type (distinct
  labels and tooltip lines kept). Same layout engine, styling, filters, Group by and exports as
  the IP view; layout choice and dragged positions are stored per view (`<vpc>:logical`).

### Changed

- The **name filter** takes `,` = OR and `+` = AND, AND binding tighter (`dev+lambda, uat`:
  (dev AND lambda) OR uat; trimmed, any case, empty terms ignored, so `+dev` / `dev+` is `dev`).
  A term matches the name, an owner's name, the ENI id, a tag value or the type (or its label);
  a hint `, = OR  + = AND` sits under the input. It applies the same way in the IP, Logical and
  Extended view.
- Diagram exports of the Logical view are named `iplens-<vpc>-logical.svg` / `.drawio`.

## 1.4.0 – 2026-10-27

### Added

- **Visual → Tag filters** (IP and Extended view): choose a tag key (suggested from the tags
  found on every resource) and one or more of its values, ticked in a checkbox list (a plain
  click or tap toggles a value; Select all / Select none; touch-sized on mobile). A filter applies
  to every resource node, whatever its type. An ENI shared by several Lambda functions matches a
  value of any of its functions (its displayed tags stay the first function's). A filter's values
  are OR'd, several filters are AND'd; tag keys match in any case, values exactly. Resources
  without the key are hidden unless **Include untagged** (off by default). Active filters show as
  removable chips, with "X of Y shown" in total and per resource type. VPC and subnet boxes are
  always drawn, unless **Hide empty containers** (off by default) is ticked. Filtering runs in
  the browser over the data already loaded (no new discovery). Compliance rules, findings,
  suggestions and data exports always use every resource; the diagram's SVG / draw.io export
  still contains the diagram as shown.
- **Visual → name filter**: comma-separated terms (e.g. `dev, nonprod`), matched in any case as
  a substring of a resource's name, of every owner's name (all functions of a shared Lambda ENI)
  or of its ENI id; terms are OR'd, and the name filter is AND'd with the tag filters. Shown as a
  removable chip and saved in presets.
- Named view filter presets, saved per account in the database: save (overwrites a preset of the
  same name, including its name filter and "Hide empty containers" choice), load and delete.
- **Visual → IP view: Transit Gateways from every Refresh.** Discovery also calls
  `ec2:DescribeTransitGatewayAttachments` and `ec2:DescribeRouteTables` (optional: a denied call
  is a Refresh warning), stored per snapshot. Transit Gateway attachment ENIs are a resource type
  of their own ("TGW attachment", with a Transit Gateway icon) instead of "ENI/other". The IP view
  draws one node per Transit Gateway outside the VPC box, an edge from each attachment ENI to its
  gateway (labelled with the attachment id and state) and from each subnet whose route table
  routes to it (tooltip: destination CIDRs / prefix lists and the route table id), without an
  Extended crawl. With a crawl its VPC → gateway lines are merged in, without the routes and
  attachments discovery already draws. A note below the diagram suggests the crawl when there is
  none, and lists the AccessDenied / UnauthorizedOperation warnings of DescribeRouteTables /
  DescribeTransitGatewayAttachments from discovery and from the crawl.

## 1.3.1 – 2026-10-22

### Changed

- The MCP server is part of the core install: `mcp` (and `uvicorn`, its HTTP mode) are regular
  dependencies, so a plain `pip install aws-iplens` is enough. The `aws-iplens[mcp]` extra is
  kept as an empty alias and still installs.

### Added

- **Settings → MCP server → Enable MCP server**: a master switch, **off by default** (also after
  an upgrade: turn it on to keep using MCP). While it is off the Start / Restart buttons are
  disabled, "start with IPLens" is ignored, the header badge is hidden, and `iplens mcp` (stdio
  and `--http`) exits with status 2: "MCP is disabled in IPLens Settings"; a server already
  running refuses tool calls. Saving with it off stops the running server. Takes effect at once
  (no IPLens restart); enabling / disabling is logged.

## 1.3.0 – 2026-10-22

### Added

- `iplens mcp`: a read-only stdio MCP server (optional extra `aws-iplens[mcp]`, official MCP
  Python SDK) over the local database. Tools: `list_subnets`, `find_subnet`, `subnet_detail`,
  `lookup_ip`, `changes` and `fit_check` (the `iplens check` logic); JSON results with the
  snapshot time, paginated where long. `--account` picks the account, `--redact` hides account
  ids, ARNs, ENI / instance ids, IPs and CIDRs in every result and error. Never calls AWS (the
  process refuses to import boto3) and never writes (read-only SQLite connection). README setup
  for VS Code, Claude Code and Hermes.
- `iplens mcp --http [--host] [--port] [--allow-remote]`: the same tools over Streamable HTTP
  (stdio stays the default). A bearer token is required on every request (`$IPLENS_MCP_TOKEN`,
  else the token stored encrypted by the UI; never on the command line); a foreign browser
  `Origin` and a foreign `Host` are rejected; a non-loopback host needs `--allow-remote`.
- **Settings → MCP server**: runs the HTTP server as a child process of IPLens. Start / Stop /
  Restart, status (running / stopped / error + last error), PID, URL and uptime, plus a header
  badge; settings for autostart, host, port (checked free before start), redact (on by default),
  account and remote access (with a warning); saving restarts a running server. Token shown once,
  copy, regenerate. A crash is shown and retried at most 3 times; the server stops with IPLens
  (and by itself if IPLens is killed). Its output goes to `mcp-server.log`, shown on the Logs page.
  **Connect** panel with copy-ready configs for VS Code (`type: http`, token via an input
  variable), Claude Code (`claude mcp add --transport http`) and the stdio alternative.
- Suggestions **Underused subnet** (under 10% used in every snapshot of the last 30 days: the
  smallest prefix fitting 2× the peak, saving the usable-IP difference; `min_free_pct` and
  `subnet_reserved` rules apply) and **Unused endpoint** ("possibly unused": an interface endpoint
  without traffic in the flow log queries of the last 14 days, once those cover at least 24 hours
  over at least 3 distinct days; the detail states the coverage). Checks that cannot be made
  (short history, no or too little flow log data for a VPC) are listed as notes on the page, in
  the report and in MCP.
- MCP tool `suggestions` (redacted with `--redact` like every tool).

### Changed

- **Detached ENI** suggestions need the ENI detached in every snapshot of the last 7 days and
  show "detached since <date>".
- `iplens check` live mode reads `application-autoscaling:DescribeScalableTargets` for the ECS
  services found, so their maximum matches the headroom model (they no longer count only up to
  their desired count).
- **Retry skipped** copies the other resource types from the snapshot of the job being retried,
  not from whichever snapshot is the latest when it is clicked.
- Headroom / fit check ALB assumption reads "8 IPs per ALB per subnet".
- CI: GitHub Actions on their Node 24 majors (checkout v7, setup-python v7, upload-artifact v7,
  download-artifact v8).

## 1.2.3 – 2026-10-21

### Added

- Pre-deploy IP fit check for CI: `iplens check --plan plan.json` (a `terraform show -json`
  plan) or `iplens check --subnet ID --need N`. Per subnet, free IPs − existing scale headroom
  demand − plan demand; exit 0 = fits, 1 = does not fit (below 0, below `--min-free-pct`) or breaks
  a saved rule (`--rules`), 2 = error. Plan demand per new / changed resource with its assumption:
  `aws_instance`, `aws_network_interface`, `aws_nat_gateway` 1; `aws_lb` 8 per ALB subnet, 1 per
  NLB / GWLB subnet; Interface `aws_vpc_endpoint` 1 per subnet; awsvpc `aws_ecs_service`
  `desired_count` plus the headroom deploy surge; `aws_autoscaling_group` `max_size` (updates: the
  delta); `aws_lambda_function` 1 per new subnet / security-group combination; `aws_db_instance` 1
  (2 Multi-AZ). Subnets known only after apply are listed as unresolved (a warning). Output as a
  table, `--format json` or `--format markdown` for PR comments; README examples for GitHub
  Actions and GitLab CI.
- Data for the check: **Headroom → Export snapshot for CI** (JSON of subnets, free IPs and the
  headroom inputs; no credentials needed in CI), or live AWS through the read-only guard and the
  Refresh timeouts with only `ec2:DescribeSubnets` / `DescribeNetworkInterfaces` (filtered to the
  subnets involved), `autoscaling:DescribeAutoScalingGroups` and ECS List / Describe calls.
  **Rules → Export rules for CI** exports the rules of the active account.

## 1.2.0 – 2026-10-21

### Added

- IP exhaustion forecast: per subnet, a linear fit of used IPs over the last 30 days of snapshots
  (at least 5 points) – the trend in IPs/day, days until free = 0 and days until the scale
  headroom demand no longer fits (free − demand = 0); "stable" for a flat or shrinking trend,
  "not enough data" below 5 points. A Forecast column on **Headroom**, a used-IP sparkline with
  the forecast on the subnet page and an "IP exhaustion forecast" table in the report.

- Alerts (**Settings → Alerts**): a webhook notified after each Refresh, in the chosen webhook
  format – Slack (`{"text": ...}`, default) or Microsoft Teams Workflows (Adaptive Card) – when a subnet's state changes – headroom over, forecast to stop fitting
  within X days (default 30), free below Y% (default 10). The last state sent is stored per
  subnet, so repeated Refreshes do not re-send; cleared subnets get one "resolved" line. A
  **Send test** button. The webhook URL is encrypted like the credentials and never logged or
  shown again; alert text uses subnet name + AZ, with account / subnet ids only when enabled.
  The webhook is the only outbound call besides AWS; a failure is logged, shown as a warning and
  never fails the Refresh.

- Scale headroom: per subnet, free IPs vs. the worst-case demand if everything scales to its
  maximum – Auto Scaling groups (`max - current` instances spread evenly over their subnets ×
  ENIs per instance), awsvpc ECS services (`max - running` tasks, 1 IP each), 8 free IPs per ALB
  subnet and 1 IP per Lambda subnet / security group combination without an ENI – each
  contributor shown with its assumption. A **Headroom** page (OK / tight / over, worst first,
  per-AZ totals with an imbalance flag, a bigger-subnet / secondary-CIDR suggestion linking the
  CIDR Planner), a Headroom column on Discovery and a Scale headroom section in the report. New
  optional, read-only `autoscaling:DescribeAutoScalingGroups` and
  `application-autoscaling:DescribeScalableTargets` (missing permission = Refresh warning; the
  headroom uses what is known); load balancer and ECS service subnets are now stored per
  snapshot. The new rows are copied by "Retry skipped" like the other resource types it does not
  collect.

- Scale headroom: ECS deploy surge – the extra tasks of a rolling deployment at max scale,
  `ceil(max × (maximumPercent − 100) / 100)` spread over the service's subnets like the
  scale-out, as its own contributor ("deploy surge: +N, maxPercent 200"). `maximumPercent`
  defaults to 200; none for `CODE_DEPLOY` / `EXTERNAL` deployment controllers or
  `maximumPercent` ≤ 100. An **include deploy surge** toggle on the Headroom page (on by
  default). ECS services now store `deploymentConfiguration.maximumPercent` and the deployment
  controller per snapshot.

- Owner names of managed-service ENIs: optional, read-only `rds:DescribeDBInstances`,
  `rds:DescribeDBClusters`, `redshift:DescribeClusters`, `elasticache:DescribeCacheClusters`,
  `elasticache:DescribeReplicationGroups`, `es:ListDomainNames` + `es:DescribeDomains` and
  `kafka:ListClustersV2` map each cluster / domain to its ENIs (by ENI id / node IP, the ENI
  description's reference, or subnet + security groups), so they read e.g. "Aurora cluster
  db-a" or "ElastiCache replication group cache-a" instead of the generic "RDS" /
  "ElastiCache". Unmatched or ambiguous ENIs keep today's attribution; a missing permission is
  a Refresh warning. The rows are stored per snapshot and copied by "Retry skipped" like the
  other resource types it does not collect.

### Changed

- The per-resource discovery timeout defaults to 30 s (was 120 s) and applies to the optional
  resource types; VPCs, subnets and ENIs always get at least 120 s (or the setting, if longer),
  with botocore read timeouts split to fit each (3 attempts × read timeout ≤ the timeout,
  connect timeout ≤ 10 s).

## 1.0.1

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
  re-running the whole Refresh. A skipped write that spans every type (resource tags) still
  retries everything.
- **Retry skipped** no longer saves a partial snapshot: in the same transaction the rows of
  every resource type it does not collect are copied from the account's latest snapshot, the
  retried ones are written fresh and the ENIs are attributed on the merged data. Overview and
  attribution stay complete, Diff / Trends show no false removals and retention keeps a full
  snapshot. tag:GetResources and CloudFormation are retried together (ownership merges both).
  Without that source snapshot (e.g. deleted meanwhile) the retry runs a full Refresh.
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

## 1.0.0

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
