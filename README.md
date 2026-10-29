# IPLens
Local web app for private IPv4 usage visibility &amp; optimization across one or more AWS accounts

## Features

- **Discovery** – read-only snapshots of VPCs, subnets, ENIs and their private IPs per account,
  with a VPC → subnet tree and a per-subnet address grid.
- **IP List** – every private IP in one filterable table (VPC, subnet, resource type, status,
  environment, owner), exportable to Excel.
- **Visual** – per-VPC diagram of subnets and resource ENIs with AWS icons, several layouts and
  SVG / draw.io export; a **Logical view** draws each resource once, whatever its AZs.
- **Extended view** – optional crawl of regional services (SNS, SQS, DynamoDB, EventBridge, S3,
  API Gateway, Step Functions, Lambda, ECS, MSK, ...) and network edges, each connection ranked by
  evidence; opt-in flow log analysis.
- **Ownership** – who manages each resource: CloudFormation, IaC tags, optional Terraform state,
  optional CloudTrail creator, or unmanaged; plus tag gaps.
- **Trends** – scheduled refresh, snapshot retention with daily downsampling, used-IP charts and
  a "full in ~N days" forecast per subnet and VPC.
- **Diff** – compare two snapshots: ENIs / IPs added, removed and changed, net delta per subnet,
  top consumers.
- **Scale headroom** – free IPs per subnet vs. the worst-case demand if every Auto Scaling group,
  ECS service, ALB and Lambda scales to its maximum; subnets that run out before max are flagged,
  with an exhaustion forecast (days until free = 0 and until the demand no longer fits).
- **Pre-deploy fit check** – `iplens check` in CI: does a Terraform plan (or N more IPs) fit its
  subnets on top of the scale headroom, and does it keep your rules? Exit code + table, JSON or
  Markdown for PR comments.
- **Alerts** (optional) – a Slack or Teams (Workflows) webhook notified after each Refresh when a subnet's
  state changes (over at max scale, forecast to run out soon, low free IPs).
- **CIDR planner** – free blocks and fragmentation per VPC CIDR, a Fit tool for new subnets and
  secondary-CIDR proposals checked for overlaps.
- **Report** – one self-contained, printable HTML report per account, optionally with identifiers
  redacted.
- **Rules & Suggestions** – IP-saving suggestions, filtered by your own rules (GUI or YAML).
- **Terraform** (optional) – read-only sync of local Terraform repos for ownership, environments
  and drift.
- **Multi-account, local and read-only** – one local app for many accounts; every AWS call passes
  a read-only allowlist guard.

## Install

Requires Python 3.11+. The PyPI distribution is `aws-iplens`; the command it installs is `iplens`.

```bash
pipx install aws-iplens        # or: python3 -m pip install aws-iplens
iplens --version
```

From a checkout (development):

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Run

```bash
iplens                         # http://127.0.0.1:8077
iplens --port 8080             # another port
iplens --home /path/to/data    # another data directory (default: $IPLENS_HOME or ~/.iplens)
iplens --no-browser            # do not open the browser
iplens --debug                 # Flask development server with the debugger (development only)
iplens check --help            # pre-deploy IP fit check for CI (no web UI, see below)
iplens mcp --help              # read-only MCP server for AI assistants (enable it in Settings)
```

IPLens is served by [waitress](https://docs.pylonsproject.org/projects/waitress/) and prints one
line with its URL, data directory and log file. With a desktop session the UI opens in the web
browser; otherwise open the printed URL. Ctrl+C stops it cleanly (running jobs are cancelled and
terraform processes stopped). AWS credentials are configured per account in the UI
(Settings → Accounts); see below.

## Data location

Everything lives in one directory: `--home`, else `$IPLENS_HOME`, else `~/.iplens` (created with
mode `0700`). Delete it to reset IPLens completely.

| path | contents |
|---|---|
| `iplens.db` | SQLite: accounts, snapshots, crawled services, rules, settings, view preferences |
| `secret.key` | Fernet key that encrypts stored AWS secrets (mode `0600`) |
| `flask.secret` | session signing key |
| `logs/` | application log (the log directory can be changed in Settings) |
| `tf-cache/` | Terraform working data of repo syncs (only when Terraform sync is used) |

## Security

- **Local only.** The server binds to `127.0.0.1` by default and rejects requests whose `Host`
  header is not a local name (DNS-rebinding protection). A non-loopback `--host` is refused
  unless `--allow-remote` is passed (IP-address `Host` headers are then accepted too); it has no
  login, so only do that on a trusted network.
- **Read-only AWS access.** Every AWS call goes through an allowlist guard (see
  [Read-only by construction](#read-only-by-construction)); IPLens never changes your account.
- **Outbound calls.** Besides AWS, the only outbound call is the optional [alert](#alerts)
  webhook POST (https only, off until a URL is set).
- **Secrets.** Access keys and session tokens are Fernet-encrypted in SQLite (or kept in memory
  only), never logged and never rendered back. Environment variable values, policy documents and
  secret values seen while crawling are matched in memory and never stored.
- **Web.** Every form POST needs a per-session CSRF token; session cookies are `HttpOnly` and
  `SameSite=Strict`. All front-end assets are vendored: the browser makes no external requests.
- **Releases** are published from GitHub Actions with PyPI Trusted Publishing (OIDC); no API
  token is stored in the repository.

## Using IPLens

1. **Settings → Accounts** – add one entry per AWS account (display name, region, auth mode) and
   use **Test**. Auth modes: environment/default chain, named profile (dropdown of
   `~/.aws/config` + `~/.aws/credentials`, SSO profiles included), access key + secret, or
   temporary credentials (paste three fields, an `export AWS_…` block, or `aws sts` JSON including
   `Expiration`; the form shows "expires in Xm"). Secrets and session tokens are Fernet-encrypted
   in SQLite, or kept in process memory only with **memory only**; they are never logged or
   rendered. Expired/rejected tokens produce "credentials expired, paste new ones" with an edit
   link. The **account selector** in the top bar picks the active account: snapshots, IP list,
   Visual and suggestions are scoped to it; rules are global unless given an account scope. An
   existing single-account database is migrated into one account automatically.
2. **Discovery → Refresh from AWS** – takes a read-only snapshot of VPCs, subnets, ENIs and their
   private IPs (plus Lambda, VPC endpoint and load balancer metadata), and shows the
   **VPC → subnet tree** and the per-subnet **address grid**. The history table can delete
   selected snapshots or **Clear history**; both need `DELETE` typed to confirm, and the latest
   snapshot of every account is always kept.
   Refresh, **Crawl services** and **Terraform sync** run as **background jobs**: a modal shows the
   current step (e.g. `root apps env dev · terraform init`), done / total, elapsed time, a live log
   tail and **Cancel** (checked between steps; a running AWS call or terraform command finishes
   first). Only one job runs per account at a time; reloading the page re-attaches to it. Without
   JavaScript the forms still work and wait for the job to finish.
3. **IP List** – one flat table of every private IP in the latest snapshot (IP, subnet, VPC,
   resource type, resource name/ref, ENI, status, **environment**), sorted numerically by address.
   Filter by VPC, subnet, resource type, status, environment or free text; **Export to Excel**
   downloads the current filter as an `.xlsx` (one sheet, header row frozen, autofilter enabled).
   A resource's environment comes from the Terraform repo root × environment that manages it,
   else from the first environment tag (Settings; default `Environment`, `env`, `stage`) on the
   resource, its subnet or its VPC. Every Visual view filters by environment and can group / colour
   by it.
4. **Visual** – nested diagram per VPC: VPC box → subnet boxes (CIDR, used/idle/free) → one node
   per resource ENI with its AWS icon, name and IPs. More than 10 nodes of one type in a subnet are
   collapsed into a group node (click to expand). Scroll/drag to zoom and pan; double-click a node
   to open its ENI. VPC/subnet borders and the legend can be toggled (remembered per account).
   Every view shares one toolbar (zoom, Fit, Expand / Collapse groups, Reset layout) and a
   **Layout** choice – Grid (default), Hierarchy (dagre), Circle, Concentric, Breadthfirst – that
   keeps every box (VPC, subnet, expanded service group, swimlane) together; the layout and the
   expanded groups are remembered per account and view, dragged node positions per account + VPC
   + view until **Reset layout** (which also leaves focus mode). **Export SVG** / **Export
   draw.io** download the view exactly as shown (draw.io: `mxgraph.aws4` shapes, VPC and subnets
   as containers, edges kept). Data comes from `GET /visual/data.json?vpc=<vpc-id>`.
   **Tag filters** (every view, in the browser over the loaded data, nothing is re-discovered):
   pick a tag key (suggested from the tags found on every resource, any case) and one or more
   values (a checkbox per value found, with Select all / Select none); a filter applies to every
   resource node, whatever its type, and only resources with one of those values are drawn. An
   ENI shared by several Lambda functions matches the values of any of them (its displayed tags
   stay the first function's). Several filters must all match; resources without the key are
   hidden unless **Include untagged**. The **name filter** takes terms with `,` = OR and
   `+` = AND, AND binding tighter (`dev+lambda, uat` is (dev AND lambda) OR uat; spaces trimmed,
   empty terms such as in `dev,,` or `+dev` ignored); a term matches when the resource's name, any
   owner's name (every function of a shared Lambda ENI), ENI id, a tag value or its type contains
   it, in any case – the same in the IP, Logical and Extended view; it combines with the tag filters
   (both must match). Active filters are removable chips, with "X of Y shown" in total and per
   type. VPC and subnet boxes always stay, unless **Hide empty containers**. Filters (tag and name)
   can be saved as named presets (per account). Compliance rules, findings, suggestions and data
   exports are never filtered.
   The IP view also draws the VPC's **Transit Gateways** outside the VPC box, from every Refresh
   (`ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeRouteTables`): each Transit Gateway
   attachment ENI (resource type "TGW attachment") is linked to its gateway, labelled with the
   attachment id and state, and each subnet whose route table routes to a gateway is linked to it
   (hover or tap: the destination CIDRs / prefix lists and the route table id). An Extended crawl
   adds what discovery does not see (TGW route table propagations) on a VPC → gateway line. A note
   below the diagram says when there is no crawl yet, and lists the `DescribeRouteTables` /
   `DescribeTransitGatewayAttachments` calls that discovery or the crawl was denied.
   The **Logical view** tab (next to the IP view, `?view=logical`) collapses multi-AZ duplicates:
   one node per logical resource instead of one per ENI, grouped by the stored ENI owner – a
   Lambda function (the functions sharing its Hyperplane ENIs are one node), an ECS service, a
   load balancer, a VPC endpoint, a NAT gateway, an RDS / ElastiCache / OpenSearch cluster or
   instance, an EC2 instance; an ENI without owner stays a node of its own. Nodes sit in the VPC
   box (no subnet boxes) with name, type icon and an AZ count (`3 AZ`), no IPs or ENI ids;
   connections between two collapsed nodes are merged into one line per connection type. Same
   layouts, styling, filters, Group by and exports as the IP view; its layout and dragged
   positions are kept apart from the other views. Double-click does not open an ENI there.
   The **IP view** is the default; the **Extended view** tab adds regional services (SNS, SQS,
   DynamoDB, EventBridge, S3, API Gateway, Step Functions, Lambda, ECS, Secrets Manager names) and
   external nodes (Transit Gateway, peering, internet via IGW / NAT) around the VPC.
   **Crawl services** (opt-in) reads them; every connection carries evidence, strongest first:
   *observed* (flow logs, X-Ray) > *configured* (subscriptions, event source mappings, targets,
   routes, ...) > *permitted* (IAM policies of Lambda / ECS roles) > *referenced* (environment
   variables). Environment variable values, policy documents and secret values are only matched
   against known resource names / ARNs in memory and never stored; IAM `Resource: "*"` shows a
   *broad access* badge. **Flow logs** (opt-in) shows the estimated Logs Insights scan size for the
   chosen window (default 1 hour) before running, and stores only ENI↔ENI/port aggregates.
   Filters by service and evidence level apply to the diagram and its exports. To stay readable
   the Extended view draws **one line per pair of nodes**, styled by its strongest evidence, with a
   *+N* badge for further evidence lines (all listed when the line is clicked). Only *observed* and
   *configured* are shown by default; *permitted* / *referenced* are opt-in, and the selection is
   remembered per account. Regional services of one type ("SQS queue ×18") and Lambda / ECS ENIs
   of a subnet are collapsible groups; lines between collapsed groups merge into one labelled
   *×count*, drawn wider the more connections it stands for. The Hierarchy layout runs left to right:
   sources (EventBridge, SNS, API Gateway, S3) → compute (Lambda, ECS) → targets, with edges routed
   along dagre's paths. Click a node or search by name / ARN / IP to see only its 1- or 2-hop
   neighbourhood (**Show all** or Esc to return). Group by tag, Terraform root or environment draws
   one swimlane per app. Exports contain exactly what is shown. **Kafka**: Amazon MSK clusters
   (`kafka:ListClustersV2`) and Lambda event source mappings from MSK or self-managed Kafka become
   *Kafka: <cluster or bootstrap host>* nodes. Crawled nodes linked to nothing in the VPC shown are
   listed in the **Not linked** side panel (click one to draw it, or **Show all crawled nodes**).
   Icons and labels are larger in the Extended view, and Fit never zooms out below a readable size.
5. **Ownership** – who manages each resource, AWS-first; the first match wins:
   **CloudFormation** stack (`cloudformation:ListStacks` / `ListStackResources`) > **IaC tag** (the
   project / repo tag key) > **Terraform** state (optional enrichment, **off by default**) >
   **CloudTrail** creator (opt-in `cloudtrail:LookupEvents` for resources still unowned: a role /
   user matching a *CI role name pattern* → "IaC (unknown repo)", anyone else → "manual") >
   **unmanaged**. Tags of every resource come from `tag:GetResources` (paginated). The source and
   value are shown in the IP List (column and filter), on ENI pages and in the Visual page's
   **Group by owner / team**. The Ownership page (formerly the Terraform / drift page) counts
   resources per source and lists the unmanaged ones and **tag gaps** (resources missing the
   configured environment / project tag); Terraform sync, drift and "managed elsewhere" markers are
   kept in its collapsed, optional Terraform section. **Settings → Ownership** picks the project /
   repo, environment, team and owner tag keys from dropdowns of the tag keys seen in the account,
   the CI role patterns, and the two optional sources. Only the values of those tag keys are stored
   (other tags by key only); CloudTrail keeps the creating role / user *name*, never its ARN or
   session name. **CloudTrail event history only covers the last 90 days**: older resources stay
   unmanaged; at most 50 unowned resources are looked up per Refresh. With the Terraform
   enrichment off, Refresh no longer re-syncs Terraform repos (the Sync buttons still work).
6. Define **Rules** (GUI or YAML import/export) and review **Suggestions**; anything a rule forbids is
   greyed out together with the IPs it would have saved. Three suggestions use the snapshot
   history and say so in a note when it cannot tell yet:
   - **Detached ENI**: detached in *every* snapshot of the last 7 days (shown "detached since
     <date>").
   - **Underused subnet**: under 10% used in every snapshot of the last 30 days; suggests the
     smallest prefix (/28 to /16) whose usable IPs fit twice the peak, saving the difference in
     usable IPs (recreate the subnet at that size).
   - **Unused endpoint**: an interface VPC endpoint whose ENIs had no traffic in the flow log
     queries (Visual → Extended view → Flow logs) of the last 14 days, suggested as "possibly
     unused" only once those queries cover at least 24 hours (overlapping windows counted once)
     spread over at least 3 distinct days; otherwise skipped with a note giving the coverage so
     far (or saying the VPC has no flow log data).
7. **Logs** shows the application log file.

## Trends

**Settings → Accounts** sets a scheduled Refresh per account (off, every hour, every 6 hours,
every 24 hours); it runs while the app is running. **Settings → Snapshot retention** bounds the
history: snapshots older than the retention window (default 90 days) are deleted and those older
than the downsample threshold (default 7 days) are thinned to one per UTC day; each account's
latest snapshot is always kept. The **Trends** page charts used IPs per subnet and VPC over 7, 30
or 90 days and fits a linear forecast ("full in ~N days" or "stable/declining", with a confidence
note below 5 points). Subnets forecast to fill within 30 days get a badge on Discovery.

## Diff

**Diff** compares two successful snapshots of the active account (by default the latest and the
one before). It lists ENIs and IPs added, removed and changed, grouped by resource type, owner and
environment, with the net IP delta per subnet and the top consumers – the resources whose IP count
grew the most.

## Scale headroom

**Headroom** sets each subnet's free IPs against the demand if everything scales to its maximum,
and lists each contributor with its assumption, e.g. "ASG web: +6 (max 20, now 8: 6 instances
here of 12 more over 2 subnets, 1 ENI per instance)":

- **Auto Scaling group**: `max - current` instances spread evenly over its subnets (the remainder
  to the subnets with the fewest instances now), times the ENIs per instance of its current
  instances (1 when none is in the snapshot).
- **ECS service** (awsvpc): `max - running` tasks spread the same way, 1 IP each. The maximum is
  the service's Application Auto Scaling target; without one it is the desired count.
- **ECS deploy surge** (own contributor, e.g. "ECS service c/api deploy surge: +4, maxPercent
  200: ..."): a rolling deployment starts new tasks before stopping old ones, so a service at its
  maximum needs `ceil(max × (maximumPercent − 100) / 100)` extra tasks, spread the same way.
  `maximumPercent` defaults to 200 when unset; blue/green (`CODE_DEPLOY`) and `EXTERNAL`
  deployments, and `maximumPercent` ≤ 100, add none. The page's **include deploy surge** toggle
  (on by default) leaves it out.
- **ALB**: 8 IPs per ALB per subnet (AWS needs at least 8 free IPs in each ALB subnet to scale).
- **Lambda**: invocations take no IPs; only a subnet / security group combination without an ENI
  yet costs 1 IP.

A subnet is **over** when it runs out before max and **tight** when less than 20% of its usable
IPs are left; the page sorts them worst first, sums them per AZ to show imbalance and, for a
subnet that is over, suggests a bigger subnet or a secondary CIDR with a link to the CIDR Planner.
Discovery shows the result in a Headroom column and the report has a Scale headroom section. A
source that was skipped (missing permission, timeout) is named on the page and the demand uses
what is known.

**Exhaustion forecast.** A linear fit of each subnet's used IPs over the last 30 days of snapshots
(at least 5) gives its trend in IPs/day, the days until its free IPs reach 0 and the days until
the demand at max scale no longer fits (free − demand = 0). A flat or shrinking trend is
"stable", fewer points "not enough data". It is shown in a Forecast column on Headroom, next to a
used-IP sparkline on the subnet page, and in the report.

## Pre-deploy fit check (CI)

`iplens check` answers, before `terraform apply`: will the new IPs fit? Per subnet it computes

```
left = free IPs - existing scale headroom demand - plan demand
```

and fails when `left` < 0, when less than `--min-free-pct` (default 0) of the subnet's usable IPs
would be left, or when the change breaks a saved [rule](#rules). The existing demand is exactly the
[Scale headroom](#scale-headroom) worst case (including the ECS deploy surge; `--no-surge` leaves
it out of both).

```bash
iplens check --subnet subnet-a --need 12 --snapshot iplens-ci-snapshot.json   # simple ask
iplens check --plan plan.json --snapshot iplens-ci-snapshot.json \
             --rules iplens-ci-rules.yaml --min-free-pct 10 --format markdown
iplens check --plan plan.json --region us-east-1                # live AWS instead of a snapshot
```

**Exit codes**: `0` fits, `1` does not fit or breaks a rule, `2` error (bad arguments, unreadable
or invalid file, a subnet missing from the data, AWS error). **Output**: a table (default),
`--format json` (machine-readable, includes every assumption) or `--format markdown` (a PR / MR
comment with a collapsible per-subnet breakdown).

**Plan demand.** `--plan` takes `terraform show -json <planfile>`. Only new and changed managed
resources count; each one is listed with its assumption:

| resource | IPs |
|---|---|
| `aws_instance` | 1 per instance (primary ENI; instances attaching `network_interface` blocks are counted on the interface) |
| `aws_network_interface` | 1 |
| `aws_lb` application | 8 IPs per ALB per subnet (AWS needs them free to scale) |
| `aws_lb` network / gateway | 1 per subnet |
| `aws_vpc_endpoint` Interface / GatewayLoadBalancer | 1 per subnet (Gateway endpoints: none) |
| `aws_nat_gateway` | 1 |
| `aws_ecs_service` (awsvpc) | `desired_count` spread over its subnets, plus the deploy surge of the headroom rule |
| `aws_autoscaling_group` | `max_size` spread over its subnets, 1 ENI per instance |
| `aws_lambda_function` | 1 per subnet / security-group combination without a Lambda ENI yet (shared by functions of the plan) |
| `aws_db_instance` | 1, 2 with Multi-AZ; AWS picks the subnets of the DB subnet group (from the plan or its prior state), so each candidate must fit 1 |

An update counts what it adds (demand after minus before per subnet: e.g. `max_size` 4 → 10, a new
ALB subnet, Multi-AZ turned on); a replacement that destroys first likewise, a
`create_before_destroy` one in full. Subnets that are **known after apply** (e.g. a subnet created
in the same plan) are listed as *unresolved* with what they would need: a warning, never a
failure. A subnet id the data does not know is an error (a stale snapshot, another account?).

**Data source.**

- `--snapshot FILE`: **Headroom → Export snapshot for CI** in the UI downloads the latest
  snapshot's subnets, free IPs and headroom inputs (every subnet, not just the scope) as JSON. No
  AWS access or credentials needed in CI; the file holds no secrets, only resource ids and counts.
- live (default without `--snapshot`): the profile (`--profile`) or the default credential chain
  and `--region`. Through the same read-only guard and per-call timeouts as a Refresh
  (`--timeout`, default 30 s; subnets / ENIs at least 120 s), and only for the subnets involved:
  `ec2:DescribeSubnets` and `ec2:DescribeNetworkInterfaces` filtered to them (required), then
  `autoscaling:DescribeAutoScalingGroups`, `ecs:ListClusters`, `ecs:ListServices` and
  `ecs:DescribeServices`, and `application-autoscaling:DescribeScalableTargets` for the ECS
  services found, so their maximum is the same as in the headroom model (optional: an error is a
  note and that demand is skipped, or for scalable targets, the services count up to their desired
  count). ALBs come from their ENIs and Lambda combinations from the Lambda ENIs. Lambda is not
  called, so existing functions' new combinations are not counted; that is named in the notes.

**Rules.** **Rules → Export rules for CI** downloads the rules that apply to the active account
(without the account limit). `--rules` also takes the full YAML export; a rule limited to another
account than the snapshot's is skipped. A plan breaks `min_free_pct` when a subnet would keep less
than the percentage at max scale after the change, `subnet_reserved` when it places IPs in a
reserved subnet, `internal_only` with an internet-facing `aws_lb`, `lambda_vpc_required` with a
function without `vpc_config`, and `protected_eni` when it deletes a matching
`aws_network_interface`. `ecs_scale_down` only concerns suggestions and is skipped.

### GitHub Actions

Commit the two exports (e.g. under `ci/`) and refresh them from the UI now and then, or use live
mode with an OIDC role that has the permissions above.

```yaml
name: ip-fit-check
on: pull_request
permissions:
  contents: read
  pull-requests: write
  id-token: write                 # only for live mode / terraform plan via OIDC
jobs:
  fit-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.PLAN_ROLE_ARN }}
          aws-region: us-east-1
      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_wrapper: false
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install aws-iplens
      - run: |
          terraform init -input=false
          terraform plan -input=false -out=tfplan
          terraform show -json tfplan > plan.json
      - name: IP fit check
        id: fit
        run: |
          set +e
          iplens check --plan plan.json --snapshot ci/iplens-ci-snapshot.json \
            --rules ci/iplens-ci-rules.yaml --min-free-pct 10 --format markdown > fit.md
          echo "code=$?" >> "$GITHUB_OUTPUT"
          cat fit.md >> "$GITHUB_STEP_SUMMARY"
      - name: Comment on the PR
        run: gh pr comment ${{ github.event.pull_request.number }} --body-file fit.md --edit-last || gh pr comment ${{ github.event.pull_request.number }} --body-file fit.md
        env:
          GH_TOKEN: ${{ github.token }}
      - name: Fail when it does not fit
        run: exit ${{ steps.fit.outputs.code }}
```

### GitLab CI

```yaml
iplens-fit-check:
  stage: test
  image: python:3.12                # has curl for the MR comment
  needs: [terraform-plan]           # a job that saved `terraform show -json tfplan > plan.json`
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
  script:
    - pip install aws-iplens
    - status=0
    - iplens check --plan plan.json --snapshot ci/iplens-ci-snapshot.json
        --rules ci/iplens-ci-rules.yaml --min-free-pct 10 --format markdown > fit.md || status=$?
    - cat fit.md
    # Optional MR comment: a project access token with the api scope in IPLENS_NOTE_TOKEN.
    - 'if [ -n "$IPLENS_NOTE_TOKEN" ]; then curl --fail -sS -X POST
        -H "PRIVATE-TOKEN: $IPLENS_NOTE_TOKEN" --data-urlencode "body@fit.md"
        "$CI_API_V4_URL/projects/$CI_PROJECT_ID/merge_requests/$CI_MERGE_REQUEST_IID/notes"; fi'
    - exit $status
  artifacts:
    when: always
    paths: [fit.md]
```

`--format json` instead gives a report for other tools (`jq '.subnets[] | select(.status != "fits")'`).

## MCP server (AI assistants)

`iplens mcp` is a read-only [MCP](https://modelcontextprotocol.io) server over stdio, so an AI
assistant can answer "where do 40 more IPs fit?" or "who holds 10.1.2.3?" from your IPLens data.
It is built on the official MCP Python SDK and included in a plain `pip install aws-iplens`
(the former `aws-iplens[mcp]` extra still installs, as an empty alias).

**Off by default.** MCP must first be switched on in **Settings → MCP server → Enable MCP
server**. While it is off, `iplens mcp` (stdio and `--http`) exits with status 2 and
"MCP is disabled in IPLens Settings", a server already running refuses every tool call, the
Start / Restart buttons are disabled and the header badge is hidden. Turning it off and saving
stops the server IPLens runs; no IPLens restart is needed either way.

**Read-only, local only.** The server reads the local SQLite database (`--home`, default
`$IPLENS_HOME` or `~/.iplens`) through a read-only connection, from the latest successful
snapshot of the account. It never calls AWS (the process refuses to even import boto3) and never
writes anything; run a Refresh in the UI to update the data. Every result carries
`snapshot_taken_at`.

| tool | answers |
|---|---|
| `list_subnets(vpc?, az?, limit?, offset?)` | id, name, CIDR, used / idle / free IPs, headroom status (ok / tight / over); paginated |
| `find_subnet(need_ips, vpc?, az?)` | subnets where `need_ips` fit at max scale, most headroom left first |
| `subnet_detail(subnet)` | usage, top consumers, headroom contributors with assumptions, exhaustion forecast |
| `lookup_ip(ip)` | ENI, owning resource, ownership and subnet; or free / reserved by AWS |
| `changes(since="latest-1")` | snapshot diff summary; `since`: `latest-N`, a snapshot id or an ISO date |
| `fit_check(subnet, need, min_free_pct?, include_surge?)` | exactly `iplens check --subnet --need` against the latest snapshot and the saved rules |
| `suggestions(kind?, include_blocked?, endpoint_days?, limit?, offset?)` | the Suggestions page: IPs each saves, allowed / blocked by which rule, and notes on checks that could not be made |

Subnets and VPCs can be given by id or by name. Options:

- `--account ACCOUNT`: IPLens account id, AWS account id or display name (default: the account
  active in the UI).
- `--redact`: hide AWS account ids, ARNs, ENI / instance ids, IP addresses and CIDRs (shown as
  `<cidr>/24`) in every result and error; subnets, VPCs and security groups are shown by name
  (numbered `name#2` when names repeat), and those names are accepted as input.

**VS Code** (`.vscode/mcp.json` in a workspace, or *MCP: Open User Configuration*):

```json
{
  "servers": {
    "iplens": {
      "type": "stdio",
      "command": "iplens",
      "args": ["mcp", "--redact"]
    }
  }
}
```

**Claude Code**:

```bash
claude mcp add iplens -- iplens mcp
claude mcp add iplens-prod -- iplens mcp --account prod --redact   # another account, redacted
```

**Hermes** (`~/.hermes/config.yaml`):

```yaml
mcp_servers:
  iplens:
    command: iplens
    args: ["mcp", "--redact"]
```

When `iplens` is not on the client's `PATH` (e.g. a virtualenv), use the absolute path of the
command, such as `/path/to/.venv/bin/iplens`.

### HTTP mode, managed from the UI

`iplens mcp --http [--host 127.0.0.1] [--port 8765] [--redact] [--account X]` serves the same
tools over Streamable HTTP at `http://127.0.0.1:8765/mcp` (stdio stays the default). The same
read-only and no-AWS guarantees apply, and every request needs `Authorization: Bearer <token>`
(401 without it). The token comes from `$IPLENS_MCP_TOKEN`, else the one stored encrypted by
**Settings → MCP server**; it is never passed on the command line. A browser request with a
foreign `Origin` is rejected (403); clients that send no Origin (editors, CLIs) are fine. A
non-loopback `--host` is refused unless `--allow-remote` is passed: the token is then the only
protection, and plain HTTP is not encrypted.

**Settings → MCP server** runs it as a child process of IPLens: Start / Stop / Restart, the status
(running / stopped / error with the last error), PID, URL and uptime, with a status badge in the
header. Settings: enable MCP server (the master switch), start with IPLens, host, port (it must be free), redact (on by default),
account, allow remote access. Saving restarts a running server. The token is generated on the first
start (or with *Generate token*), shown once to copy, and can be regenerated. A crashed server is
shown in the UI and retried at most 3 times; it is stopped when IPLens stops. Its output goes to
`mcp-server.log` in the log directory (Logs page → *MCP server*). The **Connect** panel there has
copy-ready configs:

```json
{
  "inputs": [
    {"type": "promptString", "id": "iplens-mcp-token", "description": "IPLens MCP token", "password": true}
  ],
  "servers": {
    "iplens": {
      "type": "http",
      "url": "http://127.0.0.1:8765/mcp",
      "headers": {"Authorization": "Bearer ${input:iplens-mcp-token}"}
    }
  }
}
```

```bash
export IPLENS_MCP_TOKEN=...   # the token from Settings → MCP server
claude mcp add --transport http iplens http://127.0.0.1:8765/mcp --header "Authorization: Bearer $IPLENS_MCP_TOKEN"
```

## Alerts

**Settings → Alerts** posts subnet alerts to a webhook. The **Webhook format** setting picks the
JSON body:

- **Slack** (default): `{"text": "..."}`, for a Slack incoming webhook.
- **Microsoft Teams (Workflows)**: a message with an Adaptive Card 1.4 attachment, one TextBlock
  per line, for a Teams Workflows webhook ("When a Teams webhook request is received"):
  `{"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
  "content": {"type": "AdaptiveCard", "version": "1.4", "body": [{"type": "TextBlock", ...}]}}]}`.

After each Refresh (manual or scheduled) every subnet of the account is
checked: its scale headroom becomes **over**, the [forecast](#scale-headroom) says the demand stops
fitting within *X* days (default 30), or less than *Y*% of its usable IPs are free (default 10); 0
turns a threshold off. Only state changes are sent – the last state sent is stored per subnet, so
repeated Refreshes do not repeat an alert, and a subnet that clears gets one "resolved" line. All
changes of one Refresh go out as one message. **Send test** posts a test message.

The webhook URL is Fernet-encrypted like the account credentials, never logged and never shown
again (only its host). Alerts name subnets by Name tag and AZ and the account by its display name;
account and subnet ids are only included when **Include AWS identifiers** is ticked. A failed send
is logged and shown as a warning, never fails the Refresh, and is retried after the next one.

## CIDR planner

**CIDR Planner** shows, per VPC CIDR, the subnets, the free blocks between them, how many aligned
/20 … /28 blocks still fit and a fragmentation score. The **Fit** tool carves requested subnet
sizes (optionally per AZ) out of the free space. **Secondary CIDR** proposals – or a CIDR you type
in – are checked against the AWS association restrictions and for overlaps with every network
IPLens knows about: all accounts' VPCs and routes to Transit Gateways and peering connections. It
works on stored snapshot data only and never creates anything; a Terraform snippet is shown to
copy.

## Report

**Report** renders one self-contained HTML document per account (inline CSS and SVG, no scripts
or external assets) to print to PDF or share: summary and at-risk subnets, top IP consumers, the
used-IP trend, suggestions allowed / blocked by rules, scale headroom with the exhaustion
forecast, CIDR headroom with a secondary-CIDR
recommendation and ownership coverage. It can be limited to one environment. The **redact
identifiers** option replaces account ids, ARNs, IPs / CIDRs and resource ids with stable
keyed-hash placeholders (e.g. `[ip:3fa2c1d0e4]/24`), so relations inside the report survive
while the values cannot be recovered.

## Ownership

The **Ownership** page shows who manages each resource, first match wins: CloudFormation stack,
IaC tag, Terraform state (optional, off by default), CloudTrail creator (opt-in, last 90 days
only) or *unmanaged*. It counts resources per source and lists unmanaged resources and tag gaps.
Tag keys and CI role patterns are chosen in **Settings → Ownership**. See
[Using IPLens](#using-iplens) step 5 for details.

## Extended view

The **Extended view** tab of Visual adds regional services and external nodes (Transit Gateway,
peering, internet) around a VPC. **Crawl services** is opt-in and every source is optional: a
missing permission becomes a crawl warning. Each connection carries its strongest evidence
(*observed* > *configured* > *permitted* > *referenced*); **Flow logs** is a separate opt-in that
shows the estimated scan size first and stores only aggregates. See
[Using IPLens](#using-iplens) step 4 for details.

## Terraform (optional)

Terraform is **not required**: ownership is AWS-first, and the Terraform enrichment is off by
default. When enabled, IPLens discovers roots and environments in local repositories and reads
their state – straight from S3 for `s3` backends, from the file for local backends, otherwise
through an allowlisted `terraform init` / `show -json` (never `plan`, `apply` or `state`). The
state adds ownership, environments, drift (in AWS but not in Terraform and vice versa) and
"managed elsewhere" markers, shown in the collapsed Terraform section of the Ownership page.

## Read-only by construction

Every boto3 client is created through `iplens.aws.AwsGateway`, which registers a botocore
`before-call` hook that rejects any operation not starting with `Describe`, `List` or `Get`.
The only exceptions are the CloudWatch Logs query calls of the opt-in flow log analysis
(`logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`, `logs:FilterLogEvents`); calls that
return secret values (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`, ...) are refused even
though they start with `Get`. Minimal IAM permissions:

```
ec2:DescribeVpcs  ec2:DescribeSubnets  ec2:DescribeNetworkInterfaces  ec2:DescribeVpcEndpoints
lambda:ListFunctions  elasticloadbalancing:DescribeLoadBalancers  sts:GetCallerIdentity
```

Optional: `iam:ListAccountAliases` shows the account alias in the header (without it, IPLens
shows the account id only, or the *Account display name* set in Settings).
`ec2:DescribeInstances` adds the EC2 instance Name tag (shown and searchable in the IP List) and
the instance attachment's secondary private IPs; without it ENIs keep their own IP list.
`elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth` and
`ec2:DescribeSecurityGroups` add load balancer → target and security group reference
connections to the Visual page; without them those connections are left out.
`ec2:DescribeTransitGatewayAttachments` and `ec2:DescribeRouteTables` add the IP view's Transit
Gateway links; each one missing is a Refresh warning, listed in the note below the diagram.
Managed-service names: `rds:DescribeDBInstances`, `rds:DescribeDBClusters`,
`redshift:DescribeClusters`, `elasticache:DescribeCacheClusters`,
`elasticache:DescribeReplicationGroups`, `es:ListDomainNames`, `es:DescribeDomains` and
`kafka:ListClustersV2` name the ENIs of RDS / Aurora, Redshift, ElastiCache, OpenSearch and MSK
after their cluster or domain ("Aurora cluster db-a" instead of "RDS"); each one missing is a
Refresh warning and those ENIs keep the generic attribution.
Scale headroom: `autoscaling:DescribeAutoScalingGroups` (group sizes and subnets) and
`application-autoscaling:DescribeScalableTargets` (ECS service maximums); each one missing is a
Refresh warning and the headroom uses what is known.
Ownership: `tag:GetResources`, `cloudformation:ListStacks`, `cloudformation:ListStackResources`
and, when enabled in Settings, `cloudtrail:LookupEvents` (all read-only and listed explicitly in
the guard's allowlist); a missing permission becomes a Refresh warning and that source is skipped.

Extended view (each source optional; a missing permission or disabled feature becomes a crawl
warning): `sns:List*`, `sqs:ListQueues`, `sqs:GetQueueAttributes`, `dynamodb:ListTables`,
`dynamodb:DescribeTable`, `events:List*`, `s3:ListAllMyBuckets`,
`s3:GetBucketNotification`, `apigateway:GET`, `states:List*`, `states:DescribeStateMachine`,
`secretsmanager:ListSecrets`, `lambda:ListEventSourceMappings`, `ecs:List*`, `ecs:Describe*`,
`iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:GetPolicy`,
`iam:GetPolicyVersion`, `ec2:DescribeRouteTables`, `ec2:DescribeNetworkAcls`,
`ec2:DescribeTransitGateway*`, `ec2:GetTransitGatewayRouteTablePropagations`,
`ec2:DescribeVpcPeeringConnections`, `ec2:DescribeManagedPrefixLists`,
`route53:ListHostedZones`, `route53:GetHostedZone`, `route53resolver:List*`,
`config:DescribeConfigurationRecorderStatus`, `config:GetResourceConfigHistory`,
`resource-explorer-2:GetIndex`, `resource-explorer-2:ListResources`, `xray:GetServiceGraph`,
`kafka:ListClustersV2` (the MSK list call that covers provisioned and serverless clusters).
Flow logs: `ec2:DescribeFlowLogs`, `logs:DescribeLogGroups`, `logs:StartQuery`,
`logs:GetQueryResults`, `logs:StopQuery`.

### AWS permissions per feature

All permissions are read-only. **Required** ones are needed for a Refresh; **optional** ones can
be left out – the feature or source is skipped with a Refresh / crawl warning (or, for opt-in
sources, simply not enabled).

| feature | AWS permissions | required? |
|---|---|---|
| Discovery / Refresh (also IP List, Visual IP view, scheduled Refresh) | `sts:GetCallerIdentity`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeVpcEndpoints`, `lambda:ListFunctions`, `elasticloadbalancing:DescribeLoadBalancers` | **required** |
| Account alias in the header | `iam:ListAccountAliases` | optional (falls back to account id / display name) |
| EC2 instance names and attachment IPs | `ec2:DescribeInstances` | optional (skipped with warning) |
| Visual: LB → target and security group connections | `elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth`, `ec2:DescribeSecurityGroups` | optional (connections left out) |
| Visual IP view: Transit Gateway links | `ec2:DescribeTransitGatewayAttachments`, `ec2:DescribeRouteTables` | optional (missing permission = warning, shown in the diagram's note) |
| Managed-service ENI names (RDS / Aurora, Redshift, ElastiCache, OpenSearch, MSK) | `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `redshift:DescribeClusters`, `elasticache:DescribeCacheClusters`, `elasticache:DescribeReplicationGroups`, `es:ListDomainNames`, `es:DescribeDomains`, `kafka:ListClustersV2` | optional (missing permission = warning + skip; ENIs keep the generic name) |
| Scale headroom (ASG and ECS service maximums) | `autoscaling:DescribeAutoScalingGroups`, `application-autoscaling:DescribeScalableTargets` | optional (missing permission = warning; headroom uses what is known) |
| Ownership: tags, CloudFormation | `tag:GetResources`, `cloudformation:ListStacks`, `cloudformation:ListStackResources` | optional (skipped with warning) |
| Ownership: CloudTrail creator | `cloudtrail:LookupEvents` | optional, **opt-in** in Settings |
| Extended view: services | `sns:List*`, `sqs:ListQueues`, `sqs:GetQueueAttributes`, `dynamodb:ListTables`, `dynamodb:DescribeTable`, `events:List*`, `s3:ListAllMyBuckets`, `s3:GetBucketNotification`, `apigateway:GET`, `states:List*`, `states:DescribeStateMachine`, `secretsmanager:ListSecrets`, `lambda:ListEventSourceMappings`, `ecs:List*`, `ecs:Describe*`, `kafka:ListClustersV2` | optional, each source skipped with warning |
| Extended view: IAM evidence | `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion` | optional, skipped with warning |
| Extended view: network | `ec2:DescribeRouteTables`, `ec2:DescribeNetworkAcls`, `ec2:DescribeTransitGateway*`, `ec2:GetTransitGatewayRouteTablePropagations`, `ec2:DescribeVpcPeeringConnections`, `ec2:DescribeManagedPrefixLists`, `route53:ListHostedZones`, `route53:GetHostedZone`, `route53resolver:List*` | optional, skipped with warning |
| Extended view: AWS Config | `config:DescribeConfigurationRecorderStatus`, `config:GetResourceConfigHistory` | optional, skipped with warning |
| Extended view: Resource Explorer | `resource-explorer-2:GetIndex`, `resource-explorer-2:ListResources` | optional, skipped with warning |
| Extended view: X-Ray | `xray:GetServiceGraph` | optional, skipped with warning |
| Flow logs | `ec2:DescribeFlowLogs`, `logs:DescribeLogGroups`, `logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery` | optional, **opt-in** per run |
| Trends, Diff, CIDR planner, Report | none – computed from stored snapshots | – |
| `iplens check` with `--snapshot` | none | – |
| `iplens check` live mode | `ec2:DescribeSubnets`, `ec2:DescribeNetworkInterfaces`; optional `autoscaling:DescribeAutoScalingGroups`, `ecs:ListClusters`, `ecs:ListServices`, `ecs:DescribeServices`, `application-autoscaling:DescribeScalableTargets` | EC2 ones **required** (error = exit 2); others optional (note, demand skipped) |
| Terraform sync | `sts:GetCallerIdentity`; S3 backends: `s3:ListBucket`, `s3:GetObject` on the state object, and `sts:AssumeRole` when the backend names a role; other backends: whatever `terraform init` needs to read their state | optional (enrichment off by default) |

Besides the `Describe` / `List` / `Get` prefixes, the guard's explicit allowlist is exactly:
`logs:StartQuery`, `logs:GetQueryResults`, `logs:StopQuery`, `logs:FilterLogEvents` (CloudWatch
Logs reads for flow logs), `sts:AssumeRole` (Terraform S3 backends with a role), and the ownership
sources `tag:GetResources`, `cloudformation:ListStacks`, `cloudformation:ListStackResources` and
`cloudtrail:LookupEvents`.

## Rules

| kind | params | effect |
|---|---|---|
| `lambda_vpc_required` | – | blocks "run Lambda outside VPC"; flags non-VPC functions |
| `internal_only` | `scope`: `load_balancer` / `vpc_endpoint` / `both` | blocks public-path suggestions; flags internet-facing LBs |
| `subnet_reserved` | `subnet_ids` | blocks any suggestion touching or targeting the subnets |
| `min_free_pct` | `percent`, optional `subnet_ids` | blocks moves and subnet shrinks that drop a subnet below the threshold; flags subnets below it |
| `protected_eni` | `pattern` (regex) | blocks suggestions that remove matching ENIs |

`iplens check --rules` enforces the same rules on a Terraform plan; see
[Pre-deploy fit check](#pre-deploy-fit-check-ci).

```yaml
rules:
  - name: keep-20pct-free
    kind: min_free_pct
    enabled: true
    params: {percent: 20, subnet_ids: []}
```

## Development

```bash
.venv/bin/python -m playwright install chromium   # once, for the browser test
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/python -m build                         # sdist + wheel into dist/
```

AWS is mocked with moto in tests; fixtures use placeholder data only.
`tests/test_visual_browser.py` drives the Visual page in headless Chromium (Playwright's own
download, `$IPLENS_CHROMIUM`, or `/opt/pw-browsers/chromium`). Locally it is skipped when no
browser is available; with `IPLENS_REQUIRE_BROWSER=1` (set in CI) that is a failure instead.

### Releasing

The version lives only in `pyproject.toml` (`iplens --version` reads the installed package
metadata). Bump it, merge, then push a matching tag, e.g. `v1.0.0`:
`.github/workflows/publish.yml` checks that the tag equals the version, runs the tests, builds and
publishes to PyPI via Trusted Publishing (environment `pypi`).

## Vendored front-end assets

The app must work without CDN access, so all browser assets are shipped in the package:

| asset | path | source | license |
|---|---|---|---|
| cytoscape.js 3.34.3 (`dist/cytoscape.min.js`, unmodified) | `iplens/static/vendor/cytoscape.min.js` | npm package `cytoscape@3.34.3` | MIT – `iplens/static/vendor/cytoscape.LICENSE` |
| dagre (`dagre.min.js`, unmodified) | `iplens/static/vendor/dagre.min.js` | npm package `dagre` | MIT – `iplens/static/vendor/dagre.LICENSE` |

SVG export is rendered server-side (`iplens/diagram.py`, icons embedded as data URIs) rather than
with the `cytoscape-svg` extension, which is GPL-3.0 licensed, not MIT.
| AWS Architecture Icons (14 SVGs, unmodified, original file names) | `iplens/static/icons/aws/` | AWS Architecture Icons package, release 2026-07-31 (`Icon-package_07312026`), https://aws.amazon.com/architecture/icons/ | see below |

**AWS Architecture Icons license.** The icons are © Amazon Web Services, Inc. or its affiliates.
The 2026-07-31 icon package ships without a `LICENSE.txt`; its usage terms are those published on
the AWS Architecture Icons page: *"We allow customers and partners to use these toolkits and assets
to create architecture diagrams."* IPLens uses them only for that purpose (its architecture diagram
view). They are not covered by IPLens' own license. If a future package release includes a
`LICENSE.txt`, place it at `iplens/static/icons/aws/LICENSE.txt` and update this section.

To update an icon, take the file from the matching folder of a newer package
(`Architecture-Service-Icons_*/…/48/`, `Resource-Icons_*/Res_Networking-Content-Delivery/`,
`Architecture-Group-Icons_*/`) and keep the file name, or update `TYPE_ICONS` / `LB_ICONS` /
`VPC_ICON` in `iplens/queries.py`.
