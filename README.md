# IPLens
Local web app for private IPv4 usage visibility &amp; optimization across one or more AWS accounts

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/iplens            # http://127.0.0.1:8077
```

Data (SQLite DB, encryption key, default log dir) lives in `$IPLENS_HOME` (default `~/.iplens`).

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
   resource, its subnet or its VPC. Both Visual views filter by environment and can group / colour
   by it.
4. **Visual** – nested diagram per VPC: VPC box → subnet boxes (CIDR, used/idle/free) → one node
   per resource ENI with its AWS icon, name and IPs. More than 10 nodes of one type in a subnet are
   collapsed into a group node (click to expand). Scroll/drag to zoom and pan; double-click a node
   to open its ENI. VPC/subnet borders and the legend can be toggled (remembered per account).
   Both views share one toolbar (zoom, Fit, Expand / Collapse groups, Reset layout) and a
   **Layout** choice – Grid (default), Hierarchy (dagre), Circle, Concentric, Breadthfirst – that
   keeps every box (VPC, subnet, expanded service group, swimlane) together; the layout and the
   expanded groups are remembered per account and view, dragged node positions per account + VPC
   + view until **Reset layout** (which also leaves focus mode). **Export SVG** / **Export
   draw.io** download the view exactly as shown (draw.io: `mxgraph.aws4` shapes, VPC and subnets
   as containers, edges kept). Data comes from `GET /visual/data.json?vpc=<vpc-id>`.
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
   greyed out together with the IPs it would have saved.
7. **Logs** shows the application log file.

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
`elasticloadbalancing:DescribeTargetGroups`, `elasticloadbalancing:DescribeTargetHealth` and
`ec2:DescribeSecurityGroups` add load balancer → target and security group reference
connections to the Visual page; without them those connections are left out.
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

## Rules

| kind | params | effect |
|---|---|---|
| `lambda_vpc_required` | – | blocks "run Lambda outside VPC"; flags non-VPC functions |
| `internal_only` | `scope`: `load_balancer` / `vpc_endpoint` / `both` | blocks public-path suggestions; flags internet-facing LBs |
| `subnet_reserved` | `subnet_ids` | blocks any suggestion touching or targeting the subnets |
| `min_free_pct` | `percent`, optional `subnet_ids` | blocks moves that drop a subnet below the threshold; flags subnets below it |
| `protected_eni` | `pattern` (regex) | blocks suggestions that remove matching ENIs |

```yaml
rules:
  - name: keep-20pct-free
    kind: min_free_pct
    enabled: true
    params: {percent: 20, subnet_ids: []}
```

## Development

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
```

AWS is mocked with moto in tests; fixtures use placeholder data only.

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
