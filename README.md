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
3. **IP List** – one flat table of every private IP in the latest snapshot (IP, subnet, VPC,
   resource type, resource name/ref, ENI, status), sorted numerically by address. Filter by VPC,
   subnet, resource type, status or free text; **Export to Excel** downloads the current filter as
   an `.xlsx` (one sheet, header row frozen, autofilter enabled).
4. **Visual** – nested diagram per VPC: VPC box → subnet boxes (CIDR, used/idle/free) → one node
   per resource ENI with its AWS icon, name and IPs. More than 10 nodes of one type in a subnet are
   collapsed into a group node (click to expand). Scroll/drag to zoom and pan; double-click a node
   to open its ENI. VPC/subnet borders can be toggled (remembered per account); dragged node
   positions are saved per account + VPC until **Reset layout**. **Export SVG** / **Export
   draw.io** download the view exactly as shown (draw.io: `mxgraph.aws4` shapes, VPC and subnets
   as containers, edges kept). Data comes from `GET /visual/data.json?vpc=<vpc-id>`.
   The **IP view** is the default; the **Extended view** tab adds a "Regional services" area
   (SNS, SQS, DynamoDB, EventBridge, S3, API Gateway, Step Functions, Lambda, ECS, Secrets Manager
   names) and an "External" area (Transit Gateway, peering, internet via IGW / NAT) beside the VPC.
   **Crawl services** (opt-in) reads them; every connection carries evidence, strongest first:
   *observed* (flow logs, X-Ray) > *configured* (subscriptions, event source mappings, targets,
   routes, ...) > *permitted* (IAM policies of Lambda / ECS roles) > *referenced* (environment
   variables). Environment variable values, policy documents and secret values are only matched
   against known resource names / ARNs in memory and never stored; IAM `Resource: "*"` shows a
   *broad access* badge. **Flow logs** (opt-in) shows the estimated Logs Insights scan size for the
   chosen window (default 1 hour) before running, and stores only ENI↔ENI/port aggregates.
   Filters by service and evidence level apply to the diagram and its exports.
5. Define **Rules** (GUI or YAML import/export) and review **Suggestions**; anything a rule forbids is
   greyed out together with the IPs it would have saved.
6. **Logs** shows the application log file.

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
`resource-explorer-2:GetIndex`, `resource-explorer-2:ListResources`, `xray:GetServiceGraph`.
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
