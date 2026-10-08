# IPLens
Local web app for private IPv4 usage visibility &amp; optimization in a single AWS account

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/iplens            # http://127.0.0.1:8077
```

Data (SQLite DB, encryption key, default log dir) lives in `$IPLENS_HOME` (default `~/.iplens`).

1. **Settings** – choose credentials (environment/default chain, named profile, or access key +
   secret; the secret is Fernet-encrypted in SQLite and never logged), pick a region, set the log
   directory, and use **Test connection**.
2. **Discovery → Refresh from AWS** – takes a read-only snapshot of VPCs, subnets, ENIs and their
   private IPs (plus Lambda, VPC endpoint and load balancer metadata), and shows the
   **VPC → subnet tree** and the per-subnet **address grid**.
3. **IP List** – one flat table of every private IP in the latest snapshot (IP, subnet, VPC,
   resource type, resource name/ref, ENI, status), sorted numerically by address. Filter by VPC,
   subnet, resource type, status or free text; **Export to Excel** downloads the current filter as
   an `.xlsx` (one sheet, header row frozen, autofilter enabled).
4. **Visual** – nested diagram per VPC: VPC box → subnet boxes (CIDR, used/idle/free) → one node
   per resource ENI with its AWS icon, name and IPs. More than 10 nodes of one type in a subnet are
   collapsed into a group node (click to expand). Scroll/drag to zoom and pan; click a node to open
   its ENI. Data comes from `GET /visual/data.json?vpc=<vpc-id>`.
5. Define **Rules** (GUI or YAML import/export) and review **Suggestions**; anything a rule forbids is
   greyed out together with the IPs it would have saved.
6. **Logs** shows the application log file.

## Read-only by construction

Every boto3 client is created through `iplens.aws.AwsGateway`, which registers a botocore
`before-call` hook that rejects any operation not starting with `Describe`, `List` or `Get`.
Minimal IAM permissions:

```
ec2:DescribeVpcs  ec2:DescribeSubnets  ec2:DescribeNetworkInterfaces  ec2:DescribeVpcEndpoints
lambda:ListFunctions  elasticloadbalancing:DescribeLoadBalancers  sts:GetCallerIdentity
```

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
