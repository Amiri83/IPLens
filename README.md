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
2. **Overview → Refresh from AWS** – takes a read-only snapshot of VPCs, subnets, ENIs and their
   private IPs (plus Lambda, VPC endpoint and load balancer metadata).
3. Browse the **VPC → subnet tree**, the per-subnet **address grid**, and the searchable **IP table**.
4. Define **Rules** (GUI or YAML import/export) and review **Suggestions**; anything a rule forbids is
   greyed out together with the IPs it would have saved.
5. **Logs** shows the application log file.

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
