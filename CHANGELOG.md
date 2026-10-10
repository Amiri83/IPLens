# Changelog

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
