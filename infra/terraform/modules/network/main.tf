# VPC over two AZs. Tasks run in public subnets with public IPs and no NAT gateway (cost, and the
# only egress they need is the Cloudflare Tunnel and AWS APIs). Nothing is reachable from the
# internet: the service security group has no ingress rules. Data stores live in private subnets
# that have no route to the internet gateway at all.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs = slice(data.aws_availability_zones.available.names, 0, var.az_count)
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "${var.name_prefix}-vpc" }
}

# Close the default security group: nothing may use it by accident.
resource "aws_default_security_group" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-default-closed" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count = var.az_count

  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-public-${local.azs[count.index]}", Tier = "public" }
}

resource "aws_subnet" "private" {
  count = var.az_count

  vpc_id                  = aws_vpc.this.id
  availability_zone       = local.azs[count.index]
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index + 8)
  map_public_ip_on_launch = false

  tags = { Name = "${var.name_prefix}-private-${local.azs[count.index]}", Tier = "data" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.this.id
}

resource "aws_route_table_association" "public" {
  count = var.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Local routes only: no default route.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-private" }
}

resource "aws_route_table_association" "private" {
  count = var.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# The Fargate task's security group. No ingress (Cloudflare Tunnel dials out). Egress is
# 443 (R2, AWS APIs, Web Push), 7844 (Tunnel), and the two data-store ports inside the VPC.
resource "aws_security_group" "service" {
  name        = "${var.name_prefix}-service"
  description = "powehi-server tasks: no ingress"
  vpc_id      = aws_vpc.this.id

  tags = { Name = "${var.name_prefix}-service" }
}

resource "aws_vpc_security_group_egress_rule" "service_https" {
  security_group_id = aws_security_group.service.id
  description       = "HTTPS out: Cloudflare Tunnel, R2, AWS APIs, push services"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0" # trivy:ignore:AVD-AWS-0104
}

# Tunnel (QUIC) uses UDP 7844 and TCP 7844 to Cloudflare.
resource "aws_vpc_security_group_egress_rule" "service_tunnel_tcp" {
  security_group_id = aws_security_group.service.id
  description       = "cloudflared tunnel TCP"
  ip_protocol       = "tcp"
  from_port         = 7844
  to_port           = 7844
  cidr_ipv4         = "0.0.0.0/0" # trivy:ignore:AVD-AWS-0104
}

resource "aws_vpc_security_group_egress_rule" "service_tunnel_udp" {
  security_group_id = aws_security_group.service.id
  description       = "cloudflared tunnel QUIC"
  ip_protocol       = "udp"
  from_port         = 7844
  to_port           = 7844
  cidr_ipv4         = "0.0.0.0/0" # trivy:ignore:AVD-AWS-0104
}

resource "aws_vpc_security_group_egress_rule" "service_postgres" {
  security_group_id = aws_security_group.service.id
  description       = "PostgreSQL inside the VPC"
  ip_protocol       = "tcp"
  from_port         = 5432
  to_port           = 5432
  cidr_ipv4         = var.vpc_cidr
}

resource "aws_vpc_security_group_egress_rule" "service_valkey" {
  security_group_id = aws_security_group.service.id
  description       = "Valkey inside the VPC"
  ip_protocol       = "tcp"
  from_port         = 6379
  to_port           = 6379
  cidr_ipv4         = var.vpc_cidr
}
