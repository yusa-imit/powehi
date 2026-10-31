mock_provider "aws" {
  mock_data "aws_availability_zones" {
    defaults = {
      names = ["ap-northeast-2a", "ap-northeast-2b", "ap-northeast-2c", "ap-northeast-2d"]
    }
  }
}

variables {
  name_prefix = "powehi-staging"
}

run "two_azs_and_private_has_no_internet_route" {
  command = apply

  assert {
    condition     = length(aws_subnet.public) == 2 && length(aws_subnet.private) == 2
    error_message = "Expected two public and two private subnets."
  }

  assert {
    condition     = length(distinct([for s in aws_subnet.public : s.availability_zone])) == 2
    error_message = "Public subnets must span two AZs."
  }

  assert {
    condition     = length(aws_route_table.private.route) == 0
    error_message = "The private route table must have no inline routes."
  }

  assert {
    condition     = alltrue([for s in aws_subnet.public : s.map_public_ip_on_launch == false])
    error_message = "Public IPs are assigned by the task, never by the subnet."
  }

  assert {
    condition     = aws_route.public_internet.route_table_id == aws_route_table.public.id && alltrue([for a in aws_route_table_association.private : a.route_table_id == aws_route_table.private.id]) && alltrue([for a in aws_route_table_association.public : a.route_table_id == aws_route_table.public.id])
    error_message = "The internet route and the public table belong to the public subnets only."
  }
}

run "service_sg_has_no_ingress" {
  command = apply

  assert {
    condition     = length(aws_security_group.service.ingress) == 0
    error_message = "The service security group must not accept inbound traffic."
  }

  assert {
    condition     = aws_default_security_group.this.vpc_id == aws_vpc.this.id
    error_message = "The default security group must be managed (closed)."
  }
}

run "bad_prefix_rejected" {
  command = plan

  variables {
    name_prefix = "other"
  }

  expect_failures = [var.name_prefix]
}
