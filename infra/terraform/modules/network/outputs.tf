output "vpc_id" {
  description = "VPC ID."
  value       = aws_vpc.this.id
}

output "public_subnet_ids" {
  description = "Subnets for the Fargate tasks (public IP, no inbound)."
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Subnets for RDS and ElastiCache (no route to the internet)."
  value       = aws_subnet.private[*].id
}

output "service_security_group_id" {
  description = "Security group of the powehi-server tasks; the only source the data stores accept."
  value       = aws_security_group.service.id
}
