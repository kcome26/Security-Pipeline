# Terraform configuration for hosting security scanning infrastructure on cloud
# Supports AWS, Azure, or GCP

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Security group for MobSF instance
resource "aws_security_group" "mobsf_sg" {
  name        = "security-pipeline-mobsf"
  description = "Security group for MobSF scanning instance"

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Restrict to GitHub IP ranges in production
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 instance for MobSF
resource "aws_instance" "mobsf" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.mobsf_sg.id]

  user_data = base64encode(file("${path.module}/init-mobsf.sh"))

  tags = {
    Name = "security-pipeline-mobsf"
  }
}

# Get latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]  # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
}

# Output MobSF API endpoint
output "mobsf_endpoint" {
  value       = "http://${aws_instance.mobsf.public_ip}:8000"
  description = "MobSF API endpoint"
}

output "mobsf_instance_id" {
  value = aws_instance.mobsf.id
}
