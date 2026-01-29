variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type for MobSF"
  type        = string
  default     = "t3.medium"
}

variable "key_name" {
  description = "AWS EC2 key pair name"
  type        = string
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["0.0.0.0/32"]  # Restrict to your IP in production
}
