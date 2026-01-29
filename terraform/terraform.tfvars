aws_region = "us-east-1"
instance_type = "t3.micro"  # Free tier eligible - 750 hours/month first 12 months
key_name = "mobsf-key"
allowed_ssh_cidrs = ["0.0.0.0/0"]  # Restrict to your IP in production
