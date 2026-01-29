# Security Pipeline AWS Setup Script
# Run this script after restarting PowerShell

Write-Host "=== Security Pipeline Setup ===" -ForegroundColor Green

# Step 1: Verify AWS CLI installation
Write-Host "`n1. Checking AWS CLI..." -ForegroundColor Yellow
$awsVersion = Get-Command aws -ErrorAction SilentlyContinue
if ($awsVersion) {
    aws --version
    Write-Host "✓ AWS CLI installed" -ForegroundColor Green
} else {
    Write-Host "✗ AWS CLI not found. Please restart PowerShell and run this script again." -ForegroundColor Red
    exit 1
}

# Step 2: Verify Terraform installation
Write-Host "`n2. Checking Terraform..." -ForegroundColor Yellow
$terraformVersion = Get-Command terraform -ErrorAction SilentlyContinue
if ($terraformVersion) {
    terraform --version
    Write-Host "✓ Terraform installed" -ForegroundColor Green
} else {
    Write-Host "✗ Terraform not found. Please restart PowerShell and run this script again." -ForegroundColor Red
    exit 1
}

# Step 3: Configure AWS credentials
Write-Host "`n3. Configuring AWS credentials..." -ForegroundColor Yellow
Write-Host "You'll need your AWS Access Key ID and Secret Access Key"
Write-Host "Get them from: https://console.aws.amazon.com/iam/home#/security_credentials"
aws configure

# Step 4: Create SSH key pair
Write-Host "`n4. Creating SSH key pair..." -ForegroundColor Yellow
Set-Location -Path "$PSScriptRoot\terraform"

if (-not (Test-Path "mobsf-key")) {
    ssh-keygen -t rsa -b 4096 -f mobsf-key -N '""'
    Write-Host "✓ SSH key created" -ForegroundColor Green
} else {
    Write-Host "✓ SSH key already exists" -ForegroundColor Green
}

# Step 5: Upload SSH key to AWS
Write-Host "`n5. Uploading SSH key to AWS..." -ForegroundColor Yellow
aws ec2 import-key-pair --key-name mobsf-key --public-key-material "fileb://mobsf-key.pub" --region us-east-1 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ SSH key uploaded to AWS" -ForegroundColor Green
} else {
    Write-Host "! SSH key may already exist in AWS - this is OK" -ForegroundColor Yellow
}

# Step 6: Initialize Terraform
Write-Host "`n6. Initializing Terraform..." -ForegroundColor Yellow
terraform init
if ($LASTEXITCODE -eq 0) {
    Write-Host "✓ Terraform initialized" -ForegroundColor Green
} else {
    Write-Host "✗ Terraform initialization failed" -ForegroundColor Red
    exit 1
}

# Step 7: Deploy EC2 instance
Write-Host "`n7. Deploying EC2 instance..." -ForegroundColor Yellow
Write-Host "This will create a t3.micro instance (free tier eligible)"
$confirm = Read-Host "Proceed with deployment? (yes/no)"

if ($confirm -eq "yes") {
    terraform apply -auto-approve
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "`n✓ EC2 instance deployed!" -ForegroundColor Green
        
        # Get instance ID
        $instanceId = terraform output -raw mobsf_instance_id 2>$null
        $endpoint = terraform output -raw mobsf_endpoint 2>$null
        
        Write-Host "`nIMPORTANT - Save these values:" -ForegroundColor Cyan
        Write-Host "Instance ID: $instanceId" -ForegroundColor White
        Write-Host "Endpoint: $endpoint" -ForegroundColor White
        
        # Step 8: Stop instance
        Write-Host "`n8. Stopping instance (to save costs)..." -ForegroundColor Yellow
        aws ec2 stop-instances --instance-ids $instanceId
        Write-Host "✓ Instance stopped" -ForegroundColor Green
        
        # Step 9: GitHub Secrets instructions
        Write-Host "`n=== Next Steps ===" -ForegroundColor Green
        Write-Host "Add these secrets to GitHub (Settings → Secrets → Actions):"
        Write-Host ""
        Write-Host "AWS_ACCESS_KEY_ID = (your AWS access key)" -ForegroundColor Yellow
        Write-Host "AWS_SECRET_ACCESS_KEY = (your AWS secret key)" -ForegroundColor Yellow
        Write-Host "MOBSF_INSTANCE_ID = $instanceId" -ForegroundColor Yellow
        Write-Host "MOBSF_API_KEY = (generate from MobSF web interface)" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "GitHub repo: https://github.com/kcome26/Security-Pipeline/settings/secrets/actions" -ForegroundColor Cyan
        
    } else {
        Write-Host "✗ Deployment failed" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "Deployment cancelled" -ForegroundColor Yellow
}

Write-Host "`n=== Setup Complete ===" -ForegroundColor Green
