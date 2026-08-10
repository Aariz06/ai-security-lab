param([string]$Profile = "aariz-lab")

Write-Output "# AWS Inventory - $(Get-Date -Format 'yyyy-MM-dd')`n"

Write-Output "## Account"
aws sts get-caller-identity --profile $Profile --output table

Write-Output "`n## IAM Users"
aws iam list-users --profile $Profile --query 'Users[].{User:UserName,Created:CreateDate}' --output table

Write-Output "`n## S3 Buckets"
aws s3 ls --profile $Profile

Write-Output "`n## Security Groups"
aws ec2 describe-security-groups --profile $Profile --query 'SecurityGroups[].{Name:GroupName,ID:GroupId}' --output table

Write-Output "`n## EC2 Instances"
aws ec2 describe-instances --profile $Profile --query 'Reservations[].Instances[].{ID:InstanceId,State:State.Name}' --output table