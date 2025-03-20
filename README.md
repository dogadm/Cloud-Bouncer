
# Cloud Bouncer: Intelligent AWS Compliance Enforcer

### Keeping the bad configs out of your AWS enterprise! 🚪🚫

This project serves as a comprehensive guide for deploying an enterprise-grade security compliance and governance framework on AWS using Terraform. It outlines best practices for monitoring cloud environments, enforcing security policies, and automating compliance controls efficiently.

Our hybrid approach leverages Terraform modules to distinctly separate compliance monitoring from enforcement, ensuring both flexibility and scalability in cloud security management.

## Why Security Frameworks Matter?
In modern cloud environments, security is a **shared responsibility** between cloud providers and organizations. Implementing a structured **Cloud Security Framework** ensures:
- ✅ **Robust Identity & Access Controls**
- ✅ **Data Protection & Encryption**
- ✅ **Secure Networking & Compliance**
- ✅ **Automated Monitoring & Threat Detection**
- ✅ **Disaster Recovery & Business Continuity**

By integrating these principles, organizations can proactively mitigate security risks, achieve regulatory compliance, and enhance cloud security posture.


## Diagrams

### Cloud Security Framework
The following diagram outlines the key components of a **Cloud Security Framework**, providing best practices for securing cloud environments through **identity management, network security, compliance, monitoring, and disaster recovery**.


![image alt](https://github.com/dogadm/Cloud-Bouncer/blob/df210cce67166f520a9b9da56be039d3d4202b19/Diagram/Cloud_Security_Framework_1.jpeg)

📜 **[View Cloud Security Framework]([./Cloud_Security_Framework.pdf](https://github.com/dogadm/Cloud-Bouncer/blob/5a36a6bceab314639d0bddf569c130807798e031/Diagram/Cloud_Security_Framework.pdf))**

### AWS Cloud Security Framework
For organizations deploying security in **AWS**, the following framework highlights **AWS-native security services** mapped to the **Cloud Security Framework**.

📜 **[View AWS Cloud Security Framework](./AWS_Cloud_Security_Framework.pdf)**



Before deploying this framework, ensure the following prerequisites are met:

✅ AWS Account with Administrator Access  
✅ Terraform installed on your local system  
✅ AWS CLI configured with necessary permissions  
✅ AWS Config and AWS Security Hub enabled  
✅ IAM roles and policies created for Terraform execution  

## Step 1:  Setting Up Terraform Hybrid Compliance

The Terraform Hybrid Compliance model consists of compliance monitoring and enforcement modules. The main configuration file defines the modules and a variable for enabling automatic remediation.

Create a file named `main.tf` and insert the following configuration:

```hcl
provider "aws" {
  region = "us-east-1"
}

module "compliance_check" {
  source = "./modules/compliance_check"
}

module "compliance_enforcement" {
  source  = "./modules/compliance_enforcement"
  enabled = var.enable_auto_remediation  # Controlled by a variable
}

variable "enable_auto_remediation" {
  description = "Enable or disable automatic compliance enforcement"
  type        = bool
  default     = false
}

```






## Step 2: Creating Terraform Modules

The Terraform Hybrid Compliance module structure ensures flexibility in managing compliance. Create the following directory structure:

```bash
/terraform
│── /modules
│   │── compliance_check/         # Contains AWS Config Rules
│   │── compliance_enforcement/   # Contains AWS Lambda + EventBridge
│── main.tf   # Calls both modules conditionally

```

Inside the `modules/compliance_check/` directory, create a `compliance_check.tf` file with the following configuration:

```hcl
# -------------------------------
# AWS Provider Configuration
# -------------------------------
provider "aws" {
  region = var.region  # Use the region specified in the variable above
}

# -------------------------------
# Enable AWS Security Hub
# -------------------------------
resource "aws_securityhub_account" "main" {}

# -------------------------------
# Enable AWS GuardDuty
# -------------------------------
resource "aws_guardduty_detector" "main" {
  enable = true  # Ensures GuardDuty is enabled for threat detection
}

# -------------------------------
# AWS Config Rules - Compliance Checks
# -------------------------------

# Rule 1: Ensure S3 Buckets are not Publicly Accessible
resource "aws_config_rule" "s3_bucket_public_access" {
  name = "s3-bucket-public-access"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"  # AWS-managed rule to check S3 public read access
  }
}

# Rule 2: Ensure IAM Users Do Not Have Inline Policies
resource "aws_config_rule" "iam_no_inline_policies" {
  name = "iam-no-inline-policies"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_INLINE_POLICIES"  # AWS-managed rule to check IAM inline policies
  }
}

# Rule 3: Ensure EBS Volumes are Encrypted
resource "aws_config_rule" "ebs_encryption_check" {
  name = "ebs-encryption-check"
  source {
    owner             = "AWS"
    source_identifier = "EBS_ENCRYPTED_VOLUMES"  # AWS-managed rule to check EBS volume encryption
  }
}

# Rule 4: Ensure All Resources Have Mandatory Tags
resource "aws_config_rule" "custom_tag_compliance" {
  name        = "custom-tag-compliance"
  description = "Ensures all resources have mandatory tags"
  source {
    owner             = "AWS"
    source_identifier = "REQUIRED_TAGS"  # AWS-managed rule to enforce required tags
  }
  input_parameters = <<PARAMS
{
  "tag1Key": "Environment",
  "tag2Key": "Owner"
}
PARAMS
}

# -------------------------------
# Create an SNS Topic for Security Alerts
# -------------------------------
resource "aws_sns_topic" "security_alerts" {
  name = "SecurityAlerts"  # SNS Topic for security-related notifications
}

# Subscribe an email address to the SNS Topic
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn  # Reference the SNS Topic
  protocol  = "email"                             # Set the protocol to email
  endpoint  = "security-team@example.com"         # Email where alerts will be sent
}

# -------------------------------
# Enable AWS Security Hub Finding Aggregator
# -------------------------------
resource "aws_securityhub_finding_aggregator" "siem_integration" {
  linking_mode = "ALL_REGIONS"  # Aggregates security findings from all AWS regions
}

# -------------------------------
# CloudWatch Event Rule - Detect Compliance Violations
# -------------------------------
resource "aws_cloudwatch_event_rule" "compliance_violation_detection" {
  name        = "ComplianceViolationDetectionRule"
  description = "Detects compliance violations in AWS Config"
  event_pattern = <<EOF
{
  "source": ["aws.config"],  # Event source is AWS Config
  "detail-type": ["Config Rules Compliance Change"],  # Trigger event for compliance changes
  "detail": {
    "configRuleName": ["s3-bucket-public-access", "iam-no-inline-policies", "ebs-encryption-check", "custom-tag-compliance"],  # Monitored rules
    "newEvaluationResult": {
      "complianceType": ["NON_COMPLIANT"]  # Triggers when resources become non-compliant
    }
  }
}
EOF
}

# -------------------------------
# Output Variables for Reference
# -------------------------------

# Output: Names of Compliance Check Rules
output "compliance_check_rules" {
  value = [
    aws_config_rule.s3_bucket_public_access.name,
    aws_config_rule.iam_no_inline_policies.name,
    aws_config_rule.ebs_encryption_check.name,
    aws_config_rule.custom_tag_compliance.name
  ]
}

# Output: SNS Topic ARN for Security Alerts
output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

# Output: Name of the EventBridge Rule Monitoring Compliance
output "eventbridge_rule_name" {
  value = aws_cloudwatch_event_rule.compliance_violation_detection.name
}


```
## Step 3: Deploying Compliance Enforcement

The compliance enforcement module ensures that security violations are automatically remediated. Inside the `modules/compliance_enforcement/` directory, create a `remediation.tf` file with the following:

```hcl
# -------------------------------
# Define AWS Region as a Variable
# -------------------------------
variable "region" {
  description = "AWS region"  # Specifies the AWS region where resources will be deployed
  type        = string        # The variable type is a string
  default     = "us-east-1"   # Default AWS region (can be overridden)
}

# -------------------------------
# Enable/Disable Auto-Remediation
# -------------------------------
variable "enable_auto_remediation" {
  description = "Enable or disable automatic compliance enforcement"
  type        = bool  # Boolean value to toggle auto-remediation
  default     = false # Default is disabled (can be set to true if auto-remediation is required)
}

# -------------------------------
# AWS Provider Configuration
# -------------------------------
provider "aws" {
  region = var.region  # Use the specified AWS region
}

# -------------------------------
# Create an IAM Role for Lambda Execution
# -------------------------------
resource "aws_iam_role" "lambda_role" {
  name = "LambdaComplianceEnforcerRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# -------------------------------
# Create an AWS Lambda Function for S3 Public Access Remediation
# -------------------------------
resource "aws_lambda_function" "s3_remediation" {
  count         = var.enable_auto_remediation ? 1 : 0  # Deploy Lambda only if auto-remediation is enabled
  filename      = "s3_remediation.zip"  # The packaged Lambda function
  function_name = "S3PublicAccessRemediation"
  role          = aws_iam_role.lambda_role.arn  # Attach IAM role for execution permissions
  handler       = "lambda_function.lambda_handler"  # The function handler inside the code
  runtime       = "python3.8"  # Define the Python runtime version
}

# -------------------------------
# Create an AWS Organizations Service Control Policy (SCP)
# to Deny Public Access to S3 Buckets
# -------------------------------
resource "aws_organizations_policy" "deny_s3_public_access" {
  name        = "DenyS3PublicAccessPolicy"
  description = "Service control policy to prevent S3 public access"

  content     = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock"],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
POLICY
}

# -------------------------------
# AWS Control Tower - Enforce Multi-Factor Authentication (MFA)
# -------------------------------
resource "aws_controltower_control" "enforce_mfa" {
  name        = "EnforceMFA"
  description = "Enforces MFA for all IAM users"
}

# -------------------------------
# Deploy Compliance Resources Across AWS Accounts
# Using CloudFormation StackSet
# -------------------------------
resource "aws_cloudformation_stack_set" "compliance_enforcement_stack" {
  name             = "ComplianceEnforcementStackSet"
  description      = "Deploys compliance enforcement resources across multiple AWS accounts"
  permission_model = "SERVICE_MANAGED"  # Uses AWS-managed permissions
  capabilities     = ["CAPABILITY_NAMED_IAM"]  # Allows creating IAM resources

  template_body = <<STACK
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "SecurityHub": {
      "Type": "AWS::SecurityHub::Hub"
    }
  }
}
STACK
}

# -------------------------------
# Create an SNS Topic for Security Alerts
# -------------------------------
resource "aws_sns_topic" "security_alerts" {
  name = "SecurityAlerts"
}

# Subscribe an email address to the SNS Topic
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn  # Reference the SNS Topic
  protocol  = "email"                             # Set the protocol to email
  endpoint  = "security-team@example.com"         # Email where alerts will be sent
}

# -------------------------------
# Enable AWS Security Hub Finding Aggregator
# -------------------------------
resource "aws_securityhub_finding_aggregator" "siem_integration" {
  linking_mode = "ALL_REGIONS"  # Aggregates security findings from all AWS regions
}

# -------------------------------
# Output Variables for Reference
# -------------------------------

# Output: Name of Compliance Enforcement Lambda (only if auto-remediation is enabled)
output "compliance_enforcement_lambdas" {
  value = var.enable_auto_remediation ? [
    aws_lambda_function.s3_remediation[0].function_name
  ] : ["Auto-remediation disabled"]
}

# Output: SNS Topic ARN for Security Alerts
output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

# Output: CloudFormation StackSet Name
output "cloudformation_stack_set_name" {
  value = aws_cloudformation_stack_set.compliance_enforcement_stack.name
}

# Output: Name of the SCP Policy Preventing S3 Public Access
output "scp_deny_s3_public_access" {
  value = aws_organizations_policy.deny_s3_public_access.name
}

# Output: Name of the Control Tower MFA Enforcement Policy
output "control_tower_mfa_enforcement" {
  value = aws_controltower_control.enforce_mfa.name
}

```
## Step 4: Automating Compliance with EventBridge

To trigger automatic remediation, configure AWS EventBridge to detect compliance violations and invoke AWS Lambda functions.

```hcl
# -------------------------------
# Define AWS Region as a Variable
# -------------------------------
variable "region" {
  description = "AWS region"  # Specifies the AWS region where resources will be deployed
  type        = string        # The variable type is a string
  default     = "us-east-1"   # Default AWS region (can be overridden)
}

# -------------------------------
# Enable/Disable Auto-Remediation
# -------------------------------
variable "enable_auto_remediation" {
  description = "Enable or disable automatic compliance enforcement"
  type        = bool  # Boolean value to toggle auto-remediation
  default     = false # Default is disabled (can be set to true if auto-remediation is required)
}

# -------------------------------
# AWS Provider Configuration
# -------------------------------
provider "aws" {
  region = var.region  # Use the specified AWS region
}

# -------------------------------
# Create an IAM Role for Lambda Execution
# -------------------------------
resource "aws_iam_role" "lambda_role" {
  name = "LambdaComplianceEnforcerRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

# -------------------------------
# Create an AWS Lambda Function for S3 Public Access Remediation
# -------------------------------
resource "aws_lambda_function" "s3_remediation" {
  count         = var.enable_auto_remediation ? 1 : 0  # Deploy Lambda only if auto-remediation is enabled
  filename      = "s3_remediation.zip"  # The packaged Lambda function
  function_name = "S3PublicAccessRemediation"
  role          = aws_iam_role.lambda_role.arn  # Attach IAM role for execution permissions
  handler       = "lambda_function.lambda_handler"  # The function handler inside the code
  runtime       = "python3.8"  # Define the Python runtime version
}

# -------------------------------
# AWS CloudWatch Event Rule - Detect Compliance Violations
# -------------------------------
resource "aws_cloudwatch_event_rule" "compliance_violation" {
  count       = var.enable_auto_remediation ? 1 : 0  # Create this rule only if auto-remediation is enabled
  name        = "ComplianceViolationRule"
  description = "Triggers remediation on security violations"
  
  event_pattern = <<EOF
{
  "source": ["aws.config"],  # AWS Config is the source
  "detail-type": ["Config Rules Compliance Change"],  # Listens for compliance state changes
  "detail": {
    "configRuleName": ["s3-bucket-public-access", "iam-no-inline-policies", "ebs-encryption-check"],  # Monitored rules
    "newEvaluationResult": {
      "complianceType": ["NON_COMPLIANT"]  # Trigger only if a resource becomes non-compliant
    }
  }
}
EOF
}

# -------------------------------
# Create an EventBridge Target to Trigger Lambda
# -------------------------------
resource "aws_cloudwatch_event_target" "lambda_target_s3" {
  count      = var.enable_auto_remediation ? 1 : 0  # Create this resource only if auto-remediation is enabled
  rule      = aws_cloudwatch_event_rule.compliance_violation[0].name  # Attach to the compliance violation rule
  target_id = "S3RemediationLambda"  # Identifier for the target
  arn       = aws_lambda_function.s3_remediation[0].arn  # Lambda function to be triggered
}

# -------------------------------
# Grant EventBridge Permission to Invoke Lambda
# -------------------------------
resource "aws_lambda_permission" "allow_eventbridge_s3" {
  count         = var.enable_auto_remediation ? 1 : 0  # Only create if auto-remediation is enabled
  statement_id  = "AllowExecutionFromEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.s3_remediation[0].function_name  # The function that will be invoked
  principal     = "events.amazonaws.com"  # Allow EventBridge to trigger Lambda
}

# -------------------------------
# Create an SNS Topic for Security Alerts
# -------------------------------
resource "aws_sns_topic" "security_alerts" {
  name = "SecurityAlerts"
}

# -------------------------------
# Subscribe an Email Address to the SNS Topic
# -------------------------------
resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.security_alerts.arn  # Reference the SNS Topic
  protocol  = "email"                             # Set the protocol to email
  endpoint  = "security-team@example.com"         # Email where alerts will be sent
}

# -------------------------------
# Enable AWS Security Hub Finding Aggregator
# -------------------------------
resource "aws_securityhub_finding_aggregator" "siem_integration" {
  linking_mode = "ALL_REGIONS"  # Aggregates security findings from all AWS regions
}

# -------------------------------
# Output Variables for Reference
# -------------------------------

# Output: Name of Compliance Enforcement Lambda (only if auto-remediation is enabled)
output "compliance_enforcement_lambdas" {
  value = var.enable_auto_remediation ? [
    aws_lambda_function.s3_remediation[0].function_name
  ] : ["Auto-remediation disabled"]
}

# Output: SNS Topic ARN for Security Alerts
output "sns_topic_arn" {
  value = aws_sns_topic.security_alerts.arn
}

# Output: Name of the EventBridge Rule Monitoring Compliance (if enabled)
output "eventbridge_rule_name" {
  value = var.enable_auto_remediation ? aws_cloudwatch_event_rule.compliance_violation[0].name : "EventBridge disabled"
}

```
## Step 5: Deploying and Verifying

Once all configurations are in place, follow these steps to deploy the compliance framework:

Initialize Terraform:  
   ```bash
   terraform init
   ```
Validate the Configuration:  
   ```bash
   terraform validate
   ```
Plan the Deployment:  
   ```bash
   terraform plan
   ```
Apply the Deployment:  
   ```bash
   terraform apply -auto-approve
   ```

After successful deployment, verify the following:

✅ AWS Config should list compliance violations.  
✅ AWS Security Hub should display findings.  
✅ AWS Lambda should automatically remediate non-compliant resources.  
✅ AWS EventBridge should trigger alerts and actions when compliance violations occur.  


## Conclusion

This project provides a step-by-step approach to deploying an enterprise security compliance framework on AWS. By leveraging Terraform, AWS Config, Security Hub, and automated remediation, organizations can ensure continuous compliance and security in cloud environments.
## Used By

This project is used by the following companies:

- Equans
- Plodny


## References

AWS Documentation:

 * AWS Config: [AWS Config Developer Guide](https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html)​

 * AWS Security Hub: [AWS Security Hub User Guide](https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub.html)   

 * Amazon GuardDuty: [Amazon GuardDuty User Guide](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html)   ​

 * AWS Lambda: [AWS Lambda Developer Guide](https://docs.aws.amazon.com/lambda/latest/dg/welcome.html)​

* Amazon EventBridge (formerly CloudWatch Events): [Amazon EventBridge User Guide​](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-what-is.html)

 * Amazon SNS: [Amazon SNS Developer Guide](https://docs.aws.amazon.com/sns/latest/dg/welcome.html)​

Terraform Documentation:

* Terraform AWS Provider: [Terraform AWS Provider Documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)​

* AWS Config Rule Resource: [Terraform aws_config_rule Resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_config_rule)​

* AWS Lambda Function Resource: [Terraform aws_lambda_function Resource​](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_function)

* AWS CloudWatch Event Rule Resource: [Terraform aws_cloudwatch_event_rule Resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_event_rule)

* AWS SNS Topic Resource: [Terraform aws_sns_topic Resource](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic)




## 🔗 Links
[![portfolio](https://img.shields.io/badge/my_portfolio-000?style=for-the-badge&logo=ko-fi&logoColor=white)](https://katherineoelsner.com/)
[![linkedin](https://img.shields.io/badge/linkedin-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/adeoladolapo/)



## Support

🚀 **Ready to deploy this in your environment?** 
Fork this repo or reach out for collaborations!
Email talk2me@adeoladolapo.com 

