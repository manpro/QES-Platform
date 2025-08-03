# QES Platform Terraform Outputs

################################################################################
# Cluster
################################################################################

output "cluster_arn" {
  description = "The Amazon Resource Name (ARN) of the cluster"
  value       = module.eks.cluster_arn
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
}

output "cluster_endpoint" {
  description = "Endpoint for your Kubernetes API server"
  value       = module.eks.cluster_endpoint
}

output "cluster_id" {
  description = "The ID of the EKS cluster. Note: currently a value is returned only for local EKS clusters created on Outposts"
  value       = module.eks.cluster_id
}

output "cluster_name" {
  description = "The name of the EKS cluster"
  value       = module.eks.cluster_name
}

output "cluster_oidc_issuer_url" {
  description = "The URL on the EKS cluster for the OpenID Connect identity provider"
  value       = module.eks.cluster_oidc_issuer_url
}

output "cluster_platform_version" {
  description = "Platform version for the EKS cluster"
  value       = module.eks.cluster_platform_version
}

output "cluster_status" {
  description = "Status of the EKS cluster. One of `CREATING`, `ACTIVE`, `DELETING`, `FAILED`"
  value       = module.eks.cluster_status
}

output "cluster_primary_security_group_id" {
  description = "Cluster security group that was created by Amazon EKS for the cluster"
  value       = module.eks.cluster_primary_security_group_id
}

################################################################################
# Security Groups
################################################################################

output "cluster_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the cluster security group"
  value       = module.eks.cluster_security_group_arn
}

output "cluster_security_group_id" {
  description = "ID of the cluster security group"
  value       = module.eks.cluster_security_group_id
}

output "node_security_group_arn" {
  description = "Amazon Resource Name (ARN) of the node shared security group"
  value       = module.eks.node_security_group_arn
}

output "node_security_group_id" {
  description = "ID of the node shared security group"
  value       = module.eks.node_security_group_id
}

################################################################################
# IRSA
################################################################################

output "oidc_provider" {
  description = "The OpenID Connect identity provider (issuer URL without leading `https://`)"
  value       = module.eks.oidc_provider
}

output "oidc_provider_arn" {
  description = "The ARN of the OIDC Provider if `enable_irsa = true`"
  value       = module.eks.oidc_provider_arn
}

################################################################################
# IAM Role for Service Accounts
################################################################################

output "irsa_qes_platform_role_arn" {
  description = "ARN of IAM role for QES Platform service account"
  value       = module.irsa_qes_platform.iam_role_arn
}

output "irsa_aws_load_balancer_controller_role_arn" {
  description = "ARN of IAM role for AWS Load Balancer Controller"
  value       = module.irsa_aws_load_balancer_controller.iam_role_arn
}

output "irsa_external_dns_role_arn" {
  description = "ARN of IAM role for External DNS"
  value       = module.irsa_external_dns.iam_role_arn
}

output "irsa_cluster_autoscaler_role_arn" {
  description = "ARN of IAM role for Cluster Autoscaler"
  value       = module.irsa_cluster_autoscaler.iam_role_arn
}

output "irsa_ebs_csi_role_arn" {
  description = "ARN of IAM role for EBS CSI Driver"
  value       = module.irsa_ebs_csi.iam_role_arn
}

################################################################################
# EKS Managed Node Group
################################################################################

output "eks_managed_node_groups" {
  description = "Map of attribute maps for all EKS managed node groups created"
  value       = module.eks.eks_managed_node_groups
}

output "eks_managed_node_groups_autoscaling_group_names" {
  description = "List of the autoscaling group names created by EKS managed node groups"
  value       = module.eks.eks_managed_node_groups_autoscaling_group_names
}

################################################################################
# VPC
################################################################################

output "vpc_id" {
  description = "ID of the VPC where the cluster and its nodes will be provisioned"
  value       = module.vpc.vpc_id
}

output "vpc_cidr_block" {
  description = "The CIDR block of the VPC"
  value       = module.vpc.vpc_cidr_block
}

output "private_subnets" {
  description = "List of IDs of private subnets"
  value       = module.vpc.private_subnets
}

output "public_subnets" {
  description = "List of IDs of public subnets"
  value       = module.vpc.public_subnets
}

output "intra_subnets" {
  description = "List of IDs of intra subnets"
  value       = module.vpc.intra_subnets
}

output "vpc_owner_id" {
  description = "The ID of the AWS account that owns the VPC"
  value       = module.vpc.vpc_owner_id
}

################################################################################
# S3 Buckets
################################################################################

output "storage_bucket_id" {
  description = "The name of the S3 bucket for storage"
  value       = aws_s3_bucket.qes_platform_storage.id
}

output "storage_bucket_arn" {
  description = "The ARN of the S3 bucket for storage"
  value       = aws_s3_bucket.qes_platform_storage.arn
}

output "backup_bucket_id" {
  description = "The name of the S3 bucket for backups"
  value       = aws_s3_bucket.qes_platform_backups.id
}

output "backup_bucket_arn" {
  description = "The ARN of the S3 bucket for backups"
  value       = aws_s3_bucket.qes_platform_backups.arn
}

################################################################################
# KMS
################################################################################

output "kms_key_eks_arn" {
  description = "The Amazon Resource Name (ARN) of the EKS KMS key"
  value       = aws_kms_key.eks.arn
}

output "kms_key_rds_arn" {
  description = "The Amazon Resource Name (ARN) of the RDS KMS key"
  value       = aws_kms_key.rds.arn
}

################################################################################
# Secrets Manager
################################################################################

output "database_secret_arn" {
  description = "ARN of the database credentials secret"
  value       = aws_secretsmanager_secret.database_credentials.arn
}

output "redis_secret_arn" {
  description = "ARN of the Redis auth token secret"
  value       = aws_secretsmanager_secret.redis_auth.arn
}

################################################################################
# Kubectl Configuration
################################################################################

output "configure_kubectl" {
  description = "Configure kubectl: make sure you're logged in with the correct AWS profile and run the following command to update your kubeconfig"
  value       = "aws eks --region ${var.aws_region} update-kubeconfig --name ${module.eks.cluster_name}"
}

################################################################################
# Helm Values
################################################################################

output "helm_values" {
  description = "Helm values for QES Platform deployment"
  value = {
    global = {
      storageClass = "gp2"
    }
    
    api = {
      serviceAccount = {
        annotations = {
          "eks.amazonaws.com/role-arn" = module.irsa_qes_platform.iam_role_arn
        }
      }
    }
    
    postgresql = {
      enabled = false
      external = {
        host     = "localhost" # Replace with RDS endpoint
        port     = 5432
        database = "qes_platform"
      }
    }
    
    redis = {
      enabled = false
      external = {
        host = "localhost" # Replace with ElastiCache endpoint
        port = 6379
      }
    }
    
    minio = {
      enabled = false
      external = {
        endpoint = "s3.${var.aws_region}.amazonaws.com"
        bucket   = aws_s3_bucket.qes_platform_storage.id
      }
    }
    
    backup = {
      s3 = {
        bucket = aws_s3_bucket.qes_platform_backups.id
        region = var.aws_region
      }
    }
  }
  sensitive = false
}