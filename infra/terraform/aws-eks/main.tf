# QES Platform AWS EKS Infrastructure
# Terraform configuration for production-grade EKS cluster

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.10"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
  
  backend "s3" {
    # Configure S3 backend for state storage
    bucket         = "qes-platform-terraform-state"
    key            = "eks/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    dynamodb_table = "qes-platform-terraform-locks"
  }
}

# Configure AWS Provider
provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "qes-platform"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# Data sources
data "aws_availability_zones" "available" {
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

data "aws_caller_identity" "current" {}

# Local values
locals {
  cluster_name = "${var.project_name}-${var.environment}"
  
  vpc_cidr = "10.0.0.0/16"
  azs      = slice(data.aws_availability_zones.available.names, 0, 3)
  
  tags = {
    Project     = var.project_name
    Environment = var.environment
    ManagedBy   = "terraform"
  }
}

#######################
# VPC Configuration
#######################

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"
  
  name = "${local.cluster_name}-vpc"
  cidr = local.vpc_cidr
  
  azs             = local.azs
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
  
  enable_nat_gateway   = true
  single_nat_gateway   = false
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # VPC Flow Logs for security monitoring
  enable_flow_log                      = true
  create_flow_log_cloudwatch_iam_role  = true
  create_flow_log_cloudwatch_log_group = true
  
  public_subnet_tags = {
    "kubernetes.io/role/elb" = 1
  }
  
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = 1
  }
  
  tags = local.tags
}

#######################
# EKS Cluster
#######################

module "eks" {
  source = "terraform-aws-modules/eks/aws"
  
  cluster_name    = local.cluster_name
  cluster_version = var.kubernetes_version
  
  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access_cidrs = var.cluster_endpoint_public_access_cidrs
  
  # Cluster encryption
  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }
  
  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.intra_subnets
  
  # EKS Managed Node Groups
  eks_managed_node_groups = {
    # General purpose nodes
    general = {
      name = "${local.cluster_name}-general"
      
      instance_types = ["t3.large"]
      capacity_type  = "ON_DEMAND"
      
      min_size     = 2
      max_size     = 10
      desired_size = 3
      
      disk_size = 50
      disk_type = "gp3"
      
      labels = {
        role = "general"
      }
      
      update_config = {
        max_unavailable_percentage = 33
      }
      
      # Use latest EKS optimized AMI
      use_latest_ami = true
      
      # Security groups
      create_security_group = false
      security_group_ids    = [aws_security_group.worker_nodes.id]
    }
    
    # Compute intensive nodes for signature operations
    compute = {
      name = "${local.cluster_name}-compute"
      
      instance_types = ["c5.xlarge"]
      capacity_type  = "ON_DEMAND"
      
      min_size     = 1
      max_size     = 8
      desired_size = 2
      
      disk_size = 100
      disk_type = "gp3"
      
      labels = {
        role = "compute"
      }
      
      taints = {
        compute = {
          key    = "compute"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
      
      update_config = {
        max_unavailable_percentage = 50
      }
      
      use_latest_ami = true
      
      create_security_group = false
      security_group_ids    = [aws_security_group.worker_nodes.id]
    }
    
    # Memory optimized nodes for databases
    memory = {
      name = "${local.cluster_name}-memory"
      
      instance_types = ["r5.large"]
      capacity_type  = "SPOT"
      
      min_size     = 0
      max_size     = 5
      desired_size = 1
      
      disk_size = 100
      disk_type = "gp3"
      
      labels = {
        role = "memory"
      }
      
      taints = {
        memory = {
          key    = "memory"
          value  = "true"
          effect = "NO_SCHEDULE"
        }
      }
      
      update_config = {
        max_unavailable_percentage = 50
      }
      
      use_latest_ami = true
      
      create_security_group = false
      security_group_ids    = [aws_security_group.worker_nodes.id]
    }
  }
  
  # Cluster access entry
  access_entries = {
    admin = {
      kubernetes_groups = []
      principal_arn     = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/QESPlatformAdminRole"
      
      policy_associations = {
        admin = {
          policy_arn = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
          access_scope = {
            type = "cluster"
          }
        }
      }
    }
  }
  
  # Enable IRSA (IAM Roles for Service Accounts)
  enable_irsa = true
  
  # Cluster addons
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.irsa_ebs_csi.iam_role_arn
    }
    aws-efs-csi-driver = {
      most_recent = true
    }
  }
  
  tags = local.tags
}

#######################
# Security Groups
#######################

resource "aws_security_group" "worker_nodes" {
  name_prefix = "${local.cluster_name}-worker-nodes"
  vpc_id      = module.vpc.vpc_id
  
  # Allow communication between worker nodes
  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }
  
  # Allow communication from control plane
  ingress {
    from_port       = 1025
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [module.eks.cluster_security_group_id]
  }
  
  # Allow HTTPS webhooks from control plane
  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [module.eks.cluster_security_group_id]
  }
  
  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.tags, {
    Name = "${local.cluster_name}-worker-nodes-sg"
  })
}

#######################
# KMS Keys
#######################

resource "aws_kms_key" "eks" {
  description             = "EKS Secret Encryption Key for ${local.cluster_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = merge(local.tags, {
    Name = "${local.cluster_name}-eks-encryption"
  })
}

resource "aws_kms_alias" "eks" {
  name          = "alias/${local.cluster_name}-eks"
  target_key_id = aws_kms_key.eks.key_id
}

resource "aws_kms_key" "rds" {
  description             = "RDS Encryption Key for ${local.cluster_name}"
  deletion_window_in_days = 7
  enable_key_rotation     = true
  
  tags = merge(local.tags, {
    Name = "${local.cluster_name}-rds-encryption"
  })
}

resource "aws_kms_alias" "rds" {
  name          = "alias/${local.cluster_name}-rds"
  target_key_id = aws_kms_key.rds.key_id
}

#######################
# IAM Roles for Service Accounts
#######################

module "irsa_ebs_csi" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  
  role_name             = "${local.cluster_name}-ebs-csi"
  attach_ebs_csi_policy = true
  
  oidc_providers = {
    eks = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
  
  tags = local.tags
}

module "irsa_aws_load_balancer_controller" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  
  role_name                              = "${local.cluster_name}-aws-load-balancer-controller"
  attach_load_balancer_controller_policy = true
  
  oidc_providers = {
    eks = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:aws-load-balancer-controller"]
    }
  }
  
  tags = local.tags
}

module "irsa_external_dns" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  
  role_name                     = "${local.cluster_name}-external-dns"
  attach_external_dns_policy    = true
  external_dns_hosted_zone_arns = ["arn:aws:route53:::hostedzone/*"]
  
  oidc_providers = {
    eks = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:external-dns"]
    }
  }
  
  tags = local.tags
}

module "irsa_cluster_autoscaler" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  
  role_name                        = "${local.cluster_name}-cluster-autoscaler"
  attach_cluster_autoscaler_policy = true
  cluster_autoscaler_cluster_names = [local.cluster_name]
  
  oidc_providers = {
    eks = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:cluster-autoscaler"]
    }
  }
  
  tags = local.tags
}

# QES Platform specific IAM role
module "irsa_qes_platform" {
  source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  
  role_name = "${local.cluster_name}-qes-platform"
  
  role_policy_arns = {
    policy = aws_iam_policy.qes_platform.arn
  }
  
  oidc_providers = {
    eks = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["qes-platform:qes-platform"]
    }
  }
  
  tags = local.tags
}

resource "aws_iam_policy" "qes_platform" {
  name = "${local.cluster_name}-qes-platform"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.qes_platform_storage.arn,
          "${aws_s3_bucket.qes_platform_storage.arn}/*",
          aws_s3_bucket.qes_platform_backups.arn,
          "${aws_s3_bucket.qes_platform_backups.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.database_credentials.arn,
          aws_secretsmanager_secret.redis_auth.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = [
          aws_kms_key.rds.arn,
          aws_kms_key.eks.arn
        ]
      }
    ]
  })
  
  tags = local.tags
}

#######################
# S3 Buckets
#######################

resource "aws_s3_bucket" "qes_platform_storage" {
  bucket = "${local.cluster_name}-storage"
  
  tags = local.tags
}

resource "aws_s3_bucket_encryption_configuration" "qes_platform_storage" {
  bucket = aws_s3_bucket.qes_platform_storage.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "qes_platform_storage" {
  bucket = aws_s3_bucket.qes_platform_storage.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "qes_platform_storage" {
  bucket = aws_s3_bucket.qes_platform_storage.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "qes_platform_backups" {
  bucket = "${local.cluster_name}-backups"
  
  tags = local.tags
}

resource "aws_s3_bucket_encryption_configuration" "qes_platform_backups" {
  bucket = aws_s3_bucket.qes_platform_backups.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "qes_platform_backups" {
  bucket = aws_s3_bucket.qes_platform_backups.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "qes_platform_backups" {
  bucket = aws_s3_bucket.qes_platform_backups.id
  
  rule {
    id     = "backup_lifecycle"
    status = "Enabled"
    
    expiration {
      days = 90
    }
    
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

#######################
# Secrets Manager
#######################

resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${local.cluster_name}-database-credentials"
  description             = "Database credentials for QES Platform"
  recovery_window_in_days = 7
  kms_key_id             = aws_kms_key.rds.arn
  
  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id
  
  secret_string = jsonencode({
    username = var.database_username
    password = var.database_password
  })
}

resource "aws_secretsmanager_secret" "redis_auth" {
  name                    = "${local.cluster_name}-redis-auth"
  description             = "Redis authentication token for QES Platform"
  recovery_window_in_days = 7
  
  tags = local.tags
}

resource "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = aws_secretsmanager_secret.redis_auth.id
  
  secret_string = jsonencode({
    auth_token = var.redis_auth_token
  })
}