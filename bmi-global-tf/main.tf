terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }

  backend "s3" {
    bucket         = "bmi-global-terraform-state"
    dynamodb_table = "bmi-global-state-lock"
    region         = "eu-west-1"
    key            = "terraform.tfstate"
    encrypt        = true
  }
}

provider "aws" {
  region  = var.region
  profile = var.profile
}

locals {

  # Script to install the efs mount helper, provided by AWS, and mount the network drive.
  # References: 
  #   EFS Helper - https://docs.aws.amazon.com/efs/latest/ug/installing-amazon-efs-utils.html#installing-other-distro
  #   efs-utils - https://docs.aws.amazon.com/efs/latest/ug/overview-amazon-efs-utils.html
  #   http.server - starting a simple server to ensure the instances return healthy and do not terminate, pending WP migration.

  user_data = <<-EOT
#!/bin/bash
apt-get update -y
apt-get -y install git binutils
git clone https://github.com/aws/efs-utils /home/ubuntu/efs-utils
cd /home/ubuntu/efs-utils
./build-deb.sh
apt-get -y install ./build/amazon-efs-utils*deb
mkdir -p /mnt/efs
mount -t efs -o tls ${module.efs.id}:/ /mnt/efs
chown -R ubuntu:root /mnt/efs
echo "${module.efs.id}:/ /mnt/efs efs defaults,_netdev 0 0" | sudo tee -a /etc/fstab
python3 -m http.server 8080
EOT
}

module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = var.network_name_prefix
  cidr = "10.0.0.0/16"

  azs = var.azs

  # Could have these as a variable for giving user choice?
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]       # WordPress instances placed in here
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"] # Bastion hosts in here

  # Place a NAT Gateway into each of the configured private subnets
  enable_nat_gateway = true

  enable_dns_hostnames = true

  database_subnet_group_name         = join("-", [var.environment, "private-db"])
  create_database_subnet_group       = true
  create_database_subnet_route_table = true
  database_subnets                   = ["10.0.4.0/24", "10.0.5.0/24", "10.0.6.0/24"]


  create_elasticache_subnet_group       = true
  create_elasticache_subnet_route_table = true
  elasticache_subnets                   = ["10.0.7.0/24", "10.0.8.0/24", "10.0.9.0/24"] # Caching layer

  tags = {
    Terraform   = "true"
    Environment = var.environment
  }
}

# Create a VPC Endpoint, this enabled AWS services to communicate to resources within our VPC without having to traverse the public internet.
# The main reason for creation here, is that Session Manager usually requires an instance to have a public IP address for management, we do not want
# our private subnet instances to have this (they inherently cannot, because they're in a private subnet), so we must use VPC endpoints instead.
# This keeps all communication internal to the AWS network.
module "vpc_vpc-endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "3.4.0"

  vpc_id             = module.vpc.vpc_id
  security_group_ids = [aws_security_group.wp.id]

  endpoints = {
    ssm = {
      service             = "ssm"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ssmmessages = {
      service             = "ssmmessages"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    },
    ec2messages = {
      service             = "ec2messages"
      private_dns_enabled = true
      subnet_ids          = module.vpc.private_subnets
    }
  }
}

# Caching layer via Redis using the ElastiCache service
module "elasticache-redis" {
  source  = "cloudposse/elasticache-redis/aws"
  version = "0.40.0"

  availability_zones = var.azs

  environment                = var.environment
  name                       = "wp-redis"
  vpc_id                     = module.vpc.vpc_id
  subnets                    = module.vpc.private_subnets
  cluster_size               = var.redis_cluster_size
  instance_type              = var.redis_instance_type
  apply_immediately          = true
  engine_version             = var.redis_engine_version
  family                     = var.redis_family
  at_rest_encryption_enabled = var.redis_encryption_at_rest

  security_group_description = "SG for ElastiCache Redis"
  security_group_rules = [
    {
      type                     = "egress"
      from_port                = 0
      to_port                  = 65535
      protocol                 = "-1"
      cidr_blocks              = ["0.0.0.0/0"]
      source_security_group_id = null
      description              = "Allow all outbound traffic"
    },
    {
      type                     = "ingress"
      from_port                = 0
      to_port                  = 65535
      protocol                 = "-1"
      cidr_blocks              = []
      source_security_group_id = aws_security_group.wp.id
      description              = "Allow all inbound traffic from WordPress instance SG"
    },
  ]

  # Apply specific parameters if required.
  # parameter = [
  #   {
  #     name  = "notify-keyspace-events"
  #     value = "lK"
  #   }
  # ]

}

# This provides a standard MySQL RDS instance, however; the AWS recommended best practice is to use Aurora.
# module "db" {
#   source  = "terraform-aws-modules/rds/aws"
#   version = "3.3.0"

#   # Name of the RDS instance
#   identifier = join("-", [var.environment, "wp-db"])

#   engine               = "mysql"
#   engine_version       = var.db_engine_version
#   major_engine_version = var.db_major_engine_version
#   family               = var.db_parameter_group
#   instance_class       = var.db_instance
#   allocated_storage    = var.db_storage


#   name     = var.db_name
#   username = var.db_user
#   password = var.db_password
#   port     = var.db_port

#   multi_az               = true
#   vpc_security_group_ids = [aws_security_group.db.id]

#   maintenance_window = "Mon:00:00-Mon:03:00"
#   backup_window      = "03:00-06:00"

#   tags = {
#     Terraform   = true
#     Environment = var.environment
#   }

#   # DB subnet group
#   subnet_ids = module.vpc.database_subnets

#   # Database Deletion Protection
#   # deletion_protection = true

#   # Stop a snapshot being made when deleting the DB, this is useful for testing purposes when you need to
#   # provision/tear down resources quickly,
#   skip_final_snapshot = true
# }

# Aurora MySQL compatible database, this is an AWS-specific implementation which provides better performance, high availabilty by default,
# and lower running costs. 
module "rds-aurora" {
  source  = "terraform-aws-modules/rds-aurora/aws"
  version = "5.2.0"

  name = join("-", [var.environment, "wp-db"])
  password = var.db_password
  instance_type = var.db_instance
  instance_type_replica = var.db_instance
  engine = "aurora-mysql"
  engine_version = "5.7.12"
  replica_count = 1

  vpc_id = module.vpc.vpc_id
  db_subnet_group_name = module.vpc.database_subnet_group_name
  allowed_cidr_blocks = module.vpc.private_subnets_cidr_blocks

  # Used in a testing environment, set these to true
  apply_immediately = var.db_apply_immediately
  skip_final_snapshot = var.db_skip

}


# Auto scaling group launches instances in the private subnets. There is likely to be extra work
# that is required to get everything setup for a 'BMI Global' instance, but this provides a
# convenient skeleton
module "asg" {
  source  = "terraform-aws-modules/autoscaling/aws"
  version = "~> 4.0"

  name = join("-", [var.environment, "wordpress"])

  min_size                  = 1
  max_size                  = 6
  desired_capacity          = 1 # These can be changed to variables later on
  wait_for_capacity_timeout = 0
  health_check_type         = "ELB" # The instance state is deemed healthy or unhealthy based on the load balancer sending a request to the instances
  vpc_zone_identifier       = module.vpc.private_subnets
  security_groups           = [aws_security_group.wp.id]
  iam_instance_profile_arn  = aws_iam_instance_profile.wp_instance_profile.arn

  # Launch template 
  lt_name          = join("-", [var.environment, "wp-launch-template"])
  description      = join(" ", ["Launch template in the", var.environment, " environment"])
  use_lt           = true
  user_data_base64 = base64encode(local.user_data) # Base64 user data is required within a launch template
  create_lt        = true


  image_id          = data.aws_ami.ubuntu.id # Using latest Ubuntu AMI ID for now, might change depending on company usage.
  instance_type     = "t3.micro"             # Small instance for testing, can be changed any time
  enable_monitoring = true

  target_group_arns = module.alb.target_group_arns

  # Instances are provided with the standard 8GB SSD, assumption here is that most of the
  # 'heavy work' is done by the RDS instance, i.e. the database itself.



  tags = [
    {
      key                 = "Environment"
      value               = var.environment
      propagate_at_launch = true
    }
  ]

}

# Provide scalable, shared network storage drives to the WordPress instances
module "efs" {
  source  = "cloudposse/efs/aws"
  version = "0.31.0"

  namespace              = "bmi"
  stage                  = var.environment
  name                   = "wp"
  region                 = var.region
  vpc_id                 = module.vpc.vpc_id
  subnets                = module.vpc.private_subnets
  dns_name               = "wp-efs"
  security_groups        = [aws_security_group.wp.id]
  security_group_enabled = false # Do not create a default group, we assign the WordPress SG to it anyway.
}

# DNS-compliant object storage that provides an 'origin' for which to cache static assets for the site.
module "s3" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "2.6.0"

  bucket = join("-", [var.environment, "bmi-global-static-assets"])
  acl = "public-read" # Fetches via Cloudfront require objects to be publicly readable 

  versioning = {
    enabled = true
  }

}

# Cloudfront content delivery network (CDN) which retrieves static assets from the S3 bucket and caches them
# at a convenient location, close to the user. This uses AWS' backbone network and edge locations.
module "cdn" {
  source  = "terraform-aws-modules/cloudfront/aws"
  version = "2.6.0"

  # Implement once trusted certificate is imported into AWS
  # aliases = [
  #   "cdn.bmiglobaled.com"
  # ]

  comment = "BMI Global CDN for caching static assets"

  origin = {
    s3 = {
      domain_name = module.s3.s3_bucket_bucket_regional_domain_name
      config = {
        http_port = 80
        https_port = 443
      }
    }
  }

  default_cache_behavior = {
    target_origin_id = "s3"
    viewer_protocol_policy = "allow-all"
    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]
    compress        = true
    query_string    = true
  }
}

# The internet facing "entry point" to the infrastructure, this should point to the wordpress instances
# that are configured in the private subnets - these are not reachable from the outside world and are
# only forwarded to by the load balancer on its listening ports.
module "alb" {
  source  = "terraform-aws-modules/alb/aws"
  version = "~> 6.0"

  create_lb = true
  name      = join("-", [var.environment, "alb"])

  load_balancer_type = "application"

  vpc_id          = module.vpc.vpc_id
  subnets         = module.vpc.private_subnets
  security_groups = [aws_security_group.alb.id]

  # Bucket must exist prior to ALB creation, due to a bug with the module
  # access_logs = {
  #   bucket = join("-", [var.environment, "bmi-global-alb-logs"])
  # }


  target_groups = [
    {
      name_prefix      = join("-", ["wp", var.environment])
      backend_protocol = "HTTP"
      backend_port     = 80
      target_type      = "instance"

      # Add relevant health check information for application later. This is hitting the simple server to ensure the instances are healthy for now.
      health_check = {
        enabled  = true
        path     = "/"
        port     = 8080
        protocol = "HTTP"
      }
    }
  ]

  # Listener rules for the LB,
  http_tcp_listeners = [
    {
      port        = 80
      protocol    = "HTTP"
      action_type = "forward"
    }
    # Swap out for HTTP --> HTTPS redirect once TLS is configured
    # {
    #   port = 80
    #   protocol = "HTTP"
    #   action_type = "redirect"
    #   redirect = {
    #     port = 443
    #     protocol = "HTTPS"
    #     status_code = "HTTP_301"
    #   }
    # }
  ]

  # Add TLS information later
  # https_listeners = [
  #   {
  #     port               = 443
  #     protocol           = "HTTPS"
  #     certificate_arn    = "arn:aws:iam::123456789012:server-certificate/test_cert-123456789012"
  #   }
  # ]



  tags = {
    Environment = var.environment
    Terraform   = true
  }
}

# Security group to attach onto the ALB
resource "aws_security_group" "alb" {
  name        = join("-", [var.environment, "alb-sg"])
  description = "Allow inbound traffic to ALB"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "HTTP from outside"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS from outside"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]

  }

  egress {
    description      = "Return traffic from valid requests"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Environment = var.environment
    Terraform   = true
  }
}

resource "aws_security_group" "db" {
  name        = join("-", [var.environment, "db-sg"])
  description = "Allow inbound traffic to originate from the private subnet"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Database port inbound from private subnets"
    from_port       = 3306
    to_port         = 3306 # MySQL port
    protocol        = "tcp"
    security_groups = [aws_security_group.wp.id]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Environment = var.environment
  }
}

# Security group definition for the WordPress instances
resource "aws_security_group" "wp" {
  name        = join("-", [var.environment, "wp-instance-sg"])
  description = "SG for the WordPress application instances in the private subnets"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description     = "Allow inbound traffic from the ALB"
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description     = "Allow inbound traffic from the ALB healthcheck"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    description = "Allow inbound HTTPS traffic"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [module.vpc.vpc_cidr_block] # Allow inbound traffic from our VPC, this is mainly used for SSM connections
  }

  ingress {
    description = "EFS mount target"
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # TODO: Change to user specified CIDR
  }

  # Ingress for HTTPS, although the assumption is that the ALB will terminate TLS for edge termination
  # this is left here in case we need it.
  # ingress {
  #   description      = "Allow inbound traffic from the ALB"
  #   from_port        = 443
  #   to_port          = 443
  #   protocol         = "tcp"
  #   security_groups = [aws_security_group.alb.id]
  #   }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Environment = var.environment
  }

}

resource "aws_iam_instance_profile" "wp_instance_profile" {
  name = join("-", [var.environment, "wp-instance-profile"])
  role = aws_iam_role.ssm.name
}

resource "aws_iam_role" "ssm" {
  name = join("-", [var.environment, "instance-ssm"])
  path = "/"

  managed_policy_arns = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"] # AWS managed policy for Systems Manager
  assume_role_policy  = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com"
            },
            "Effect": "Allow"
        }
    ]
}
EOF
}