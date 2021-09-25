variable "region" {
  description = "The region to place all of the resources into"
  default     = "eu-west-1"
  type        = string
}

variable "profile" {
  description = "The AWS account profile to use to deploy the resources"
  default     = "bmi-global"
  type        = string
}

variable "environment" {
  description = "The environment that is being deployed into"
  default     = "dev"
  type        = string
}

variable "network_name_prefix" {
  description = "The prefix to give the named network resources"
  default     = "dev"
  type        = string
}

variable "azs" {
  description = "Availability Zones (AZs) to use for the deployed network resources"
  type        = list(string)
  default     = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
}

variable "bastion_ssh_key_name" {
  description = "The SSH key pair name to use with the bastion host"
  type        = string
}

variable "redis_cluster_size" {
  description = "Number of nodes in the Redis cluster"
  default     = 1
  type        = number
}

variable "redis_instance_type" {
  description = "Type of instance for ElastiCache"
  default     = "cache.t2.micro"
  type        = string
}

variable "redis_engine_version" {
  description = "Version of Redis to run"
  default     = "4.0.10"
  type        = string
}

variable "redis_family" {
  description = "Redis family"
  default     = "redis4.0"
  type        = string

}

variable "redis_encryption_at_rest" {
  description = "Enable at rest encryption on Redis"
  default     = false
  type        = bool
}

variable "db_engine_version" {
  description = "Database engine version of MySQL to use"
  default     = "8.0.20"
  type        = string
}

# This is known as an option group in the web console
variable "db_major_engine_version" {
  description = "Major version of the engine to associate with"
  default     = "8.0"
  type        = string
}

variable "db_parameter_group" {
  description = "Parameter group to apply to the DB"
  default     = "mysql8.0"
  type        = string
}
variable "db_instance" {
  description = "AWS instance type for the MySQL database"
  default     = "db.t3.medium"
  type        = string
}

variable "db_storage" {
  description = "Amount of storage for the DB, in GB"
  default     = "20"
  type        = string
}

variable "db_name" {
  description = "Database name to create"
  default     = "wp"
  type        = string
}

variable "db_user" {
  description = "Database user for the master DB"
  default     = "bmi"
  type        = string
}

# This can show up in the state file, so ensure it is not checked into Git and only accessed by those who require it
variable "db_password" {
  description = "Database password for the master DB"
  sensitive   = true
  type        = string

  validation {
    # Password validation to ensure a strong password with at least:
    # 8 characters or more in length 
    # 2 uppercase letters
    # 3 lowercase letters
    # 1 special character
    # 2 digits
    # condition = can(regex("^(?=.*[A-Z].*[A-Z])(?=.*[!@#$&*])(?=.*[0-9].*[0-9])(?=.*[a-z].*[a-z].*[a-z]).{8,}$", var.db_password))

    # Use this if you wish to only implement a length condition or change the regex for your own needs
    condition = length(var.db_password) > 8

    error_message = "Database password must meet the criteria."
  }
}

variable "db_skip" {
  description = "Skip the creation of a snapshot of the database before it is deleted"
  default     = false
  type        = string
}

variable "db_apply_immediately" {
  description = "Skip the maintainence window and apply the changes immediately"
  default     = false
  type        = string
}

variable "db_port" {
  description = "Database port to accept connections"
  default     = "3306" # MySQL port
  type        = string
}

# Retrieve latest 20.04 Ubuntu AMI, used for testing an instance launch whilst awaiting BMI Global
# related configuration
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}
