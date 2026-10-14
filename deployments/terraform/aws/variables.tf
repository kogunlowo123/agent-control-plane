variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "agent-control-plane"
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_id" {
  description = "VPC hosting the EKS cluster"
  type        = string
}

variable "private_subnet_ids" {
  description = "Private subnets for the database (at least two AZs)"
  type        = list(string)
  validation {
    condition     = length(var.private_subnet_ids) >= 2
    error_message = "Provide subnets in at least two availability zones."
  }
}

variable "cluster_security_group_id" {
  description = "Security group of the EKS nodes allowed to reach PostgreSQL"
  type        = string
}

variable "db_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.r6g.large"
}

variable "db_allocated_storage_gb" {
  description = "Initial database storage"
  type        = number
  default     = 50
}

variable "tags" {
  description = "Tags applied to every resource"
  type        = map(string)
  default     = { "app.kubernetes.io/part-of" = "agent-control-plane" }
}
