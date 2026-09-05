variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "environment" {
  type = string
}

variable "documents_bucket" {
  type = string
}

variable "index_bucket" {
  type = string
}

variable "queue_name" {
  type = string
}

variable "embedding_model" {
  type    = string
  default = "text-embedding-3-small"
}

variable "batch_size" {
  type    = number
  default = 64
}

variable "aws_access_key_id" {
  type      = string
  sensitive = true
}

variable "aws_secret_access_key" {
  type      = string
  sensitive = true
}
