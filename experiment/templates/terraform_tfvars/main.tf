terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key_id
  secret_key = var.aws_secret_access_key
}

resource "aws_s3_bucket" "documents" {
  bucket = var.documents_bucket
}

resource "aws_s3_bucket" "index" {
  bucket = var.index_bucket
}

resource "aws_sqs_queue" "to_index" {
  name                       = var.queue_name
  visibility_timeout_seconds = 300
}

resource "aws_iam_role" "indexer" {
  name = "${var.environment}-embeddings-indexer"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
