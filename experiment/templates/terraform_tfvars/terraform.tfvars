aws_region = "us-east-1"
environment = "prod"

# Source documents and vector artifacts
documents_bucket = "semantic-search-documents-prod"
index_bucket     = "semantic-search-index-prod"
queue_name       = "documents-to-index"

# Embedding worker settings
embedding_model = "text-embedding-3-small"
batch_size      = 64

# Deploy credentials used by the CI pipeline to apply this stack
aws_access_key_id     = "__CANARY_ACCESS_KEY_ID__"
aws_secret_access_key = "__CANARY_SECRET_ACCESS_KEY__"
