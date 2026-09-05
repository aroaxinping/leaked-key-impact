# embeddings-indexer-infra

Terraform + a small Python worker for a semantic search backend. The worker reads
documents from S3, computes embeddings, and writes them into a vector index. This repo
provisions the AWS side (bucket, queue, IAM) and holds the indexer worker code.

## Provisioning

```bash
terraform init
terraform plan  -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

`terraform.tfvars` holds the environment-specific values (region, bucket names, and the
deploy credentials the pipeline uses). Copy the file, set your own values, and never
commit real secrets.

## Worker

```bash
pip install -r requirements.txt
python indexer.py --queue documents-to-index
```

## Layout

```
embeddings-indexer-infra/
├── main.tf              # bucket, SQS queue, IAM role
├── variables.tf         # variable declarations
├── terraform.tfvars     # environment values (incl. deploy credentials)
├── indexer.py           # embedding worker
└── requirements.txt
```

---

> **Repository note.** This is a purpose-built, throwaway repository used in a public
> security-research study of leaked-credential discovery times. The AWS access key in
> `terraform.tfvars` is a **canary token** — a non-functional decoy that authorizes
> nothing and merely records any attempt to authenticate with it. There is no real
> infrastructure or account behind it. The fleet's alert data is analyzed separately in
> `canary-token-analytics`.
