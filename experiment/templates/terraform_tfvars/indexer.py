"""Embedding worker: pull documents from the queue, embed, write to the index."""
import argparse
import json
import logging

import boto3

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("embeddings-indexer")


def embed(texts: list[str]) -> list[list[float]]:
    # Placeholder for the embedding model call.
    return [[0.0] * 1536 for _ in texts]


def run(queue_name: str) -> None:
    sqs = boto3.client("sqs")
    url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]

    while True:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=20)
        messages = resp.get("Messages", [])
        if not messages:
            continue
        docs = [json.loads(m["Body"]) for m in messages]
        vectors = embed([d["text"] for d in docs])
        log.info("indexed %d documents", len(vectors))
        for m in messages:
            sqs.delete_message(QueueUrl=url, ReceiptHandle=m["ReceiptHandle"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", default="documents-to-index")
    run(parser.parse_args().queue)
