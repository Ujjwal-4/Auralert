#!/usr/bin/env python3
"""Prove that Amazon Bedrock works from this machine before you claim it in the submission.

Usage:  python scripts/check_bedrock.py
Needs AWS credentials (env vars or profile), AWS_REGION and BEDROCK_MODEL_ID in .env.
Exit code 0 = Bedrock Converse call succeeded; non-zero = it did not.
"""

import os
import sys

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv is optional here
    pass

import boto3
from botocore.exceptions import BotoCoreError, ClientError

MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
REGION = os.getenv("AWS_REGION", "us-east-1")


def main() -> int:
    print(f"Region: {REGION}\nModel:  {MODEL_ID}")
    try:
        client = boto3.client("bedrock-runtime", region_name=REGION)
        resp = client.converse(
            modelId=MODEL_ID,
            messages=[{"role": "user", "content": [{"text": "Reply with the single word: OK"}]}],
            inferenceConfig={"maxTokens": 20},
        )
        text = resp["output"]["message"]["content"][0]["text"]
        print(f"SUCCESS - Bedrock replied: {text!r}")
        return 0
    except (ClientError, BotoCoreError) as err:
        print(f"FAILED - {err}")
        print(
            "Fix: enable model access in the Bedrock console for this region, set a valid "
            "BEDROCK_MODEL_ID (or inference profile ID), and check your AWS credentials."
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
