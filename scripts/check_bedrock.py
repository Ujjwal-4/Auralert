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
        err_str = str(err)
        if "AccessDenied" in err_str:
            print(
                "\nNote on Model Access: Foundation models like Claude Haiku are paid and require manual access approval\n"
                "in the AWS Bedrock Console. Don't worry if you don't have access—AURALERT automatically runs using its\n"
                "built-in deterministic fallback engine without needing AWS credentials or paid model approvals!\n"
                "See docs/FRICTION-LOG.md for full details."
            )
        elif "NoCredentials" in err_str:
            print(
                "\nNote on AWS Credentials: Configure AWS credentials via 'aws configure' with a scoped IAM developer user.\n"
                "SECURITY WARNING: Never use AWS root account credentials for CLI development.\n"
                "See docs/FRICTION-LOG.md for the recommended least-privilege Bedrock IAM policy."
            )
        else:
            print(
                "\nFix: enable model access in the Bedrock console for this region, set a valid "
                "BEDROCK_MODEL_ID (or inference profile ID), and check your AWS credentials."
            )
        return 1


if __name__ == "__main__":
    sys.exit(main())
