# AWS Cognito Identity Situational Awareness

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/M4M03Q2JN)

This Python script interacts with AWS Cognito Identity Pools and Security Token Service (STS) to provide situational awareness regarding identity credentials.

## Features

- **Analyze Cognito Identity Pools:** List and check Cognito Identity Pools within your AWS account/region.
- **Check Identity Credentials:**
  - Attempt to obtain identity credentials without authentication.
  - Attempt to obtain identity credentials with authentication if unauthenticated access fails.
- **Display STS Information:** Fetch and display current STS information including User ID, Account ID, and ARN.

## Prerequisites

- Python 3.x
- AWS SDK for Python (Boto3)
- AWS credentials configured locally or via AWS IAM roles

## Setup

1. Install dependencies:
   ```
   pip install boto3
