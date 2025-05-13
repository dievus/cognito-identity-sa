import boto3
from botocore.exceptions import ClientError
import argparse
from typing import Optional, Dict, Any

def banner() -> None:
    banner_art = r"""
╔═╗┌─┐┌─┐┌┐┌┬┌┬┐┌─┐  ╦┌┬┐┌─┐┌┐┌┌┬┐┬┌┬┐┬ ┬
║  │ ││ ┬││││ │ │ │  ║ ││├┤ │││ │ │ │ └┬┘
╚═╝└─┘└─┘┘└┘┴ ┴ └─┘  ╩─┴┘└─┘┘└┘ ┴ ┴ ┴  ┴ 
╔═╗╦╔╦╗╦ ╦╔═╗╔╦╗╦╔═╗╔╗╔╔═╗╦              
╚═╗║ ║ ║ ║╠═╣ ║ ║║ ║║║║╠═╣║              
╚═╝╩ ╩ ╚═╝╩ ╩ ╩ ╩╚═╝╝╚╝╩ ╩╩═╝            
╔═╗╦ ╦╔═╗╦═╗╔═╗╔╗╔╔═╗╔═╗╔═╗              
╠═╣║║║╠═╣╠╦╝║╣ ║║║║╣ ╚═╗╚═╗              
╩ ╩╚╩╝╩ ╩╩╚═╚═╝╝╚╝╚═╝╚═╝╚═╝              
"""
    print(banner_art)

def extract_credentials(credentials: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Extract AWS credentials from a credentials dictionary."""
    return {
        'AccessKeyId': credentials.get('AccessKeyId'),
        'SecretKey': credentials.get('SecretKey'),
        'SessionToken': credentials.get('SessionToken')
    }

def print_credentials(identity: Dict[str, Any], creds: Dict[str, Optional[str]], route: str) -> None:
    print(f"Credentials found for {identity.get('UserId')} via {route} route")
    print("-" * 80)
    print(f"Account:       {identity.get('Account')}")
    print(f"Arn:           {identity.get('Arn')}")
    print(f"Access Key:    {creds['AccessKeyId']}")
    print(f"Secret Key:    {creds['SecretKey']}")
    print(f"Session Token: {creds['SessionToken']}")
    if route == 'unauthenticated':
        print("[!!!] Note that this is likely a critical finding.")
    else:
        print("[!] Note that this is likely a high to critical severity finding.")

def get_identity_and_credentials(client, identity_id: str) -> Optional[Dict[str, Any]]:
    try:
        response = client.get_credentials_for_identity(IdentityId=identity_id)
        return response.get("Credentials", {})
    except ClientError as e:
        handle_client_error(e)
        return None

def get_identity_id(client, pool_id: str) -> Optional[str]:
    try:
        response = client.get_id(IdentityPoolId=pool_id)
        return response.get("IdentityId")
    except ClientError as e:
        handle_client_error(e)
        return None

def assume_and_print(creds: Dict[str, Optional[str]], route: str) -> None:
    if not creds or not creds.get('AccessKeyId'):
        print("[!] No credentials obtained.")
        return
    new_session = boto3.Session(
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretKey'],
        aws_session_token=creds['SessionToken']
    )
    new_sts_client = new_session.client('sts')
    new_identity = new_sts_client.get_caller_identity()
    print_credentials(new_identity, creds, route)

def anon_check(args, unauth_cognito_client) -> None:
    """Attempt to obtain identity credentials without authentication."""
    print('\nAttempting to obtain identity credentials without authentication...\n')
    creds = get_identity_and_credentials(unauth_cognito_client, args.ident_id)
    assume_and_print(extract_credentials(creds), 'unauthenticated')

def handle_client_error(e: ClientError) -> None:
    error_code = e.response['Error']['Code']
    if error_code == "AccessDeniedException":
        print("[!] Access denied.")
        print(f"    Reason: {e.response['Error']['Message']}")
    else:
        print(f"[!] Unexpected error: {e}")

def list_identity_pools_and_check(
    cognito_client, unauth_cognito_client
) -> None:
    try:
        cog_list_idents = cognito_client.list_identity_pools(MaxResults=60)
        print("\nCognito Identity Pool Information")
        print("-" * 80)
        identity_pools = cog_list_idents.get("IdentityPools", [])
        if not identity_pools:
            print("[!] No Cognito Identity Pools found in this account/region.")
            return
        for pool in identity_pools:
            pool_id = pool.get("IdentityPoolId")
            pool_name = pool.get("IdentityPoolName")
            print(f"Identity Pool Name : {pool_name}")
            print(f"Identity Pool ID   : {pool_id}")
            # Try unauthenticated first
            identity_id = get_identity_id(unauth_cognito_client, pool_id)
            if identity_id:
                print(f"Identity ID        : {identity_id}")
                print('\nAttempting to obtain identity credentials without authentication...\n')
                creds = get_identity_and_credentials(unauth_cognito_client, identity_id)
                assume_and_print(extract_credentials(creds), 'unauthenticated')
            else:
                print(f"[!] Could not obtain unauthenticated identity for pool {pool_id}.")
                identity_id = get_identity_id(cognito_client, pool_id)
                if identity_id:
                    print(f"Identity ID        : {identity_id}")
                    print('\nAttempting to obtain identity credentials with authentication...')
                    creds = get_identity_and_credentials(cognito_client, identity_id)
                    assume_and_print(extract_credentials(creds), 'authenticated')
                else:
                    print(f"[!] Could not obtain authenticated identity for pool {pool_id} either.")
            print("-" * 80)
    except ClientError as e:
        handle_client_error(e)
    except Exception as e:
        print(f"[!] Unexpected error while listing identity pools: {e}")

def main() -> None:
    parser = argparse.ArgumentParser(
        description='Cognito Identity Situational Awareness')
    parser.add_argument('--aws-access-key-id', required=False,
                        help='AWS Access Key ID')
    parser.add_argument('--aws-secret-access-key',
                        required=False, help='AWS Secret Access Key')
    parser.add_argument('--aws-session-token', required=False,
                        default='', help='AWS Session Token (optional)')
    parser.add_argument('--aws-region', required=True, help='AWS Region')
    parser.add_argument('--ident-id', required=False, help='Identity ID for unauthentcated checks')
    parser.add_argument('--profile', required=False, help='AWS profile name from credentials file')
    args = parser.parse_args()
    banner()
    if args.profile:
        unauth_session = boto3.Session(profile_name=args.profile, region_name=args.aws_region)
        session = boto3.Session(profile_name=args.profile, region_name=args.aws_region)
    else:
        unauth_session = boto3.Session(
            region_name=args.aws_region
        )
        session = boto3.Session(
            aws_access_key_id=args.aws_access_key_id,
            aws_secret_access_key=args.aws_secret_access_key,
            aws_session_token=args.aws_session_token,
            region_name=args.aws_region
        )
    sts_client = session.client('sts')
    unauth_cognito_client = unauth_session.client('cognito-identity')
    cognito_client = session.client('cognito-identity')
    try:
        if args.ident_id:
            anon_check(args, unauth_cognito_client)
        else:
            identity = sts_client.get_caller_identity()
            print("\nSecurity Token Service (STS) information")
            print("-" * 80)
            print(f"UserId: {identity.get('UserId')}")
            print(f"Account: {identity.get('Account')}")
            print(f"Arn: {identity.get('Arn')}")
            list_identity_pools_and_check(cognito_client, unauth_cognito_client)
    except ClientError as e:
        handle_client_error(e)
    except Exception as e:
        print(f"[!] Unexpected error in main: {e}")

if __name__ == "__main__":
    main()
