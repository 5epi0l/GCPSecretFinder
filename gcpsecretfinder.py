#!/usr/bin/env python3


import argparse
import requests
from google.oauth2 import service_account
from typing import List, Optional, Tuple
import json
from google.auth.transport.requests import Request
import sys

REGIONS = [
        "us-west1","us-west2", "us-west3", "us-west4", "us-central1", "us-east1", "us-east4", "us-east5", "us-south1", "northamerica-northeast1", "northamerica-northeast2", "southamerica-west1", "southamerica-east1", "northamerica-south1", "europe-west2", "europe-west1", "europe-west4", "europe-west6", "europe-west3", "europe-central2", "europe-west8", "europe-southwest1", "europe-west9", "europe-west12", "europe-west10", "europe-north2", "asia-south1", "asia-south2", "asia-southeast1", "asia-southeast2", "asia-east2", "asia-east1", "asia-northeast1", "asia-northeast2", "australia-southeast1", "australia-southeast2", "asia-northeast3", "asia-southeast3", "me-west1", "me-central1", "me-central2", "africa-south1"
        ]


def getAccessTokenForServiceAccount(key_file: str) -> str:
    credentials = service_account.Credentials.from_service_account_file(
            key_file,
            scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
    credentials.refresh(Request())
    return credentials.token()


def scanRegionsForSecrets(project: str, region: str, access_token: str) -> Optional[List[str]]:

    url = f"https://secretmanager.{region}.rep.googleapis.com/v1/projects/{project}/locations/{region}/secrets"
    headers = {
            "Authorization": f"Bearer {access_token}"
            }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()
        secrets = data.get('secrets', [])

        if secrets:
            return [secret.get('name') for secret in secrets if secret.get('name')]
        return []

    
    except requests.exceptions.RequestException as e:
        print(f"[!] An error has occured: {e}", file=sys.stderr)

def retrieveFoundSecrets(secret_name: str, access_token: str, version: str = "latest") -> Optional[Tuple[str, bool]]:
    region = secret_name.split('/')[3]
    project_num = secret_name.split('/')[1]
    secret = secret_name.split('/')[5]
    url = f"https://secretmanager.{region}.rep.googleapis.com/v1/projects/{project_num}/locations/{region}/secrets/{secret}/versions/latest:access"
    headers = {
            "Authorization": f"Bearer {access_token}"
            }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        data = response.json()
        payload = data.get('payload', {})


        if 'data' in payload:
            import base64
            decoded = base64.b64decode(payload['data']).decode('utf-8')
            return decoded, False

        return None, False


    except requests.exceptions.RequestException as e:
        print(f"[!] Error retrieving secret: {secret_name}: {e}", file=sys.stderr)
        return None, False

def main():

    parser = argparse.ArgumentParser(
        description='Enumerating GCP Secrets Across All Locations',
        formatter_class = argparse.RawDescriptionHelpFormatter
        )
    parser.add_argument(
            '-p','--project', required=True, help='GCP Project ID'
            )
    parser.add_argument(
            '-t','--token', help='Access Token (String)'
            )
    parser.add_argument(
            '-f','--token-file', help='Access Token File'
            )
    parser.add_argument(
            '-s', '--service-account-key',help='Service Account Key JSON File'
            )

    parser.add_argument(
            '-r', '--retrieve', action='store_true', help='Retrieve Secret Values'
            )
    
    parser.add_argument(
            '-v', '--version', default='latest', help='Secret Version to retrieve. (default: Latest)'
            )

    args = parser.parse_args()

    if args.token:
        access_token = args.token
    elif args.token_file:
        try:
            with open(args.token_file, 'r') as f:
                access_token = f.read().strip()
        except IOError as e:
            print(f"[!] Error occured while reading token from file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        try:
            access_token = get_access_token_from_service_account(args.service_account_key)
        except Exception as e:
            print(f"[!] Error occured while getting token from service Account: {e}", file=sys.stderr)
            sys.exit(1)


    regions_to_scan = REGIONS


    all_secrets = []
    total_secrets = 0
    secretName = None
    
    print("[*] Hunting Secrets...")

    for region in regions_to_scan:
        secrets = scanRegionsForSecrets(args.project, region, access_token)

        if secrets:
            for secret in secrets:
                if args.retrieve:
                    value, is_binary = retrieveFoundSecrets(secret, access_token, args.version)
                    if value is not None:
                        secretName = value
                        

                all_secrets.append(secretName)

                print(f"[*] secret found: {secret}")
            total_secrets += len(secrets)

    if args.retrieve:
        if all_secrets:
            print("[*] Retrieving Value")
            for s in all_secrets:
                print(f"\n{s}")
    
    if total_secrets == 0:
        print("[!] No Secrets Found")
    else:
        print("[*] Total Secrets Retrieved: ", total_secrets)
if __name__ == "__main__":
    main()
