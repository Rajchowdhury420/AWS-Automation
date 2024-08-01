import boto3
from botocore.exceptions import ClientError
from rich.console import Console
from rich.progress import track
from rich.table import Table

client = boto3.client('organizations')

def get_all_ous():
    ous = []
    root_id = client.list_roots()['Roots'][0]['Id']
    paginator = client.get_paginator('list_organizational_units_for_parent')
    for page in paginator.paginate(ParentId=root_id):
        ous.extend(page['OrganizationalUnits'])
    return ous

def get_account_ids_in_ou(ou_id):
    account_ids = []
    paginator = client.get_paginator('list_accounts_for_parent')
    for page in paginator.paginate(ParentId=ou_id):
        for account in page['Accounts']:
            account_ids.append(account['Id'])
    return account_ids

def is_account_suspended(account_id):
    try:
        response = client.describe_account(AccountId=account_id)
        account_status = response['Account']['Status']
        return account_status == 'SUSPENDED'
    except ClientError as e:
        return f"Error: {e.response['Error']['Message']}"

console = Console()

table = Table(title="AWS Account Status Check")

table.add_column("OU ID", justify="right", style="cyan", no_wrap=True)
table.add_column("Account ID", justify="right", style="green", no_wrap=True)
table.add_column("Status", justify="right", style="magenta")

ous = get_all_ous()

for ou in track(ous, description="Processing OUs..."):
    ou_id = ou['Id']
    account_ids = get_account_ids_in_ou(ou_id)
    for account_id in account_ids:
        status = is_account_suspended(account_id)
        status_text = "Suspended" if status is True else "Active" if status is False else status
        table.add_row(ou_id, account_id, status_text)

console.print(table)
