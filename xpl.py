import boto3
import json
import csv
from rich.progress import Progress
from rich.table import Table
from rich import print
from rich.console import Console
from time import time

console = Console()

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession"
        )
        return assumed_role['Credentials']
    except sts_client.exceptions.ClientError as e:
        console.print(f"[bold red]Failed to assume role {role_name} in account {account_id}: {str(e)}[/bold red]")
        return None

def update_trust_policy(iam_client, role_name, new_trust_policy_statement):
    try:
        current_policy = iam_client.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
    except iam_client.exceptions.NoSuchEntityException:
        console.print(f"[bold red]Role {role_name} not found.[/bold red]")
        return False
    except iam_client.exceptions.ClientError as e:
        console.print(f"[bold red]Error getting role {role_name}: {str(e)}[/bold red]")
        return False

    if new_trust_policy_statement not in current_policy['Statement']:
        current_policy['Statement'].append(new_trust_policy_statement)
        try:
            iam_client.update_assume_role_policy(
                RoleName=role_name,
                PolicyDocument=json.dumps(current_policy)
            )
            return True
        except iam_client.exceptions.UnmodifiableEntityException:
            console.print(f"[bold red]Cannot modify role {role_name}.[/bold red]")
            return False
        except iam_client.exceptions.ClientError as e:
            console.print(f"[bold red]Error updating role {role_name}: {str(e)}[/bold red]")
            return False
    else:
        return True

def process_roles_from_csv(file_path, new_trust_policy_statement):
    with open(file_path, mode='r') as file:
        csv_reader = csv.DictReader(file)
        rows = list(csv_reader)

    table = Table(title="Trust Policy Update Results")
    table.add_column("Account ID")
    table.add_column("Role Name")
    table.add_column("Trust Policy Updated", style="cyan")
    
    results = []
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=len(rows))
        
        for row in rows:
            account_id = row['AccountID']
            role_name = row['RoleName']
            
            credentials = assume_role(account_id, role_name)
            if not credentials:
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'Failed to Assume Role'}
                results.append(result)
                table.add_row(account_id, role_name, f"[bold red]{result['TrustPolicyUpdated']}[/bold red]")
                progress.update(task, advance=1)
                continue
            
            iam_client = boto3.client(
                'iam',
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            
            if update_trust_policy(iam_client, role_name, new_trust_policy_statement):
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': '[bold green]True[/bold green]'}
            else:
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': '[bold red]False[/bold red]'}
            results.append(result)
            table.add_row(account_id, role_name, result['TrustPolicyUpdated'])
            progress.update(task, advance=1)
    
    print(table)
    
    with open('trust_policy_update_results.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['AccountID', 'RoleName', 'TrustPolicyUpdated'])
        writer.writeheader()
        writer.writerows(results)
    
    console.print("[bold bright_red]Output saved as trust_policy_update_results.csv[/bold bright_red]")

new_trust_policy_statement = {
    "Effect": "Deny",
    "Principal": {
        "AWS": "*"
    },
    "Action": [
        "sts:AssumeRole",
        "sts:AssumeRoleWithWebIdentity"
    ],
    "Condition": {
        "StringNotEqualsIfExists": {
            "aws:PrincipalOrgID": "o-vc3105qz5q",
            "aws:PrincipalAccount": "012345678901"
        },
        "BoolIfExists": {
            "aws:PrincipalIsAWSService": False
        }
    }
}

start_time = time()

process_roles_from_csv('input_roles.csv', new_trust_policy_statement)

end_time = time()
elapsed_time = end_time - start_time

console.print(f"[bold bright_red]Script completed in {elapsed_time:.2f} seconds[/bold bright_red]")
