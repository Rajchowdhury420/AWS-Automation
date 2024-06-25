import boto3
import json
import csv
from rich.progress import Progress
from rich.table import Table
from rich import print

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    role_arn = f'arn:aws:iam::{account_id}:role/{role_name}'
    
    try:
        assumed_role_object = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AssumeRoleSession"
        )
        credentials = assumed_role_object['Credentials']
        return credentials
    except Exception as e:
        print(f"[bright_red]Error assuming role {role_name} in account {account_id}: {e}")
        return None

def add_trust_relationship(iam_client, role_name, trust_policy):
    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )
        return True
    except iam_client.exceptions.UnmodifiableEntityException:
        return False

def add_trust_relationship_to_roles_from_csv(trust_policy, input_csv):
    # Read roles and account IDs from the input CSV file
    roles = []
    with open(input_csv, mode='r', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            roles.append({'AccountID': row['AccountID'], 'RoleName': row['RoleName']})
    
    table = Table(title="Trust Policy Update Results")
    table.add_column("Account ID")
    table.add_column("Role Name")
    table.add_column("Trust Policy Updated", style="cyan")
    
    results = []
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=len(roles))
        
        # Add trust relationship to each role
        for role in roles:
            account_id = role['AccountID']
            role_name = role['RoleName']
            
            if role_name.startswith('AWSServiceRole'):
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'Skipped (Protected role)'}
                results.append(result)
                progress.update(task, advance=1)
                continue  # Skip modifying protected roles
            
            # Assume the role in the target account
            credentials = assume_role(account_id, role_name)
            if credentials:
                iam_client = boto3.client(
                    'iam',
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
                
                if add_trust_relationship(iam_client, role_name, trust_policy):
                    result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'True'}
                else:
                    result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'False'}
            else:
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'Assume Role Failed'}
            
            results.append(result)
            table.add_row(account_id, role_name, result['TrustPolicyUpdated'])
            progress.update(task, advance=1)
    
    print(table)
    
    with open('trust_policy_update_results.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['AccountID', 'RoleName', 'TrustPolicyUpdated'])
        writer.writeheader()
        writer.writerows(results)
    
    print("[bright_red]Output saved as trust_policy_update_results.csv")

trust_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "ds.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}

input_csv = 'roles_input.csv'

add_trust_relationship_to_roles_from_csv(trust_policy, input_csv)
