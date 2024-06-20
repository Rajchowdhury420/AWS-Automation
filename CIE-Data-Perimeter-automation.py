import boto3
import json
import csv
from rich.progress import Progress
from tqdm import tqdm
from rich import print

def add_trust_relationship(role_name, trust_policy):
    iam_client = boto3.client('iam')
    
    # Update the role's trust relationship policy
    try:
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(trust_policy)
        )
        return True
    except iam_client.exceptions.UnmodifiableEntityException:
        return False

def add_trust_relationship_to_all_roles(trust_policy):
    iam_client = boto3.client('iam')
    
    # Get a list of all IAM roles
    roles = iam_client.list_roles()['Roles']
    
    # Create a list to store results
    results = []
    
    # Create a progress bar
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=len(roles))
        
        # Add trust relationship to each role
        for role in roles:
            role_name = role['RoleName']
            account_id = role['Arn'].split(':')[4]
            
            if role_name.startswith('AWSServiceRole'):
                print(f"Skipping protected role: {role_name}")
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'Skipped (Protected role)'}
                results.append(result)
                progress.update(task, advance=1)
                continue  # Skip modifying protected roles
            
            if add_trust_relationship(role_name, trust_policy):
                print(f"Added trust relationship to role: {role_name}")
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'True'}
                results.append(result)
            else:
                print(f"Failed to add trust relationship to role: {role_name}")
                result = {'AccountID': account_id, 'RoleName': role_name, 'TrustPolicyUpdated': 'False'}
                results.append(result)
            
            # Update progress
            progress.update(task, advance=1)
    
    # Write results to a CSV file
    with open('trust_policy_update_results.csv', mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=['AccountID', 'RoleName', 'TrustPolicyUpdated'])
        writer.writeheader()
        writer.writerows(results)
    
    # Print final message
    print("[bright_red]Output saved as trust_policy_update_results.csv")

# Trust relationship policy to be added to every role
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

# Add trust relationship to all roles
add_trust_relationship_to_all_roles(trust_policy)

