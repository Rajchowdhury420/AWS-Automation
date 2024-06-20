import boto3
import json
from rich.progress import Progress
from tqdm import tqdm

def add_trust_relationship(role_name, trust_policy):
    iam_client = boto3.client('iam')
    
    # Update the role's trust relationship policy
    iam_client.update_assume_role_policy(
        RoleName=role_name,
        PolicyDocument=json.dumps(trust_policy)
    )

def add_trust_relationship_to_all_roles(trust_policy):
    iam_client = boto3.client('iam')
    
    # Get a list of all IAM roles
    roles = iam_client.list_roles()['Roles']
    
    # Create a progress bar
    with Progress() as progress:
        task = progress.add_task("[cyan]Processing...", total=len(roles))
        
        # Add trust relationship to each role
        for role in roles:
            role_name = role['RoleName']
            add_trust_relationship(role_name, trust_policy)
            
            # Update progress
            progress.update(task, advance=1)
            print(f"Added trust relationship to role: {role_name}")

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

