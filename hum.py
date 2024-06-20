import boto3
import csv
import logging  # Make sure to import the logging module
from rich.progress import Progress, BarColumn, TextColumn, TimeRemainingColumn
from rich.console import Console
from rich.logging import RichHandler

# Initialize clients for IAM and CloudFormation
iam_client = boto3.client('iam')
cf_client = boto3.client('cloudformation')

# Setup console and logging
console = Console()
logging.basicConfig(
    level="INFO", 
    format="%(message)s", 
    datefmt="[%X]", 
    handlers=[RichHandler(console=console, rich_tracebacks=True)]
)

def get_cloudformation_roles():
    """Retrieve roles created via CloudFormation along with their stack details"""
    cf_roles = {}
    # Paginate through all CloudFormation stacks
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Retrieving CloudFormation stacks...", total=None)
        for page in cf_client.get_paginator('describe_stacks').paginate():
            for stack in page['Stacks']:
                stack_name = stack['StackName']
                stack_arn = stack['StackId']
                # List resources for each stack
                resources = cf_client.list_stack_resources(StackName=stack_name)['StackResourceSummaries']
                for resource in resources:
                    if resource['ResourceType'] == 'AWS::IAM::Role':
                        role_name = resource['PhysicalResourceId']
                        cf_roles[role_name] = (stack_name, stack_arn)
                        console.log(f"[cyan]Processing role from CloudFormation stack: {role_name}")
            progress.update(task, advance=1)

    # Handle StackSets
    stacksets = cf_client.list_stack_sets()['Summaries']
    for stackset in stacksets:
        stackset_name = stackset['StackSetName']
        instances_paginator = cf_client.get_paginator('list_stack_instances')
        for page in instances_paginator.paginate(StackSetName=stackset_name):
            for instance in page['Summaries']:
                if 'StackId' in instance:
                    stack_id = instance['StackId']
                    stack_instance_resources = cf_client.list_stack_resources(StackName=stack_id)['StackResourceSummaries']
                    for resource in stack_instance_resources:
                        if resource['ResourceType'] == 'AWS::IAM::Role':
                            role_name = resource['PhysicalResourceId']
                            cf_roles[role_name] = (stackset_name, stack_id)
                            console.log(f"[magenta]Processing role from CloudFormation StackSet: {role_name}")
                else:
                    console.log(f"[red]No StackId found for instance in StackSet: {stackset_name}")
    return cf_roles

def get_all_roles():
    """Retrieve all IAM roles"""
    all_roles = set()
    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn(),
        console=console
    ) as progress:
        task = progress.add_task("[green]Retrieving IAM roles...", total=None)
        for page in iam_client.get_paginator('list_roles').paginate():
            for role in page['Roles']:
                all_roles.add(role['RoleName'])
                console.log(f"[green]Processing IAM role: {role['RoleName']}")
            progress.update(task, advance=1)
    return all_roles

def write_to_csv(cloudformation_roles, manual_roles, cf_role_details):
    """Write roles to a CSV file with CloudFormation stack details"""
    with open('roles_audit.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Role Name', 'Creation Method', 'Stack Name or Set ID', 'Stack ARN'])
        for role in cloudformation_roles:
            stack_name, stack_arn = cf_role_details.get(role, ('N/A', 'N/A'))
            writer.writerow([role, 'CloudFormation', stack_name, stack_arn])
        for role in manual_roles:
            writer.writerow([role, 'Manual', 'N/A', 'N/A'])

def main():
    console.log("[bold blue]Starting to gather roles data...")
    cf_role_details = get_cloudformation_roles()
    all_roles = get_all_roles()
    
    cf_roles = set(cf_role_details.keys())
    manually_created_roles = all_roles - cf_roles
    cloudformation_created_roles = all_roles & cf_roles
    
    console.log("Writing results to CSV...")
    write_to_csv(cloudformation_created_roles, manually_created_roles, cf_role_details)
    
    console.log("[bold green]Process completed successfully!")

if __name__ == "__main__":
    main()

