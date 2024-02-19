import boto3
import pandas as pd

region = 'us-east-1'
user_pool_id = 'us-east-1_iyPa9CTy7'
pool_client = boto3.client('cognito-idp', region_name=region)

def export_all_users_to_excel(user_pool_id, pool_client, file_path):
    try:
        users_data = []

        # Initial request to list users
        response = pool_client.list_users(UserPoolId=user_pool_id)

        # Extract user attributes from the initial response
        users_data += [{attr['Name']: attr['Value'] for attr in user['Attributes']} for user in response['Users']]

        # Continue making requests with PaginationToken until all users are retrieved
        while 'PaginationToken' in response:
            pagination_token = response['PaginationToken']
            response = pool_client.list_users(UserPoolId=user_pool_id, PaginationToken=pagination_token)
            users_data += [{attr['Name']: attr['Value'] for attr in user['Attributes']} for user in response['Users']]

        # Convert data to a Pandas DataFrame
        df = pd.DataFrame(users_data)

        # Save DataFrame to an Excel file
        excel_file_path = f'{file_path}\\cognito_users_final.xlsx'
        df.to_excel(excel_file_path, index=False)

        print(f"All user data exported to {excel_file_path}")
    except Exception as e:
        print(f"Error exporting users: {e}")

# Specify the file path
file_path = r'C:\Users\ankur.dang\Desktop\testpy'

# Call the function to export all users to Excel
export_all_users_to_excel(user_pool_id, pool_client, file_path)
