import boto3
import csv
import string
import secrets
region = 'ca-central-1'
pool_client = boto3.client('cognito-idp', region_name=region)
def generate_random_password():
    # Define character sets
    lowercase_letters = string.ascii_lowercase
    uppercase_letters = string.ascii_uppercase
    digits = string.digits
    special_characters = string.punctuation

    # Ensure at least one character from each category
    password = (
        secrets.choice(lowercase_letters) +
        secrets.choice(uppercase_letters) +
        secrets.choice(digits) +
        secrets.choice(special_characters)
    )

    # Add remaining characters
    remaining_length = 12 - len(password)  # Adjust the length as needed
    all_characters = lowercase_letters + uppercase_letters + digits + special_characters
    password += ''.join(secrets.choice(all_characters) for _ in range(remaining_length))

    # Shuffle the characters to make the password more random
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)
    shuffled_password = ''.join(password_list)

    return shuffled_password
def create_user(client, target_pool_id, username, email, temp_password, custom_attributes):
    try:
        user_attributes = [
            {
                'Name': 'email',
                'Value': email
            },
            {
                'Name': 'custom:DNNUsername',
                'Value': custom_attributes.get('custom:DNNUsername', '')  # Custom DNNUsername attribute
            },
            {
                'Name': 'custom:IsSuperUser',
                'Value': custom_attributes.get('custom:IsSuperUser', '')  # Custom IsSuperUser attribute
            },
            {
                'Name': 'custom:LastName',
                'Value': custom_attributes.get('custom:LastName', '')  # Custom LastName attribute
            },
            {
                'Name': 'custom:FirstName',
                'Value': custom_attributes.get('custom:FirstName', '')  # Custom FirstName attribute
            },
            {
                'Name': 'custom:DisplayName',
                'Value': custom_attributes.get('custom:DisplayName', '')  # Custom DisplayName attribute
            }
        ]

        response = client.admin_create_user(
            UserPoolId=target_pool_id,
            Username=username,
            TemporaryPassword=temp_password,
            UserAttributes=user_attributes
        )

        print(f"User {username} created with temporary password and email {email}.")
        return response
    except Exception as e:
        print(f"Error creating user {username}: {e}")
        return None
def set_user_password(client, target_pool_id, username, password):
    try:
        client.admin_set_user_password(
            UserPoolId=target_pool_id,
            Username=username,
            Password=password,
            Permanent=True
        )
        print(f"Password for user {username} set and confirmed in pool.")
    except Exception as e:
        print(f"Error setting password for user {username}: {e}")
def mark_email_verified(client, target_pool_id, username):
    try:
        response = client.admin_update_user_attributes(
            UserPoolId=target_pool_id,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'email_verified',
                    'Value': 'true'
                }
            ]
        )
        print(f"Email verified for user {username}.")
        return response
    except Exception as e:
        print(f"Error updating email verification for user {username}: {e}")
def force_change_password(client, target_pool_id, username):
    try:
        response = client.admin_update_user_attributes(
            UserPoolId=target_pool_id,
            Username=username,
            UserAttributes=[
                {
                    'Name': 'user_status',
                    'Value': 'FORCE_CHANGE_PASSWORD'
                }
            ]
        )
        print(f"User status set to FORCE_CHANGE_PASSWORD for user {username}.")
        return response
    except Exception as e:
        print(f"Error updating user attributes for user {username}: {e}")
# Read your CSV file and loop through the usernames to create users and set temporary passwords
csv_file_path = r'C:\Users\ankur.dang\Desktop\testpy\template.csv'
with open(csv_file_path, 'r') as file:
    reader = csv.DictReader(file)
    for row in reader:
        username = row['cognito:username']
        email = row['email']  # Assuming 'email' is the header for email in your CSV
        temp_password = generate_random_password()  # Set your desired temporary password
        # Create user with temporary password and email
        custom_attributes = {
                                'custom:DNNUsername': row.get('custom:DNNUsername', ''),
                                'custom:IsSuperUser': row.get('custom:IsSuperUser', ''),
                                'custom:LastName': row.get('custom:LastName', ''),
                                'custom:FirstName': row.get('custom:FirstName', ''),
                                'custom:DisplayName': row.get('custom:DisplayName', '')
                            }

        create_user_response = create_user(pool_client, 'ca-central-1_sriCd1Oa4', username, email, temp_password, custom_attributes)
        mark_email_verified(pool_client, 'ca-central-1_sriCd1Oa4', username)