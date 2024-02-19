using DNN.OpenId.Cognito;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DotNetNuke.Entities.Users;
using DotNetNuke.Entities.Portals;
using Amazon.Runtime;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;

namespace NG.Cognito.AWS
{
    public class AWSUserController
    {
        private readonly DNNOpenIDCognitoConfig _config;

        public AWSUserController(DNNOpenIDCognitoConfig config) 
        { 
            _config = config;
        }

        public bool CreateCognitoUser(string email, string DNNUsername, string password, PortalSettings settings)
        {
            try
            {
                string cognitoIAMUserAccessKey = _config.IAMUserAccessKey;
                string cognitoIAMUserSecretKey = _config.IAMUserSecretKey;
                string cognitoAPPUsername = _config.AppUsername;
                string cognitoAPPClientID = _config.ApiKey;
                string cognitoAPPSecretKey = _config.ApiSecret;
                string cognitoUserPoolID = _config.CognitoPoolID;

                UserInfo objUserInfo = UserController.GetUserByName(settings.PortalId, DNNUsername);

                BasicAWSCredentials credentials = new Amazon.Runtime.BasicAWSCredentials(cognitoIAMUserAccessKey, cognitoIAMUserSecretKey);

                //Need to Put a condition here : Select that region which has the cognito user pool
                //Put an if condition based on a variable which will choose the region like canada central or virginia
                AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(credentials, Amazon.RegionEndpoint.CACentral1);

                //Generate SECRET_HASH
                byte[] message = Encoding.UTF8.GetBytes(cognitoAPPUsername + cognitoAPPClientID);
                byte[] key = Encoding.UTF8.GetBytes(cognitoAPPSecretKey);
                System.Security.Cryptography.HMACSHA256 hmac = new System.Security.Cryptography.HMACSHA256(key);
                byte[] hash = hmac.ComputeHash(message);
                string hashStr = Convert.ToBase64String(hash);

                var request = new AdminCreateUserRequest
                {
                    UserPoolId = cognitoUserPoolID,
                    Username = email,
                    TemporaryPassword = null,
                    MessageAction = "SUPPRESS", // Optional: This prevents sending a welcome email to the user
                    UserAttributes = new List<AttributeType>
                {
                    new AttributeType { Name = "email", Value = email },
                    new AttributeType { Name = "email_verified", Value = "true" },
                    new AttributeType { Name = "custom:FirstName", Value = objUserInfo.FirstName },
                    new AttributeType { Name = "custom:LastName", Value = objUserInfo.LastName },
                    new AttributeType { Name = "custom:IsSuperUser", Value = objUserInfo.IsSuperUser ? "1" : "0" },
                    new AttributeType { Name = "custom:DisplayName", Value = objUserInfo.DisplayName },
                    new AttributeType { Name = "custom:DNNUsername", Value = objUserInfo.Username },
                },
                    ClientMetadata = new Dictionary<string, string>
                {
                    { "SECRET_HASH", hashStr }
                }
                };

                provider.AdminCreateUser(request);

                //after user created, set the password
                var passwordRequest = new AdminSetUserPasswordRequest
                {
                    UserPoolId = cognitoUserPoolID,
                    Username = email,
                    Password = password,
                    Permanent = true
                };

                provider.AdminSetUserPassword(passwordRequest);

                return true;
            }
            catch
            {
                //Log Error
                return false;
            }


        }
    }
}
