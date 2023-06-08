#region Usings

using System;

using DotNetNuke.Services.Authentication;
using System.Web.UI.WebControls;
using ProcsIT.Dnn.AuthServices.OpenIdConnect;
using System.Web.UI.HtmlControls;
using ProcsIT.Dnn.Authentication.OpenIdConnect.Components;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Users;
using Amazon.Runtime;
using DotNetNuke.UI.UserControls;
using System.Collections.Generic;
using System.Text;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using ProcsIT.Dnn.Authentication.OpenIdConnect;
using System.Runtime;


#endregion

namespace DNN.OpenId.Cognito
{
    public partial class Login : OidcLoginBase
    {
        protected HtmlGenericControl loginItem;

        protected override string AuthSystemApplicationName => "Oidc";

        public override bool SupportsRegistration => false;

        protected override UserData GetCurrentUser() => OAuthClient.GetCurrentUser<OidcUserData>();

        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            btnLogin.Click += new EventHandler(LoginButton_Click);
            OAuthClient = new OidcClient(PortalId, Mode);
            loginItem.Visible = Mode == AuthMode.Login;
        }

        private void LoginButton_Click(object sender, EventArgs e)
        {
            if (!ExistsCognitoUser(txtEmail.Text))
            {
                bool userCreated = false;
                if (!EmailExistsAsUsername(PortalSettings, txtEmail.Text))
                {
                    //WE NEED TO ASK FOR THE USERNAME AND CREATE IT IN COGNITO
                    userCreated = CreateCognitoUser(txtEmail.Text, txtUsername.Text, txtPassword.Text, PortalSettings);
                }
                else
                {
                    //THE USERNAME IS THE EMAIL. WE NEED TO CREATE IT IN COGNITO
                    userCreated = CreateCognitoUser(txtEmail.Text, txtEmail.Text, txtPassword.Text, PortalSettings);                   
                }

                if (userCreated)
                {
                    OAuthClient.Authorize();
                }
            }
            else
            {
                OAuthClient.Authorize();
            }
            
        }

        public bool CreateCognitoUser(string email, string DNNUsername, string password, PortalSettings settings)
        {
            try
            {
                string cognitoIAMUserAccessKey = "";
                string cognitoIAMUserSecretKey = "";
                string cognitoAPPUsername = "";
                string cognitoAPPClientID = "";
                string cognitoAPPSecretKey = "";
                string cognitoUserPoolID = "";

                UserInfo objUserInfo = UserController.GetUserByName(settings.PortalId, DNNUsername);

                BasicAWSCredentials credentials = new Amazon.Runtime.BasicAWSCredentials(cognitoIAMUserAccessKey, cognitoIAMUserSecretKey);

                AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(credentials, Amazon.RegionEndpoint.USEast1);

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
                    new AttributeType { Name = "custom:PreferredUsername", Value = objUserInfo.Username },
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
            catch(Exception ex)
            {
                //Log Error
                return false;
            }
            
            
        }

        public bool ExistsCognitoUser(string email)
        {
            try
            {
                string cognitoIAMUserAccessKey = "";
                string cognitoIAMUserSecretKey = "";
                string cognitoUserPoolID = "";

                BasicAWSCredentials credentials = new Amazon.Runtime.BasicAWSCredentials(cognitoIAMUserAccessKey, cognitoIAMUserSecretKey);

                AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(credentials, Amazon.RegionEndpoint.USEast1);

                var request = new AdminGetUserRequest();
                request.Username = email;
                request.UserPoolId = cognitoUserPoolID;

                AdminGetUserResponse cognitoUser = provider.AdminGetUser(request);

                if (cognitoUser != null)
                {
                    return true;
                }
                else
                {
                    return false;
                }
            }
            catch(Exception ex)
            {
                //log error
                return false;
            }
            
        }
        public bool EmailExistsAsUsername(PortalSettings settings, string email)
        {
            UserInfo objUserInfo = UserController.GetUserByName(settings.PortalId, email);
            if (objUserInfo == null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }
    }


    
}

