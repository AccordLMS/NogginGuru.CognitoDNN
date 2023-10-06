#region Usings

using System;
using System.Web.UI;
using DotNetNuke.Services.Authentication;
using ProcsIT.Dnn.AuthServices.OpenIdConnect;
using System.Web.UI.HtmlControls;
using ProcsIT.Dnn.Authentication.OpenIdConnect.Components;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Users;
using Amazon.Runtime;
using System.Collections.Generic;
using System.Text;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using DotNetNuke.Security.Membership;
using DotNetNuke.Services.Authentication.Oidc;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Amazon.Extensions.CognitoAuthentication;
using System.Threading;
using System.Security.Cryptography;
using System.Web.ModelBinding;
using System.Runtime.CompilerServices;
using System.IdentityModel.Tokens.Jwt;
using ProcsIT.Dnn.Authentication.OpenIdConnect;
using System.Web.UI.WebControls;
using Amazon;
using DotNetNuke.Services.Mail;
using System.Text.RegularExpressions;
using Amazon.Runtime.Internal;
using DotNetNuke.Framework.Providers;
using DotNetNuke.Common;
using DotNetNuke.Entities.Tabs;
using System.Web;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Tokens;



#endregion

namespace DNN.OpenId.Cognito
{
    public partial class Login : OidcLoginBase
    {
        protected HtmlGenericControl loginItem;
        private static DNNOpenIDCognitoConfig config;
        private AmazonCognitoIdentityProviderClient _client;
        private string email = string.Empty;
        private string password = string.Empty;
        private string username = string.Empty;

        protected override string AuthSystemApplicationName => "Oidc";

        public override bool SupportsRegistration => false;

        protected override UserData GetCurrentUser() => OAuthClient.GetCurrentUser<OidcUserData>();

        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            btnLogin.Click += new EventHandler(LoginButton_Click);
            btnSendResetLink.Click += new EventHandler(SendResetPassword_Click);
            btnResetPassword.Click += new EventHandler(ResetPassword_Click);
            lnkResetPassword.ServerClick += new EventHandler(LinkResetPassword_Click);
            OAuthClient = new OidcClient(PortalId, Mode);
            config = DNNOpenIDCognitoConfig.GetConfig(PortalId);

            //loginItem.Visible = Mode == AuthMode.Login;
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);



            if (Request.QueryString["ResetPassword"] == null)
            {
                txtPasswordAux.Visible = false;
                divUsername.Visible = false;
                lblErrorMessage.Visible = false;
                divNewPassword.Visible = false;
                divEmailCode.Visible = false;
                lblMessage.Text = config.LoginMessage;
                btnSendResetLink.Visible = false;
                btnResetPassword.Visible = false;
                if (!IsPostBack)
                {
                    txtPassword.Attributes["type"] = "password";
                    txtNewPassword.Attributes["type"] = "password"; 
                }
            }
            
            
        }

        private void LoginButton_Click(object sender, EventArgs e)
        {
            lblErrorMessage.Visible = false;

            if (email == string.Empty)
            {
                if (txtEmail.Text == string.Empty || txtEmail.Text.Trim() == "")
                {
                    lblErrorMessage.Visible = true;
                    lblErrorMessage.Text = "You need to enter an Email address.";
                    System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                    return;
                }
                else
                {
                    email = txtEmail.Text;
                }
            }

            if (!IsValidEmail(email))
            {
                lblErrorMessage.Visible = true;
                lblErrorMessage.Text = "You need to enter a valid Email address.";
                System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                return;
            }
 

            if(password == string.Empty)
            {
                if (txtPassword.Text == string.Empty || txtPassword.Text.Trim() == "")
                {
                    if(txtPasswordAux.Text == string.Empty || txtPasswordAux.Text.Trim() == "")
                    {
                        lblErrorMessage.Visible = true;
                        lblErrorMessage.Text = "You need to enter a Password.";
                        System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                        return;
                    }
                    else
                    {
                        txtPassword.Text = txtPasswordAux.Text;
                        password = txtPassword.Text;
                    }
                                        
                }
                else
                {
                    password = txtPassword.Text;
                }               
            }


            txtPoolID.Value = config.CognitoPoolID;
            txtClientID.Value = config.ApiKey;
            
            PortalController pController = new PortalController();
            string portalName = pController.GetPortal(PortalId).PortalName;
            
            if (!ExistsCognitoUser(txtEmail.Text))
            {
                var loginStatus = UserLoginStatus.LOGIN_FAILURE;
                
                bool userCreated = false;
                if (!EmailExistsAsUsername(PortalSettings, txtEmail.Text))
                {
                    username = txtUsername.Text;
                    //WE NEED TO ASK FOR THE USERNAME AND CREATE IT IN COGNITO

                    if (username == string.Empty || username.Trim() == "")
                    {
                        divEmail.Visible = false;
                        divPassword.Visible = false;
                        divUsername.Visible = true;
                        lblMessage.Text = "Please enter your username to complete migration.";
                        txtPasswordAux.Text = txtPassword.Text;
                        return;
                    }

                    UserController.ValidateUser(PortalId, username, password, "", "", portalName, ref loginStatus);

                    if (loginStatus == UserLoginStatus.LOGIN_SUCCESS || loginStatus == UserLoginStatus.LOGIN_SUPERUSER)
                    {
                        userCreated = CreateCognitoUser(txtEmail.Text, txtUsername.Text, txtPassword.Text, PortalSettings);
                    }
                    else
                    {
                        //DNN Login failed
                        lblErrorMessage.Visible = true;
                        lblErrorMessage.Text = "Login failed. Username or password are incorrect.";
                        System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                        divEmail.Visible=true;
                        divPassword.Visible=true;   
                        divUsername.Visible=true;
                        lblMessage.Visible = true;
                        lblMessage.Text = "Please enter your email, username and password";
                        return;
                    }

                }
                else
                {
                    //THE USERNAME IS THE EMAIL. WE NEED TO CREATE IT IN COGNITO
                    UserController.ValidateUser(PortalId, email, password, "", "", portalName, ref loginStatus);

                    if (loginStatus == UserLoginStatus.LOGIN_SUCCESS || loginStatus == UserLoginStatus.LOGIN_SUPERUSER)
                    {
                        userCreated = CreateCognitoUser(txtEmail.Text, txtEmail.Text, txtPassword.Text, PortalSettings);
                    }
                    else
                    {
                        //DNN Login failed
                        lblErrorMessage.Visible = true;
                        lblErrorMessage.Text = "Login failed. Username or password are incorrect.";
                        System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                        divEmail.Visible = true;
                        divPassword.Visible = true;
                        divUsername.Visible = true;
                        lblMessage.Visible = true;
                        lblMessage.Text = "Please enter your email, username and password";
                        return;
                    }
                }

                if (userCreated)
                {
                    this.CustomLogin(txtEmail.Text, txtPassword.Text, portalName);
                }
                else
                {
                    //Error creating cognito user
                    lblErrorMessage.Visible = true;
                    lblErrorMessage.Text = "There was a problem migrating your user. Please contact your administration";
                    System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                    return;
                }
            }
            else
            {
                this.CustomLogin(txtEmail.Text, txtPassword.Text, portalName);      
            }

        }

        private void SendResetPassword_Click(object sender, EventArgs e)
        {
            SendPasswordResetLink(txtEmail.Text);
            divEmail.Visible = false;
            divUsername.Visible = false;
            divPassword.Visible = false;
            divRememberMe.Visible = false;
            divResetPassword.Visible = false;
            btnLogin.Visible = false;
            btnSendResetLink.Visible = false;
            txtPasswordAux.Visible = false;
            lblErrorMessage.Visible = false;
            lblMessage.Text = "An email was sent with a code to reset the Password. Please enter the code and your new password below to reset it.";
            divNewPassword.Visible = true;
            divEmailCode.Visible = true;
            btnResetPassword.Visible = true;

        }

        private void ResetPassword_Click(object sender, EventArgs e)
        {
            ResetPassword(txtEmail.Text);
            divEmail.Visible = false;
            divUsername.Visible = false;
            divPassword.Visible = false;
            divRememberMe.Visible = false;
            divResetPassword.Visible = false;
            btnLogin.Visible = false;
            btnSendResetLink.Visible = false;
            txtPasswordAux.Visible = false;
            lblErrorMessage.Visible = false;
            lblMessage.Text = "Your password has been reset.";
            divNewPassword.Visible = false;
            divEmailCode.Visible = false;
            btnResetPassword.Visible = false;

        }

        private void LinkResetPassword_Click(object sender, EventArgs e)
        {
            divEmail.Visible = true;
            divUsername.Visible = false;
            divPassword.Visible = false;
            divRememberMe.Visible = false;
            divResetPassword.Visible = false;
            btnLogin.Visible = false;
            btnSendResetLink.Visible = true;
            txtPasswordAux.Visible = false;
            lblErrorMessage.Visible = false;
            lblMessage.Text = "Please enter your email address and we will send an email with a link to Reset your password";


        }

        public bool CreateCognitoUser(string email, string DNNUsername, string password, PortalSettings settings)
        {
            try
            {
                string cognitoIAMUserAccessKey = config.IAMUserAccessKey;
                string cognitoIAMUserSecretKey = config.IAMUserSecretKey;
                string cognitoAPPUsername = config.AppUsername;
                string cognitoAPPClientID = config.ApiKey;
                string cognitoAPPSecretKey = config.ApiSecret;
                string cognitoUserPoolID = config.CognitoPoolID;

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
            catch (Exception ex)
            {
                //Log Error
                return false;
            }


        }

        public bool ExistsCognitoUser(string email)
        {
            try
            {
                string cognitoIAMUserAccessKey = config.IAMUserAccessKey;
                string cognitoIAMUserSecretKey = config.IAMUserSecretKey;
                string cognitoUserPoolID = config.CognitoPoolID;

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
            catch (Exception ex)
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

        public void SendPasswordResetLink(string username)
        {
            string cognitoIAMUserAccessKey = config.IAMUserAccessKey;
            string cognitoIAMUserSecretKey = config.IAMUserSecretKey;
            string cognitoUserPoolID = config.CognitoPoolID;

            BasicAWSCredentials credentials = new Amazon.Runtime.BasicAWSCredentials(cognitoIAMUserAccessKey, cognitoIAMUserSecretKey);

            AmazonCognitoIdentityProviderClient providerClient = new AmazonCognitoIdentityProviderClient(credentials, Amazon.RegionEndpoint.USEast1);

            var secretHash = CalculateSecretHash(username, config.ApiKey, config.ApiSecret);

            var adminCreateUserPasswordResetRequest = new ForgotPasswordRequest
            {
                ClientId = config.ApiKey,
                Username = username,
                SecretHash = secretHash,
            };

            providerClient.ForgotPassword(adminCreateUserPasswordResetRequest);
        }

        public void ResetPassword(string username)
        {
            string cognitoIAMUserAccessKey = config.IAMUserAccessKey;
            string cognitoIAMUserSecretKey = config.IAMUserSecretKey;
            string cognitoUserPoolID = config.CognitoPoolID;

            BasicAWSCredentials credentials = new Amazon.Runtime.BasicAWSCredentials(cognitoIAMUserAccessKey, cognitoIAMUserSecretKey);

            AmazonCognitoIdentityProviderClient providerClient = new AmazonCognitoIdentityProviderClient(credentials, Amazon.RegionEndpoint.USEast1);

            var secretHash = CalculateSecretHash(username, config.ApiKey, config.ApiSecret);

            // Create a ConfirmForgotPasswordRequest
            var confirmForgotPasswordRequest = new ConfirmForgotPasswordRequest
            {
                ClientId = config.ApiKey,
                SecretHash = secretHash,
                Username = username,
                ConfirmationCode = txtEmailCode.Text, // The code received in the email
                Password = txtNewPassword.Text,
            };

            // Confirm the forgot password request
            var confirmForgotPasswordResponse = providerClient.ConfirmForgotPassword(confirmForgotPasswordRequest);

            if(confirmForgotPasswordResponse.HttpStatusCode == System.Net.HttpStatusCode.OK)
            {
                divEmail.Visible = true;
            }

        }

        [HttpPost]
        public void CustomLogin(string username, string password, string portalName)
        {
            string clientID = config.ApiKey;
            string clientSecret = config.ApiSecret;

            var credentials = new Amazon.Runtime.BasicAWSCredentials("accessKey", "secretKey");
            var region = Amazon.RegionEndpoint.USEast1;
            _client = new AmazonCognitoIdentityProviderClient(credentials, region);

            try
            {
                var secretHash = CalculateSecretHash(username, clientID, clientSecret);

                var request = new InitiateAuthRequest
                {
                    AuthFlow = AuthFlowType.USER_PASSWORD_AUTH,
                    AuthParameters = new Dictionary<string, string>
                {
                    { "USERNAME", username },
                    { "PASSWORD", password },
                    { "SECRET_HASH", secretHash }
                },
                    ClientId = clientID,
                    ClientMetadata = new Dictionary<string, string>
                 {
                    {"scope", "openid"}, // Include the "openid" scope here
                 }
            };

                

                var response = _client.InitiateAuth(request);

                // Check the authentication result
                if (response.AuthenticationResult != null)
                {
                    // Authentication successful
                    var accessToken = response.AuthenticationResult.AccessToken;
                    if (accessToken != null && accessToken != "")
                    {
                        SetCookie("cognitoAccessToken", accessToken, 120);
                    }

                    var refreshToken = response.AuthenticationResult.RefreshToken;
                    if(refreshToken != null && refreshToken != "")
                    {
                        SetCookie("cognitoRefreshToken", refreshToken, 120);
                    }

                    var idToken = response.AuthenticationResult.IdToken;
                    
                    var handler = new JwtSecurityTokenHandler();
                    var token = handler.ReadJwtToken(accessToken);

                    var jwtToken = handler.ReadJwtToken(idToken);

                    if (jwtToken.Payload.TryGetValue("scope", out var scopes))
                    {
                        var scopeString = scopes.ToString();
                        if (scopeString.Contains("openid"))
                        {
                            // The "openid" scope is present in the token
                            Console.WriteLine("Token includes 'openid' scope.");
                        }
                        else
                        {
                            Console.WriteLine("Token does not include 'openid' scope.");
                        }
                    }


                    var profileProperties = new Dictionary<string, string>();
                    foreach (var claim in token.Claims)
                    {
                        // Extract the profile properties from the claims
                        if (claim.Type.StartsWith("username"))
                        {
                            var cognitoUsername = claim.Value;
                            if (cognitoUsername != null && cognitoUsername.Length > 0)
                            {
                                string cognitoIAMUserAccessKey = config.IAMUserAccessKey;
                                string cognitoIAMUserSecretKey = config.IAMUserSecretKey;
                                string cognitoUserPoolID = config.CognitoPoolID;

                                BasicAWSCredentials AWScredentials = new Amazon.Runtime.BasicAWSCredentials(cognitoIAMUserAccessKey, cognitoIAMUserSecretKey);

                                AmazonCognitoIdentityProviderClient provider = new AmazonCognitoIdentityProviderClient(AWScredentials, Amazon.RegionEndpoint.USEast1);

                                var cognitoRequest = new AdminGetUserRequest();
                                cognitoRequest.Username = cognitoUsername;
                                cognitoRequest.UserPoolId = cognitoUserPoolID;

                                AdminGetUserResponse cognitoUser = provider.AdminGetUser(cognitoRequest);

                                foreach (AttributeType attribute in cognitoUser.UserAttributes)
                                {
                                    if (attribute.Name == "custom:DNNUsername")
                                    {
                                        UserInfo objUserInfo = UserController.GetUserByName(attribute.Value);
                                        UserLoginStatus loginStatus = UserLoginStatus.LOGIN_SUCCESS;
                                        var eventArgs = new UserAuthenticatedEventArgs(objUserInfo, objUserInfo.Email, loginStatus, "Oidc")
                                        {
                                            Authenticated = true,
                                            Message = "User authorized",
                                            RememberMe = false
                                        };

                                        UserController.UserLogin(PortalId, objUserInfo, portalName, "Oidc", false);
                                        Response.Redirect(config.RedirectURL);
                                        return;
                                    }
                                }



                            }
                            return;
                        }
                    }

                }
                else
                {
                    //USER DID NOT AUTHENTICATE IN COGNITO
                    lblErrorMessage.Visible = true;
                    lblErrorMessage.Text = "Login failed. Email or password are incorrect.";
                    System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                    divEmail.Visible = true;
                    divPassword.Visible = true;
                    divUsername.Visible = true;
                    lblMessage.Visible = true;
                    lblMessage.Text = "Please enter your email and password";
                    return;
                }
            }
            catch (Amazon.CognitoIdentityProvider.Model.NotAuthorizedException ex)
            {
                //USER DID NOT AUTHENTICATE IN COGNITO
                lblErrorMessage.Visible = true;
                lblErrorMessage.Text = "Login failed. Email or password are incorrect.";
                System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                divEmail.Visible = true;
                divPassword.Visible = true;
                divUsername.Visible = false;
                lblMessage.Visible = true;
                lblMessage.Text = "Please enter your email and password";
                return;
            }
            catch (Exception ex)
            {
                //USER DID NOT AUTHENTICATE IN COGNITO
                lblErrorMessage.Visible = true;
                lblErrorMessage.Text = "Login failed. Email or password are incorrect.";
                System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
                divEmail.Visible = true;
                divPassword.Visible = true;
                divUsername.Visible = false;
                lblMessage.Visible = true;
                lblMessage.Text = "Please enter your email and password";
                return;

            }
        }

        private string CalculateSecretHash(string username, string clientID, string clientSecret)
        {
            var message = Encoding.UTF8.GetBytes(username + clientID);
            var key = Encoding.UTF8.GetBytes(clientSecret);
            using (var hmac = new HMACSHA256(key))
            {
                var hashBytes = hmac.ComputeHash(message);
                return Convert.ToBase64String(hashBytes);
            }
        }

        static bool IsValidEmail(string email)
        {
            // Regular expression pattern for validating email addresses
            string pattern = @"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(email, pattern);
        }

        public void SetCookie(string key, string value, int expirationMinutes)
        {
            if(ExistsCookie(key))
            {
                Response.Cookies.Remove(key);                
            }
           
            HttpCookie cookie = new HttpCookie(key, value);
            cookie.Expires = DateTime.UtcNow.AddMinutes(expirationMinutes);

            Response.Cookies.Add(cookie);           
        }

        public bool ExistsCookie(string cookieName)
        {
            foreach (string cookie in Request.Cookies.AllKeys)
            {
                if (cookie == cookieName)
                {
                    return true;
                }
            }
            return false;
        }


    }
}

