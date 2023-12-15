#region Usings

using System;
using System.Web.UI;
using DotNetNuke.Services.Authentication;
using ProcsIT.Dnn.AuthServices.OpenIdConnect;
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
using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Text.RegularExpressions;
using System.Web;
using Newtonsoft.Json.Linq;
using Microsoft.IdentityModel.Tokens;
using DotNetNuke.Services.Tokens;
using HttpContext = System.Web.HttpContext;
using DotNetNuke.Services.Localization;
using Newtonsoft.Json;
using System.IO;
using System.Net;
using System.Net.Http;
using IdentityModel.Client;
using System.Linq;
using ProcsIT.Dnn.Authentication.OpenIdConnect;
using DotNetNuke.Common;
using DotNetNuke.Common.Utilities;
using DotNetNuke.UI.Skins.Controls;



#endregion

namespace DNN.OpenId.Cognito
{
    public partial class Login : AuthenticationLoginBase
    {

        private TokenResponse objTokenResponse { get; set; }
        protected OidcClientBase OAuthClient { get; set; }


        public new string RedirectURL { 
            get 
            { 
                return _redirectURL;
            } 
            set {} 
        }

        //Query string parameters
        private string _CognitoVerificationCode => HttpContext.Current.Request.Params["code"];
        private string _DNNVerificationCode => HttpContext.Current.Request.Params["verificationcode"];

        private string _redirectURL;



        private DNNOpenIDCognitoConfig config;
        private AmazonCognitoIdentityProviderClient _client;
        private string email = string.Empty;
        private string password = string.Empty;
        
        private string AuthorizationEndpoint = string.Empty;
        private string TokenEndpoint = string.Empty;

        protected string AuthSystemApplicationName => "Oidc";

        
        protected UserData GetCurrentUser() => OAuthClient.GetCurrentUser<OidcUserData>();


        public override bool Enabled {  
            get {
                if (config == null) config = DNNOpenIDCognitoConfig.GetConfig(PortalId);
                return config.Enabled;
            } 
        }


        /// <summary>
        /// redirects the user to the hosted UI to get a code when comming back
        /// </summary>
        public virtual void GetCode()
        {
            // hybrid flow
            var parameters = new List<QueryParameter>
                                        {
                                            new QueryParameter { Name = OAuthConsts.ResponseTypeKey, Value = OAuthConsts.CodeKey },
                                            new QueryParameter { Name = OAuthConsts.ClientIdKey, Value = config.ApiKey },
                                            new QueryParameter { Name = OAuthConsts.RedirectUriKey, Value = config.LoginUrl },
                                            new QueryParameter { Name = "scope", Value = "openid profile" },
                                            new QueryParameter { Name = "state", Value = AuthSystemApplicationName }
                                        };

            // Call authorization endpoint
            HttpContext.Current.Response.Redirect(AuthorizationEndpoint + "?" + parameters.ToNormalizedString(), true);
        }

        /// <summary>
        /// After you have code in the url, call the token endpoint to get the user data, and login the user in DNN
        /// </summary>
        /// <returns></returns>
        public virtual AuthorisationResult Authorize()
        {

            var parameters = new List<QueryParameter>
            {
                new QueryParameter { Name = OAuthConsts.ClientIdKey, Value = config.ApiKey },
                new QueryParameter { Name = OAuthConsts.RedirectUriKey, Value = config.LoginUrl },
                new QueryParameter { Name = OAuthConsts.ClientSecretKey, Value = config.ApiSecret },
                new QueryParameter { Name = OAuthConsts.GrantTypeKey, Value = "authorization_code" },
                new QueryParameter { Name = OAuthConsts.CodeKey, Value = _CognitoVerificationCode }
            };


            var responseText = ExecuteWebRequest(HttpMethod.Post, new Uri(TokenEndpoint), parameters.ToNormalizedString());
            if (responseText == null)
                return AuthorisationResult.Denied;

            objTokenResponse = new TokenResponse(responseText);

            if (objTokenResponse.IsError)
                return AuthorisationResult.Denied;


            string username = String.Empty;
            bool isFederatedLogin = false;

            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (tokenHandler.CanReadToken(objTokenResponse.IdentityToken))
            {
                var token = tokenHandler.ReadJwtToken(objTokenResponse.IdentityToken);
                isFederatedLogin = token.Claims.Count(c => c.Type == "identities") > 0;
            }

            if (isFederatedLogin)
            {
                username = GetDNNUserName(objTokenResponse.IdentityToken);
            }
            else 
            {
                username = GetUserName(objTokenResponse.IdentityToken);
            }

            if (username == null || username == string.Empty)
                return AuthorisationResult.Denied;
            else
            {
                //user exits and was validated in cognito, so, login to DNN
                PortalController pController = new PortalController();
                string portalName = pController.GetPortal(PortalId).PortalName;


                LoginUser(portalName,username);

                return AuthorisationResult.Authorized;
            }
            
        }

        /// <summary>
        /// Get the username from the token
        /// </summary>
        /// <param name="identityToken">the identity token from cognito</param>
        /// <returns>the dnn username</returns>
        private string GetUserName(string identityToken)
        {
            string username = string.Empty;
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(identityToken))
                return null;

            var token = tokenHandler.ReadJwtToken(identityToken);
            username = token.Claims.First(c => c.Type == "custom:DNNUsername").Value;
            return username;
        }

        /// <summary>
        /// For federated logins, check if the user exists, else creates a user
        /// </summary>
        /// <param name="identityToken"></param>
        /// <returns></returns>
        private string GetDNNUserName(string identityToken)
        {
            var userName = String.Empty;
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(identityToken))
                return String.Empty;
            var token = tokenHandler.ReadJwtToken(identityToken);

            if (config.HandleSSOLogins)
            {
                var userEmail = String.Empty;
                try
                {
                    userEmail = token.Claims.First(c => c.Type == "email")?.Value;
                }
                catch (Exception ex)
                {
                    
                    userEmail = ConstructSyntheticEmail(identityToken);
                }

                
                if (!EmailExistsAsUsername(PortalSettings, userEmail))
                {
                    UserController userController = new UserController();

                    var userInfo = new UserInfo()
                    {
                        PortalID = PortalId,
                        Username = userEmail,
                        Email = userEmail,
                        Membership = { Password = "test@1234", Approved = true }
                    };

                    try
                    {
                        UserCreateStatus userCreateStatus = UserController.CreateUser(ref userInfo);
                        if (userCreateStatus == UserCreateStatus.Success)
                        {
                            return userInfo.Username;
                        }

                    }
                    catch (Exception ex)
                    {
                        return String.Empty;
                    }

                }
                else
                {
                    var user = UserController.GetUserByName(userEmail);
                    if (user != null)
                    {
                        return user.Username;
                    }
                }

            }
            return userName;
        }

        /// <summary>
        /// Construct a synthetic email string from claims in the id token
        /// </summary>
        /// <param name="identityToken"></param>
        /// <returns></returns>
        private string ConstructSyntheticEmail(string identityToken)
        {
            var syntheticEmail = String.Empty;
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(identityToken))
                return String.Empty;
            var token = tokenHandler.ReadJwtToken(identityToken);
            string identitiesClaim = token.Claims.First(c => c.Type == "identities").Value.ToString();
            var identitiesClaimJson = JObject.Parse(identitiesClaim);
            var userId = token.Claims.First(c => c.Type == "sub")?.Value;
            var domain = identitiesClaimJson["providerName"]?.ToString().ToLower();

            syntheticEmail =  $"{userId}@{domain}.com";
            return syntheticEmail;
        }

        /// <summary>
        /// executes a web call with parameters and authentication based on module configuration
        /// </summary>
        /// <param name="method">web method to be used</param>
        /// <param name="uri">URI</param>
        /// <param name="parameters">parameters (will be included in url for get, or body for post)</param>
        /// <returns>the full response</returns>
        private string ExecuteWebRequest(HttpMethod method, Uri uri, string parameters )
        {
            WebRequest request;

            if (method == HttpMethod.Post)
            {
                byte[] byteArray = Encoding.UTF8.GetBytes(parameters);

                request = WebRequest.CreateDefault(uri);
                request.Method = "POST";
                request.ContentType = "application/x-www-form-urlencoded";
                request.ContentLength = byteArray.Length;

                if (!string.IsNullOrEmpty(parameters))
                {
                    Stream dataStream = request.GetRequestStream();
                    dataStream.Write(byteArray, 0, byteArray.Length);
                    dataStream.Close();
                }
            }
            else
            {
                request = WebRequest.CreateDefault(GenerateRequestUri(uri.ToString(), parameters));
            }

            if (objTokenResponse?.AccessToken != null)
                request.Headers.Add($"Authorization: Bearer {objTokenResponse.AccessToken}");
            else
            {

                string svcCredentials = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(config.ApiKey + ":" + config.ApiSecret));

                request.Headers.Add("Authorization", "Basic " + svcCredentials);
            }

            try
            {
                using (WebResponse response = request.GetResponse())
                using (Stream responseStream = response.GetResponseStream())
                {
                    if (responseStream != null)
                    {
                        using (var responseReader = new StreamReader(responseStream))
                        {
                            return responseReader.ReadToEnd();
                        }
                    }
                }
            }
            catch (WebException ex)
            {
                DotNetNuke.Services.Exceptions.Exceptions.LogException(ex);
                using (Stream responseStream = ex.Response.GetResponseStream())
                {
                    if (responseStream != null)
                    {
                        using (var responseReader = new StreamReader(responseStream))
                        {
                            Exception customEx = new Exception(responseReader.ReadToEnd(), ex);
                            DotNetNuke.Services.Exceptions.Exceptions.LogException(customEx);
                        }
                    }
                }
            }
            return null;
        }

        private Uri GenerateRequestUri(string url, string parameters)
        {
            if (string.IsNullOrEmpty(parameters))
                return new Uri(url);

            return new Uri(string.Format("{0}{1}{2}", url, url.Contains("?") ? "&" : "?", parameters));
        }


        protected override void OnInit(EventArgs e)
        {
            if (config  == null) config = DNNOpenIDCognitoConfig.GetConfig(PortalId);
            
            AuthorizationEndpoint = config.CognitoDomain + "/oauth2/authorize";
            TokenEndpoint = config.CognitoDomain + "/oauth2/token";
            _redirectURL = config.RedirectURL;

            if (!string.IsNullOrEmpty(_DNNVerificationCode))
                VerifyUser();

            if (_CognitoVerificationCode != null && _CognitoVerificationCode != "")
            {
                Authorize();
            }
            else if (config.Enabled && config.UseHostedUI && UserController.Instance.GetCurrentUserInfo() != null) 
            {
                GetCode();
            }
            else 
            {
                base.OnInit(e);
                btnLogin.Click += new EventHandler(LoginButton_Click);
                btnSendResetLink.Click += new EventHandler(SendResetPassword_Click);
                btnResetPassword.Click += new EventHandler(ResetPassword_Click);
                lnkResetPassword.ServerClick += new EventHandler(LinkResetPassword_Click);
                OAuthClient = new OidcClient(PortalId, Mode);
            }



        }


        private void VerifyUser()
        {
            if (!string.IsNullOrEmpty(_DNNVerificationCode) && this.PortalSettings.UserRegistration == (int)Globals.PortalRegistrationType.VerifiedRegistration)
            {
                
                try
                {
                    UserController.VerifyUser(_DNNVerificationCode.Replace(".", "+").Replace("-", "/").Replace("_", "="));

                }
                catch (UserAlreadyVerifiedException)
                {
                    DotNetNuke.UI.Skins.Skin.AddModuleMessage(this, Localization.GetString("UserAlreadyVerified", this.LocalResourceFile), ModuleMessage.ModuleMessageType.YellowWarning);
                }
                catch (InvalidVerificationCodeException)
                {
                    DotNetNuke.UI.Skins.Skin.AddModuleMessage(this, Localization.GetString("InvalidVerificationCode", this.LocalResourceFile), ModuleMessage.ModuleMessageType.RedError);
                }
                catch (UserDoesNotExistException)
                {
                    DotNetNuke.UI.Skins.Skin.AddModuleMessage(this, Localization.GetString("UserDoesNotExist", this.LocalResourceFile), ModuleMessage.ModuleMessageType.RedError);
                }
                catch (Exception)
                {
                    DotNetNuke.UI.Skins.Skin.AddModuleMessage(this, Localization.GetString("InvalidVerificationCode", this.LocalResourceFile), ModuleMessage.ModuleMessageType.RedError);
                }
            }
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

                NG.Cognito.AWS.AWSUserController awsUser = new NG.Cognito.AWS.AWSUserController(config);

                bool userCreated = false;
                if (!EmailExistsAsUsername(PortalSettings, txtEmail.Text))
                {
                    string username = txtUsername.Text;
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
                        userCreated = awsUser.CreateCognitoUser(txtEmail.Text, txtUsername.Text, txtPassword.Text, PortalSettings);
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
                        userCreated = awsUser.CreateCognitoUser(txtEmail.Text, txtEmail.Text, txtPassword.Text, PortalSettings);
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
            lblMessage.Text = "Please enter your email address and we will send an email with a code to Reset your password";


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
            catch
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
                        //SetCookie("cognitoAccessToken", accessToken, 120);
                    }

                    var refreshToken = response.AuthenticationResult.RefreshToken;
                    if(refreshToken != null && refreshToken != "")
                    {
                        //SetCookie("cognitoRefreshToken", refreshToken, 120);
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
                                        LoginUser(portalName, attribute.Value);
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
                    PresentError();

                    divUsername.Visible = true;
                }
            }
            
            catch 
            {
                //USER DID NOT AUTHENTICATE IN COGNITO
                PresentError();

            }
        }

        /// <summary>
        /// it logs in the DNN user
        /// </summary>
        /// <param name="portalName">dnn portal name</param>
        /// <param name="userName">user name</param>
        private void LoginUser(string portalName, string userName)
        {
            UserInfo objUserInfo = UserController.GetUserByName(userName);
                       
            AuthenticationController.SetAuthenticationType(AuthSystemApplicationName);
            UserController.UserLogin(PortalId, objUserInfo, portalName, AuthSystemApplicationName, false);
            Response.Redirect(config.RedirectURL);
            Response.End();
        }

        /// <summary>
        /// shows the error controls with appropiate message
        /// </summary>
        private void PresentError()
        {
            lblErrorMessage.Visible = true;
            lblErrorMessage.Text = "Login failed. Email or password are incorrect.";
            System.Web.UI.ScriptManager.RegisterStartupScript(this, this.GetType(), "HideErrorLabel", "setTimeout(hideErrorLabel, 5000);", true);
            divEmail.Visible = true;
            divPassword.Visible = true;
            divUsername.Visible = false;
            lblMessage.Visible = true;
            lblMessage.Text = "Please enter your email and password";
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

