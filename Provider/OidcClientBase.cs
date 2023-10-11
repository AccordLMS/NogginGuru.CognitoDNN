using DNN.OpenId.Cognito;
using DotNetNuke.Common;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Data;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Entities.Users;
using DotNetNuke.Instrumentation;
using DotNetNuke.Security.Membership;
using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Authentication.Oidc;
using DotNetNuke.Services.Localization;
using DotNetNuke.UI.UserControls;
using IdentityModel.Client;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Globalization;
using System.IdentityModel.Selectors;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Web;

namespace ProcsIT.Dnn.AuthServices.OpenIdConnect
{
    public abstract class OidcClientBase
    {
        protected string AuthorizationEndpoint { get; set; }
        protected string UserInfoEndpoint { get; set; }
        protected string TokenEndpoint { get; set; }
        protected string Scope { get; set; }
        protected string APIResource { get; set; }

        private static DNNOpenIDCognitoConfig moduleConfig;

        private string VerificationCode => HttpContext.Current.Request.Params[OAuthCodeKey];

        private TokenResponse TokenResponse { get; set; }

        private static readonly ILog Logger = LoggerSource.Instance.GetLogger(typeof(OidcClientBase));
        private static DNNOpenIDCognitoConfig config;

        private const string OAuthClientIdKey = "client_id";
        private const string OAuthClientSecretKey = "client_secret";
        private const string OAuthRedirectUriKey = "redirect_uri";
        private const string OAuthGrantTypeKey = "grant_type";
        private const string OAuthCodeKey = "code";
        private const string OAuthHybrid = "code id_token";
        private const string OAuthToken = "token";

        private readonly Random _random = new Random();

        private readonly string _apiKey;
        private readonly string _apiSecret;
        private readonly string _callbackUri;
        private readonly string _service;
        private readonly AuthMode _authMode;

        //Set default Expiry to 14 days 
        private TimeSpan AuthTokenExpiry { get; set; } = new TimeSpan(14, 0, 0, 0);

        protected OidcClientBase(int portalId, AuthMode mode, string service)
        {
            moduleConfig = DNNOpenIDCognitoConfig.GetConfig(portalId);
            _authMode = mode;
            _service = service;

            _apiKey = moduleConfig.ApiKey;
            _apiSecret = moduleConfig.ApiSecret;

            _callbackUri = _authMode == AuthMode.Login
                                    ? Globals.LoginURL(string.Empty, false)
                                    : Globals.RegisterURL(string.Empty, string.Empty);
        }

        public virtual void Authorize()
        {
            // hybrid flow
            var parameters = new List<QueryParameter>
                                        {
                                            new QueryParameter { Name = "response_type", Value = OAuthCodeKey },//added by Javier
                                            //new QueryParameter { Name = "response_type", Value = OAuthHybrid },
                                            new QueryParameter { Name = OAuthClientIdKey, Value = _apiKey },
                                            new QueryParameter { Name = OAuthRedirectUriKey, Value = _callbackUri },
                                            new QueryParameter { Name = "scope", Value = Scope },
                                            //new QueryParameter { Name = "nonce", Value = GenerateNonce() },
                                            new QueryParameter { Name = "state", Value = _service }//,
                                            //new QueryParameter { Name = "response_mode", Value = "form_post" }
                                        };

            // Call authorization endpoint
            //HttpContext.Current.Response.Redirect(AuthorizationEndpoint + "?" + parameters.ToNormalizedString(), true);
        }

        //public virtual AuthorisationResult Authorize(PortalSettings settings, string IPAddress)
        //{
        //    // TODO: When user is allowed to give consent, what to do when certain items are denied?
        //    // refresh_token -> unable to refresh
        //    // userClaims => only sub is known, other claims remain empty
        //    // api1 => no access to api
        //    // The client can be configured to set required items or not ask for consent. But if not:
        //    // TODO: implement missing refresh token, unable to access api

            


        //    var parameters = new List<QueryParameter>
        //    {
        //        new QueryParameter { Name = OAuthClientIdKey, Value = _apiKey },
        //        new QueryParameter { Name = OAuthRedirectUriKey, Value = _callbackUri },
        //        new QueryParameter { Name = OAuthClientSecretKey, Value = _apiSecret },
        //        new QueryParameter { Name = OAuthGrantTypeKey, Value = "authorization_code" },
        //        new QueryParameter { Name = OAuthCodeKey, Value = VerificationCode }
        //    };

        //    if (!string.IsNullOrEmpty(APIResource))
        //        parameters.Add(new QueryParameter { Name = "resource", Value = APIResource });

        //    var responseText = ExecuteWebRequest(HttpMethod.Post, new Uri(TokenEndpoint), parameters.ToNormalizedString(), string.Empty);
        //    if (responseText == null)
        //        return AuthorisationResult.Denied;

        //    TokenResponse = new TokenResponse(responseText);

        //    if (TokenResponse.IsError)
        //        return AuthorisationResult.Denied;



        //    // IdentityToken is available, perform checks:
        //    //var acceptedScopes = HttpContext.Current.Request["Scope"];
        //    var userId = GetUserId(TokenResponse.IdentityToken);

        //    if (userId == null)
        //        return AuthorisationResult.Denied;

        //    //var loginStatus = UserLoginStatus.LOGIN_FAILURE;
        //    //var objUserInfo = UserController.ValidateUser(settings.PortalId, userId, string.Empty, _service, string.Empty, settings.PortalName, IPAddress, ref loginStatus);
        //    //if (objUserInfo != null && (objUserInfo.IsDeleted || loginStatus != UserLoginStatus.LOGIN_SUCCESS))
        //    //    return AuthorisationResult.Denied;


        //    AuthTokenExpiry = GetExpiry(Convert.ToInt32(TokenResponse.ExpiresIn));
        //    return TokenResponse == null ? AuthorisationResult.Denied : AuthorisationResult.Authorized;
        //}

        private string GenerateNonce()
        {
            // Just a simple implementation of a random number between 123400 and 9999999
            return _random.Next(123400, 9999999).ToString(CultureInfo.InvariantCulture);
        }

        public virtual void redirectToUrl()
        {
            string url = moduleConfig.RedirectURL;

            if (url == null) return;

            HttpContext.Current.Response.Redirect(url + "?AuthorizationCode=" + VerificationCode);
        }

        private string ComputeHash(HashAlgorithm hashAlgorithm, string data)
        {
            if (hashAlgorithm == null)
                throw new ArgumentNullException("hashAlgorithm");

            if (string.IsNullOrEmpty(data))
                throw new ArgumentNullException("data");

            byte[] dataBuffer = Encoding.ASCII.GetBytes(data);
            byte[] hashBytes = hashAlgorithm.ComputeHash(dataBuffer);

            return Convert.ToBase64String(hashBytes);
        }
        
        private string ExecuteWebRequest(HttpMethod method, Uri uri, string parameters, string authHeader)
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

            if (TokenResponse?.AccessToken != null)
                request.Headers.Add($"Authorization: Bearer {TokenResponse.AccessToken}");
            else
            {
                string username = _apiKey;
                string password = _apiSecret;

                string svcCredentials = Convert.ToBase64String(ASCIIEncoding.ASCII.GetBytes(username + ":" + password));

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
                using (Stream responseStream = ex.Response.GetResponseStream())
                {
                    if (responseStream != null)
                    {
                        using (var responseReader = new StreamReader(responseStream))
                        {
                            Logger.ErrorFormat("WebResponse exception: {0}", responseReader.ReadToEnd());
                        }
                    }
                }
            }
            return null;
        }

        private string GenerateSignatureUsingHash(string signatureBase, HashAlgorithm hash)
        {
            return ComputeHash(hash, signatureBase);
        }

        private Uri GenerateRequestUri(string url, string parameters)
        {
            if (string.IsNullOrEmpty(parameters))
                return new Uri(url);

            return new Uri(string.Format("{0}{1}{2}", url, url.Contains("?") ? "&" : "?", parameters));
        }

        protected virtual TimeSpan GetExpiry(int expiresIn)
        {
            return TimeSpan.MinValue;
        }

        protected virtual string GetToken(string accessToken)
        {
            return accessToken;
        }

        public virtual void AuthenticateUser(UserData user, PortalSettings settings, string IPAddress, Action<NameValueCollection> addCustomProperties, Action<UserAuthenticatedEventArgs> onAuthenticated)
        {
            if (user.Username != null && user.Email != null)
            {
                if (user.FirstName == null || user.FirstName == "")
                {
                    user.FirstName = user.Username;  
                }
                if (user.LastName == null || user.LastName == "")
                {
                    user.LastName = user.Username;
                }


                UserInfo objUserInfo = UserController.GetUserByName(settings.PortalId, user.Username);
                //var objUserInfo = UserController.ValidateUser(settings.PortalId, user.Username, string.Empty, _service, string.Empty, settings.PortalName, IPAddress, ref loginStatus);

                if (objUserInfo == null)
                {
                    //We create the user
                    objUserInfo = new UserInfo();
                    objUserInfo.FirstName = user.FirstName;
                    objUserInfo.LastName = user.LastName;
                    objUserInfo.Email = user.Email;
                    objUserInfo.Username = user.Username;
                    objUserInfo.DisplayName = user.DisplayName;
                    objUserInfo.Membership.Password = UserController.GeneratePassword();
                    objUserInfo.PortalID = settings.PortalId;
                    objUserInfo.IsSuperUser = false;
                    var usrCreateStatus = new UserCreateStatus();

                    usrCreateStatus = UserController.CreateUser(ref objUserInfo);


                    if (usrCreateStatus != UserCreateStatus.Success)
                    {
                        //LOG ERROR
                    }
                }
                else
                {
                    //User already exists
                    if (objUserInfo.Membership.LockedOut)
                    {
                        UserController.UnLockUser(objUserInfo);
                    }
                    objUserInfo.Membership.Approved = true;

                }

                UserValidStatus validStatus = UserController.ValidateUser(objUserInfo, settings.PortalId, true);
                UserLoginStatus loginStatus = validStatus == UserValidStatus.VALID ? UserLoginStatus.LOGIN_SUCCESS : UserLoginStatus.LOGIN_FAILURE;
                if (loginStatus == UserLoginStatus.LOGIN_SUCCESS)
                {
                    //SetLoginDate(user.Username);
                    //Raise UserAuthenticated Event
                    var eventArgs = new UserAuthenticatedEventArgs(objUserInfo, objUserInfo.Email, loginStatus, "Oidc")
                    {
                        Authenticated = true,
                        Message = "User authorized",
                        RememberMe = false
                    };

                    UserController.UserLogin(settings.PortalId, objUserInfo, settings.PortalName, "Oidc", false);



                }
            }
        }

        public virtual TUserData GetCurrentUser<TUserData>() where TUserData : UserData
        {
            if (!IsCurrentUserAuthorized())
                return null;

            var responseText = ExecuteWebRequest(HttpMethod.Get, GenerateRequestUri(UserInfoEndpoint, TokenResponse.AccessToken), null, string.Empty);
            var user = JsonConvert.DeserializeObject<TUserData>(responseText);
            user.Id = GetUserId(TokenResponse?.IdentityToken);
            return user;
        }

        private string GetUserId(string identityToken)
        {
            var tokenHandler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
            if (!tokenHandler.CanReadToken(identityToken))
                return null;

            var token = tokenHandler.ReadJwtToken(identityToken);
            return $"{_service}_{token.Claims.FirstOrDefault(c => c.Type == "sub")?.Value}";
        }

        public bool HasVerificationCode()
        {
            return VerificationCode != null;
        }

        public bool IsCurrentService()
        {
            var service = HttpContext.Current.Request.Params["state"];
            return !string.IsNullOrEmpty(service) && service == _service;
        }

        public bool IsCurrentUserAuthorized()
        {
            return TokenResponse?.AccessToken != null;
        }

        private void SetLoginDate(string username)
        {
            StringBuilder mysqlstring = new StringBuilder();

            mysqlstring.Append("UPDATE {databaseOwner}aspnet_Membership SET LastLoginDate = @0 where UserId in (select UserId from {databaseOwner}aspnet_Users where UserName = @1)");

            using (DotNetNuke.Data.IDataContext db = DataContext.Instance())
            {
                db.Execute(System.Data.CommandType.Text, mysqlstring.ToString(), DateTime.Now.ToString(), username);
            }
        }

        public bool CreateCognitoUser(string email, string DNNUsername, string password)
        {
            return false;
        }
        public bool EmailExistsAsUsername (PortalSettings settings, string email)
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
