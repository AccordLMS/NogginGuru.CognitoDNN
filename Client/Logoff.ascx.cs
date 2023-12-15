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
using System.ComponentModel;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Services.Authentication.OAuth;
using ProcsIT.Dnn.Authentication.OpenIdConnect;
using QueryParameter = ProcsIT.Dnn.AuthServices.OpenIdConnect.QueryParameter;
using DotNetNuke.Security;
using DotNetNuke.Common;
using DotNetNuke.Entities.Tabs;



#endregion

namespace DNN.OpenId.Cognito
{
    public partial class Logoff: AuthenticationLogoffBase
    {
        private DNNOpenIDCognitoConfig _config;

        private string _logOffEndpoint;

        protected string AuthSystemApplicationName => "Oidc";

        protected override void OnInit(EventArgs e)
        {
            _config = DNNOpenIDCognitoConfig.GetConfig(PortalId);
            _logOffEndpoint = _config.CognitoDomain + "/logout";
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            LogOutDNN();

            LogOutCognito();            
           
        }

        private void LogOutDNN()
        {
            var curPortal = PortalController.GetCurrentPortalSettings();

            //Remove user from cache
            DataCache.ClearUserCache(curPortal.PortalId, UserController.GetCurrentUserInfo().Username);

            //sign out any logged on user
            var objPortalSecurity = new PortalSecurity();
            objPortalSecurity.SignOut();
        }

        private void LogOutCognito()
        {
            string homeUrl;
            if (this.PortalSettings.HomeTabId > -1)
            {
                homeUrl = Globals.NavigateURL(this.PortalSettings.HomeTabId);
            }
            else
            {
                homeUrl = _config.LoginUrl;
            }
            // hybrid flow
            var parameters = new List<QueryParameter>
                                        {
                                            new QueryParameter { Name = OAuthConsts.ResponseTypeKey, Value = OAuthConsts.CodeKey },
                                            new QueryParameter { Name = OAuthConsts.ClientIdKey, Value = _config.ApiKey },
                                            //new QueryParameter { Name = OAuthConsts.RedirectUriKey, Value = homeUrl }, //return to home
                                            new QueryParameter { Name = "logout_uri", Value = homeUrl }, //return to home
                                            new QueryParameter { Name = "scope", Value = "openid profile" },
                                            new QueryParameter { Name = "state", Value = AuthSystemApplicationName }
                                        };

            // Call authorization endpoint
            HttpContext.Current.Response.Redirect(_logOffEndpoint + "?" + parameters.ToNormalizedString(), true);
        }

    }
}

