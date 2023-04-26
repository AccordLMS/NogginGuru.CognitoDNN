using DotNetNuke.Services.Authentication;
using ProcsIT.Dnn.AuthServices.OpenIdConnect;
using System;
using System.Web;

namespace ProcsIT.Dnn.Authentication.OpenIdConnect.Components
{
    public class OidcClient : OidcClientBase
    {
        protected override TimeSpan GetExpiry(int expirseIn) => new TimeSpan(0, 0, expirseIn);

        protected override string GetToken(string accessToken) => accessToken;

        public OidcClient(int portalId, AuthMode mode)
          : base(portalId, mode, "Oidc")
        {
            AuthorizationEndpoint = "https://noggigurutest1.auth.us-east-1.amazoncognito.com/oauth2/authorize";
            TokenEndpoint = "https://noggigurutest1.auth.us-east-1.amazoncognito.com/oauth2/token";
            UserInfoEndpoint = "https://noggigurutest1.auth.us-east-1.amazoncognito.com/oauth2/userInfo";

            //Scope = HttpUtility.UrlEncode("openid profile offline_access api1");
            Scope = HttpUtility.UrlEncode("openid profile");//from Javier
        }
    }
}
