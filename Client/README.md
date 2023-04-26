# ProcsIT.Dnn.Authentication.OpenIdConnect  
Authentication plugin for DNN.

Configure the endpoint(s) here.


    public class OidcClient : OidcClientBase
    {
        public OidcClient(int portalId, AuthMode mode)
          : base(portalId, mode, "Oidc")
        {
            TokenEndpoint = "https://localhost:5001/connect/token";
            AuthorizationEndpoint = "https://localhost:5001/connect/authorize";
            Scope = HttpUtility.UrlEncode("openid profile offline_access api1");
            UserInfoEndpoint = "https://localhost:5001/connect/userinfo";
        }
