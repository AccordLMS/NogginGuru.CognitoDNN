using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Authentication.Oidc;
using System;
using System.Collections.Specialized;

namespace ProcsIT.Dnn.AuthServices.OpenIdConnect
{
    public abstract class OidcLoginBase : AuthenticationLoginBase
    {
        protected virtual string AuthSystemApplicationName => "Oidc";

        public override bool Enabled => true;// OidcConfigBase.GetConfig(AuthSystemApplicationName, PortalId).Enabled;

        protected OidcClientBase OAuthClient { get; set; }

        protected abstract UserData GetCurrentUser();

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            var shouldAuthorize = OAuthClient.IsCurrentService() && OAuthClient.HasVerificationCode();
            if (Mode == AuthMode.Login)
                shouldAuthorize = shouldAuthorize || OAuthClient.IsCurrentUserAuthorized();

            if (shouldAuthorize && OAuthClient.Authorize(PortalSettings, IPAddress) == AuthorisationResult.Authorized)
                OAuthClient.AuthenticateUser(GetCurrentUser(), PortalSettings, IPAddress, AddCustomProperties, OnUserAuthenticated);
        }

        protected virtual void AddCustomProperties(NameValueCollection properties)
        {
        }

    }
}