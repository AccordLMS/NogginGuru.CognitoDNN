using DotNetNuke.Services.Authentication;
using ProcsIT.Dnn.Authentication.OpenIdConnect.Components;
using ProcsIT.Dnn.AuthServices.OpenIdConnect;
using System;
using System.Web.UI.HtmlControls;
using System.Web.UI.WebControls;

namespace ProcsIT.Dnn.Authentication.OpenIdConnect
{
    public class Login : OidcLoginBase
    {
        protected HtmlGenericControl loginItem;
        protected LinkButton loginButton;

        protected override string AuthSystemApplicationName => "Oidc";

        public override bool SupportsRegistration => false;

        protected override UserData GetCurrentUser() => OAuthClient.GetCurrentUser<OidcUserData>();

        protected override void OnInit(EventArgs e)
        {
            base.OnInit(e);
            loginButton.Click += new EventHandler(LoginButton_Click);
            OAuthClient = new OidcClient(PortalId, Mode);
            loginItem.Visible = Mode == AuthMode.Login;
        }

        private void LoginButton_Click(object sender, EventArgs e)
        {
            OAuthClient.Authorize();
        }
    }

}
