# ProcsIT.Dnn.OpenIdConnect
OpenIdConnect provider and plugin for DNN (DotNetNuke).

I've written an OpenIdConnect provider because I needed one and no public providers were available. I am not a member of the DNN community and I have no further knowledge of DNN.
Originally started as POC, the project now moved to implementation.

The code was adapted from an old version of OpenId that I found in the archives of codeplex.
Based on oidc specifications and other documentation I've now implemented the hybrid flow. Please consult the specifications to see how the hybrid flow works.

The software contains of three parts:

1. provider: handles the oidc requests
2. plugin: compiled code that contains settings and interacts with the provider
3. web UI: very basic login form and settings form

Update the settings in the plugin:

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

There is no package available to install this component. So in order to make this work, copy the provider dll and plugin dll to the \Website\bin folder. Copy the web UI to \Website\DesktopModules\AuthenticationServices\oidc.

Configure DNN to add oidc authentication. When succeeded an extra tab will be visible with a link to the IDP. After clicking on the link the user is redirected to the IDP, logs in and is redirected back to DNN. At that point the admin will receive a message that a new user needs to be approved.

Once approved, the user has access like a local user. It is quite possible that there can be some improvements. Like a direct link instead of a tab and automatically approve new users.

