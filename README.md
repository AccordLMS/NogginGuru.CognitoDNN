ProcsIT.Dnn.OpenIdConnect
OpenIdConnect provider and plugin for DNN (DotNetNuke).

I've written an OpenIdConnect provider because I needed one and no public providers were available. I am not a member of the DNN community and I have no further knowledge of DNN. Originally started as POC, the project now moved to implementation.

The code was adapted from an old version of OpenId that I found in the archives of codeplex. Based on oidc specifications and other documentation I've now implemented the hybrid flow. Please consult the specifications to see how the hybrid flow works.

The software contains of three parts:

provider: handles the oidc requests
plugin: compiled code that contains settings and interacts with the provider
web UI: very basic login form and settings form
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

Version 2.0.1
This package configured for CACentral1 region since the userpool in cognito for tracfone is in canada region.

Version 3.0.0
This version contains package NogginGuru.CognitoDNN.03.00.00_Install which contains changes related to Reset Password and RoadTripNation.

Reset Password UI is configured to handle the case where User status is set to Force Change Password and all kind of exceptions that come with it and also handles the redirection to login page after user succesfully resets his password.

RoadTripNation: At the time of login refresh token is set in cookies so that it can be utilized at Cognito.Connector package, This change will allow the user to login directly to RoadTripNation after clicking the button.