using DotNetNuke.Services.Authentication.OAuth;

namespace ProcsIT.Dnn.Authentication.OpenIdConnect
{
  public class Settings : OAuthSettingsBase
  {
    protected override string AuthSystemApplicationName
    {
      get
      {
        return "Oidc";
      }
    }
  }
}
