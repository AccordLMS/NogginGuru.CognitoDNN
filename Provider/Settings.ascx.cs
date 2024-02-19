#region Usings

using System;

using DotNetNuke.Services.Authentication;
using DotNetNuke.Services.Exceptions;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Profile;
using System.Data;
using System.Collections.Generic;
using System.Web.UI.WebControls;

#endregion

namespace DNN.OpenId.Cognito
{
    public partial class Settings : AuthenticationSettingsBase
    {
        public override void UpdateSettings()
        {
            try
            {

                var config = DNNOpenIDCognitoConfig.GetConfig(PortalId);
                config.PortalID = PortalId;
                config.ApiKey = txtApiKey.Text;
                config.ApiSecret = txtApiSecret.Text;
                config.Enabled = chkEnabled.Checked;
                config.IAMUserAccessKey = txtIAMUserAccessKey.Text;
                config.IAMUserSecretKey = txtIAMUserSecretKey.Text;
                config.AppUsername = txtAppUsername.Text;
                config.CognitoPoolID = txtCognitoPoolID.Text;
                config.RedirectURL = txtRedirectURL.Text;
                config.LoginUrl = txtLoginURL.Text;
                config.LoginMessage = txtLoginMessage.Text;
                config.UseHostedUI = chkHostedUI.Checked;
                config.CognitoDomain = txtCognitoDomain.Text;

                DNNOpenIDCognitoConfig.UpdateConfig(config);

            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);

            try
            {
                var config = DNNOpenIDCognitoConfig.GetConfig(PortalId);
                txtApiKey.Text = config.ApiKey;
                txtApiSecret.Text = config.ApiSecret;
                txtRedirectURL.Text = config.RedirectURL;
                txtLoginURL.Text = config.LoginUrl;
                chkEnabled.Checked = config.Enabled;
                txtIAMUserAccessKey.Text = config.IAMUserAccessKey;
                txtIAMUserSecretKey.Text = config.IAMUserSecretKey;
                txtAppUsername.Text = config.AppUsername;
                txtCognitoPoolID.Text = config.CognitoPoolID;
                txtLoginMessage.Text = config.LoginMessage;
                txtCognitoDomain.Text = config.CognitoDomain;
            }
            catch (Exception exc)
            {
                Exceptions.ProcessModuleLoadException(this, exc);
            }
        }
    }


    [Serializable]
    public class DNNOpenIDCognitoConfig : AuthenticationConfigBase
    {
        private const string PREFIX = "DNN.OpenID.Cognito_";

        public DNNOpenIDCognitoConfig(int portalID) : base(portalID)
        {
            this.PortalID = portalID;
            Enabled = true;
            string setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "Enabled", out setting))
                Enabled = bool.Parse(setting);

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "ApiKey", out setting))
                ApiKey = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "ApiSecret", out setting))
                ApiSecret = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "RedirectURL", out setting))
                RedirectURL = setting;
            
            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "LoginUrl", out setting))
                LoginUrl = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "IAMUserAccessKey", out setting))
                IAMUserAccessKey = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "IAMUserSecretKey", out setting))
                IAMUserSecretKey = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "AppUsername", out setting))
                AppUsername = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "CognitoPoolID", out setting))
                CognitoPoolID = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "UseHostedUI", out setting))
                UseHostedUI = bool.Parse(setting);

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "CognitoDomain", out setting))
                CognitoDomain = setting;

            setting = Null.NullString;
            if (PortalController.Instance.GetPortalSettings(portalID).TryGetValue(PREFIX + "LoginMessage", out setting))
            {
                if (setting == Null.NullString)
                    LoginMessage = "Your username will soon be migrated to the email address associated with your account. Please enter your email address and password";
                else
                    LoginMessage = setting;
            }
            else { LoginMessage = "Your username will soon be migrated to the email address associated with your account. Please enter your email address and password"; }
        }

        public bool Enabled { get; set; }
        public string ApiKey { get; set; }
        public string ApiSecret { get; set; }
        public string RedirectURL { get; set; }
        public string LoginUrl { get; set; }
        public string IAMUserAccessKey { get; set; }
        public string IAMUserSecretKey { get; set; }
        public string AppUsername { get; set; }
        public string CognitoPoolID { get; set; }
        public bool UseHostedUI { get; set; }
        public string LoginMessage { get; set; }
        public string CognitoDomain { get; set; }



        public static DNNOpenIDCognitoConfig GetConfig(int portalId)
        {
            var config = new DNNOpenIDCognitoConfig(portalId);
            return config;
        }

        public static void UpdateConfig(DNNOpenIDCognitoConfig config)
        {
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "Enabled", config.Enabled.ToString());
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "ApiKey", config.ApiKey);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "ApiSecret", config.ApiSecret);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "RedirectURL", config.RedirectURL);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "LoginUrl", config.LoginUrl);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IAMUserAccessKey", config.IAMUserAccessKey);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "IAMUserSecretKey", config.IAMUserSecretKey);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "AppUsername", config.AppUsername);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "CognitoPoolID", config.CognitoPoolID);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "UseHostedUI", config.UseHostedUI.ToString());
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "LoginMessage", config.LoginMessage);
            PortalController.UpdatePortalSetting(config.PortalID, PREFIX + "CognitoDomain", config.CognitoDomain);

        }

    }
}

