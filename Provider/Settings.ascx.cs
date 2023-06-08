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
        private const string usrPREFIX = "usr" + "_";

        public override void UpdateSettings()
        {
            try
            {

                var config = DNNOpenIDCognitoConfig.GetConfig(PortalId);
                config.PortalID = PortalId;
                config.ApiKey = txtApiKey.Text;
                config.ApiSecret = txtApiSecret.Text;
                config.Enabled = chkEnabled.Checked;
                config.RedirectURL = txtRedirectURL.Text;

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
                chkEnabled.Checked = config.Enabled;
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
        private const string usrPREFIX = "usr_";
        protected DNNOpenIDCognitoConfig(int portalID) : base(portalID)
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
        }

        public bool Enabled { get; set; }
        public string ApiKey { get; set; }
        public string ApiSecret { get; set; }
        public string RedirectURL { get; set; }



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

        }

    }
}

