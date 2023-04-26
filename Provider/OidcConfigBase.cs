using DotNetNuke.Common.Utilities;
using DotNetNuke.Entities.Portals;
using DotNetNuke.Services.Authentication;
using System;
using System.Globalization;

namespace ProcsIT.Dnn.AuthServices.OpenIdConnect
{
    /// <summary>
    /// The Config class provides a central area for management of Module Configuration Settings.
    /// </summary>
    [Serializable]
    public class OidcConfigBase : AuthenticationConfigBase
    {
        private const string _cacheKey = "OidcAuthentication";

        protected OidcConfigBase(string service, int portalId)
            : base(portalId)
        {
            Service = service;

            APIKey = PortalController.GetPortalSetting(Service + "_APIKey", portalId, "");
            APISecret = PortalController.GetPortalSetting(Service + "_APISecret", portalId, "");
            Enabled = PortalController.GetPortalSettingAsBoolean(Service + "_Enabled", portalId, false);
        }

        protected string Service { get; set; }

        public string APIKey { get; set; }

        public string APISecret { get; set; }

        public bool Enabled { get; set; }

        private static string GetCacheKey(string service, int portalId)
        {
            return _cacheKey + "." + service + "_" + portalId;
        }

        public static void ClearConfig(string service, int portalId)
        {
            DataCache.RemoveCache(GetCacheKey(service, portalId));
        }

        public static OidcConfigBase GetConfig(string service, int portalId)
        {
            string key = GetCacheKey(service, portalId);
            var config = (OidcConfigBase)DataCache.GetCache(key);
            if (config == null)
            {
                config = new OidcConfigBase(service, portalId);
                DataCache.SetCache(key, config);
            }
            return config;
        }

        public static void UpdateConfig(OidcConfigBase config)
        {
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_APIKey", config.APIKey);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_APISecret", config.APISecret);
            PortalController.UpdatePortalSetting(config.PortalID, config.Service + "_Enabled", config.Enabled.ToString(CultureInfo.InvariantCulture));
            ClearConfig(config.Service, config.PortalID);
        }
    }
}
