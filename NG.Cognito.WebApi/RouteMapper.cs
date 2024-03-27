using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using DotNetNuke.Web.Api;

namespace NG.Cognito.WebApi
{
    public class RouteMapper : IServiceRouteMapper
    {

        //public static void Register(HttpConfiguration config)
        //{

        //    config.Routes.MapHttpRoute("AuthenticationServices/oidc", "Cognito", "{controller}/{userId}", new[] { "NG.Cognito.WebApi" });
        //    //config.MessageHandlers.Add(new TokenValidationHandler());
                       

        //}

        public void RegisterRoutes(IMapRoute mapRouteManager)
        {
          
            //general API (servicesController)
            mapRouteManager.MapHttpRoute("AuthenticationServices/oidc", "Cognito", "{controller}/{action}", new[] { "NG.Cognito.WebApi" });


        }
    }
}
