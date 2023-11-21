using DotNetNuke.Web.Api;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Http;
using DotNetNuke.Entities.Users;
using NG.Cognito.AWS;
using DNN.OpenId.Cognito;
using DotNetNuke.Entities.Portals;
using System.Collections.Specialized;
using System.Web;

namespace NG.Cognito.WebApi
{
    public class NGUserController : DnnApiController
    {
        public NGUserController() { }

        /// <summary>
        /// url http://localhost/test/desktopmodules/AuthenticationServices/oidc/api/NGUser/SendUserToCognitoDto
        /// </summary>
        /// <param name="portalId"></param>
        /// <param name="userId"></param>
        /// <returns></returns>
        [AllowAnonymous]
        [HttpPost]
        public HttpResponseMessage SendUserToCognito()
        {
            try
            {
                string strData = Request.Content.ReadAsStringAsync().Result;

                NameValueCollection data = HttpUtility.ParseQueryString(strData);

                //get data from form post
                int portalId = int.Parse(data["PortalId"]);
                int userId = int.Parse(data["UserId"]);
                string password = data["Password"];
                string submissionGUID = data["SubmissionGUID"];

                LiveFormsController liveFormsController = new LiveFormsController();

                // 1- check API token in the header
                if (liveFormsController.CheckSubmissionGUID(submissionGUID))
                {

                    // 2- get user from dnn
                    UserInfo dnnUser = UserController.GetUserById(portalId, userId);


                    // 3- send user to cognito
                    PortalSettings portalSettings = new PortalSettings(portalId);
                    DNNOpenIDCognitoConfig config = new DNNOpenIDCognitoConfig(portalId);
                    AWSUserController cognitoController = new AWSUserController(config);

                    cognitoController.CreateCognitoUser(dnnUser.Email, dnnUser.Username, password, portalSettings);


                    return Request.CreateResponse(HttpStatusCode.OK);
                }
                else
                {
                    return Request.CreateResponse(HttpStatusCode.InternalServerError, "Incorrrect token");
                }
            }
            catch (Exception ex)
            {
                return Request.CreateResponse(HttpStatusCode.InternalServerError, ex.Message);
            }
        }
    }
}
