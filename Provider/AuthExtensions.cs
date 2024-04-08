//using ProcsIT.Dnn.AuthServices.OpenIdConnect;
//using System.Collections.Generic;
//using System.Text;

//namespace DotNetNuke.Services.Authentication.Oidc
//{
//    internal static class AuthExtensions
//    {
//        public static string ToNormalizedString(this IList<QueryParameter> parameters)
//        {
//            var sb = new StringBuilder();
//            for (int i = 0; i < parameters.Count; i++)
//            {
//                QueryParameter p = parameters[i];
//                sb.AppendFormat("{0}={1}", p.Name, p.Value);

//                if (i < parameters.Count - 1)
//                {
//                    sb.Append("&");
//                }
//            }

//            return sb.ToString();
//        }
//    }
//}