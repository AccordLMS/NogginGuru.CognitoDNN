using DotNetNuke.Common.Utilities;
using Microsoft.ApplicationBlocks.Data;
using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NG.Cognito.WebApi
{
    internal class LiveFormsController
    {

        private readonly string _connectionString;


        internal LiveFormsController()
        {
            _connectionString = Config.GetConnectionString("SiteSqlServer");
        }


        internal bool CheckSubmissionGUID(string submissionGUID)
        {
            DotNetNuke.Services.Exceptions.Exceptions.LogException(new Exception("CheckSubmissionGUID start"));

            string sqlQuery = String.Empty;
            sqlQuery += "select 1";
            sqlQuery += "  from LiveForms_Submission";
            sqlQuery += " where UpdatedOn > DATEADD(MINUTE,-10,getdate()) and SubmissionGUID = '" + submissionGUID + "'";


            DotNetNuke.Services.Exceptions.Exceptions.LogException(new Exception("CheckSubmissionGUID: " + sqlQuery));


            bool result = Convert.ToBoolean(SqlHelper.ExecuteScalar(_connectionString, CommandType.Text, sqlQuery));

            DotNetNuke.Services.Exceptions.Exceptions.LogException(new Exception("CheckSubmissionGUID end"));

            return result;
        }
    }
}
