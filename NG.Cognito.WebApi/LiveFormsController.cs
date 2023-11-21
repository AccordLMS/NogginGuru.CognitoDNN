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
            string sqlQuery = String.Empty;
            sqlQuery += "select 1";
            sqlQuery += "  from LiveForms_Submission";
            sqlQuery += " where UpdatedOn > DATEADD(MINUTE,-10,getdate()) and SubmissionGUID = '" + submissionGUID + "'";

            bool result = Convert.ToBoolean(SqlHelper.ExecuteScalar(_connectionString, CommandType.Text, sqlQuery));


            return result;
        }
    }
}
