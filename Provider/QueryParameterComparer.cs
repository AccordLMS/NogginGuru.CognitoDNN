using System;
using System.Collections.Generic;

namespace ProcsIT.Dnn.AuthServices.OpenIdConnect
{
    /// <summary>
    /// Comparer class used to perform the sorting of the query parameters
    /// </summary>
    internal class QueryParameterComparer : IComparer<QueryParameter>
    {
        public int Compare(QueryParameter x, QueryParameter y)
        {
            if (x.Name == y.Name)
            {
                return String.CompareOrdinal(x.Value, y.Value);
            }
            return String.CompareOrdinal(x.Name, y.Name);
        }

    }
}