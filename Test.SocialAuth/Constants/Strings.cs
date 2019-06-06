using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Test.SocialAuth.Constants
{
    public static class Strings
    {
        public static string RemoveAllNonPrintableCharacters(string target)
        {
            return Regex.Replace(target, @"\p{C}+", string.Empty);
        }
    }
}
