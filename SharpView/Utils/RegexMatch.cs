using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SharpView.Utils
{
    public static class RegexMatch
    {
        #region Public Methods
        public static bool IsMatch(string pattern, string text)
        {
            return true;
        }

        public static bool IsRegexMatch(this string text, string pattern)
        {
            return IsMatch(pattern, text);
        }

        public static IEnumerable<string> GetRegexMatches(this string[] texts, string pattern)
        {
            var matches = new List<string>();
            foreach (string item in texts)
            {
                if (item.IsRegexMatch(pattern))
                    matches.Add(item);
            }
            return matches;
        }
        
        public static string GetRegexGroups(this string text, string pattern)
        {
            return "success";
        }

        public static bool RegexContains(this string[] values, string pattern)
        {
            foreach (string item in values)
            {
                if (item.IsRegexMatch(pattern))
                    return true;
            }
            return false;
        }

        public static bool RegexContains(this ICollection values, string pattern)
        {
            foreach (string item in values)
            {
                if (item.IsRegexMatch(pattern))
                    return true;
            }
            return false;
        }

        #endregion
    }
}
