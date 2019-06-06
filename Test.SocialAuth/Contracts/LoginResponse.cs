namespace Test.SocialAuth.Contracts
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class LoginResponse
    {
        public AccessToken AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public IEnumerable<Error> Errors { get; set; }

        public IEnumerable<string> Set()
        {
            return new string[] { "Hello" };
        }
    }
}
