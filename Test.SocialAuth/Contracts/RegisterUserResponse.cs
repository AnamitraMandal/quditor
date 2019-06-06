namespace Test.SocialAuth.Contracts
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class RegisterUserResponse
    {
        public string Id { get; set; }
        public IEnumerable<string> Errors { get; set; }
    }
}
