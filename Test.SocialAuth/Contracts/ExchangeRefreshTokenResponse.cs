using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Test.SocialAuth.Contracts
{
    public class ExchangeRefreshTokenResponse
    {
        public AccessToken AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
