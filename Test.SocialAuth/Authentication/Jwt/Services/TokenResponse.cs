using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Test.SocialAuth.Authentication.Jwt.Services
{
    public class TokenResponse
    {
        public static async Task<string> GenerateJwt(
            int id,
            string userName,
            ITokenService tokenService,
            JsonSerializerSettings serializerSettings)
        {
            var response = new
            {
                auth_token = await tokenService.GenerateEncodedToken(id, userName),
            };

            return JsonConvert.SerializeObject(response, serializerSettings);
        }
    }
}
