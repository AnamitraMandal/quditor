namespace Test.SocialAuth.Authentication.Jwt.Services
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Test.SocialAuth.Contracts;

    public interface ITokenService
    {
        ClaimsPrincipal GetPrincipalFromToken(string token, string signingKey);

        Task<AccessToken> GenerateEncodedToken(int id, string userName);
    }
}
