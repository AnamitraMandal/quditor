namespace Test.SocialAuth.Authentication.Claims
{
    using System;
    using System.Security.Claims;
    using System.Security.Principal;
    using Test.SocialAuth.Constants;

    public class ClaimService : IClaimService
    {
        public ClaimsIdentity GenerateClaimsIdentity(int id, string userName)
        {
            if (string.IsNullOrWhiteSpace(userName))
            {
                throw new ArgumentNullException("INVALID");
            }

            var claimsIdentity = new ClaimsIdentity(new GenericIdentity(userName, "Token"), new[] {
                new Claim(Constants.Strings.JwtClaimIdentifiers.Id, id.ToString()),
                new Claim(Constants.Strings.JwtClaimIdentifiers.Rol, Constants.Strings.JwtClaims.ApiAccess)
            });

            return claimsIdentity;
        }
    }
}
