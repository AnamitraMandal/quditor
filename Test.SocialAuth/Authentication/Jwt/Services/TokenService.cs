namespace Test.SocialAuth.Authentication.Jwt.Services
{
    using Microsoft.Extensions.Options;
    using Microsoft.IdentityModel.Tokens;
    using System;
    using System.IdentityModel.Tokens.Jwt;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using Test.SocialAuth.Authentication.Claims;
    using Test.SocialAuth.Contracts;

    public class TokenService : ITokenService
    {
        private JwtIssuerOptions jwtOptions;
        private IClaimService claimService;
        private readonly ITokenHandler tokenHandler;

        public TokenService(
            ITokenHandler tokenHandler,
            IOptions<JwtIssuerOptions> jwtOptions,
            IClaimService claimService)
        {
            ThrowIfInvalidOptions(jwtOptions.Value);
            this.jwtOptions = jwtOptions?.Value;
            this.claimService = claimService ?? throw new ArgumentNullException(nameof(claimService));
            this.tokenHandler = tokenHandler ?? throw new ArgumentNullException(nameof(tokenHandler));
        }

        public async Task<AccessToken> GenerateEncodedToken(int id, string userName)
        {
            var identity = this.claimService.GenerateClaimsIdentity(id, userName);

            var claims = new[]
            {
                 new Claim(JwtRegisteredClaimNames.Sub, userName),
                 new Claim(JwtRegisteredClaimNames.Jti, await jwtOptions.JtiGenerator()),
                 new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(jwtOptions.IssuedAt).ToString(), ClaimValueTypes.Integer64),
                 identity.FindFirst(Constants.Constants.Strings.JwtClaimIdentifiers.Rol),
                 identity.FindFirst(Constants.Constants.Strings.JwtClaimIdentifiers.Id)
             };

            // Create the JWT security token and encode it.
            var jwt = new JwtSecurityToken(
                issuer: jwtOptions.Issuer,
                audience: jwtOptions.Audience,
                claims: claims,
                notBefore: jwtOptions.NotBefore,
                expires: jwtOptions.Expiration,
                signingCredentials: jwtOptions.SigningCredentials);

            return new AccessToken
            {
                Token = tokenHandler.WriteToken(jwt),
                ExpiresIn = (int)jwtOptions.ValidFor.TotalSeconds
            };
        }

        public ClaimsPrincipal GetPrincipalFromToken(string token, string signingKey)
        {
            return this.tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateAudience = false, //you might want to validate the audience and issuer depending on your use case
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),
                ValidateLifetime = false //here we are saying that we don't care about the token's expiration date
            });
        }

        /// <returns>Date converted to seconds since Unix epoch (Jan 1, 1970, midnight UTC).</returns>
        private static long ToUnixEpochDate(DateTime date)
          => (long)Math.Round((date.ToUniversalTime() -
                               new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero))
                              .TotalSeconds);

        private static void ThrowIfInvalidOptions(JwtIssuerOptions options)
        {
            if (options == null) throw new ArgumentNullException(nameof(options));

            if (options.ValidFor <= TimeSpan.Zero)
            {
                throw new ArgumentException("Must be a non-zero TimeSpan.", nameof(JwtIssuerOptions.ValidFor));
            }

            if (options.SigningCredentials == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.SigningCredentials));
            }

            if (options.JtiGenerator == null)
            {
                throw new ArgumentNullException(nameof(JwtIssuerOptions.JtiGenerator));
            }
        }
    }
}
