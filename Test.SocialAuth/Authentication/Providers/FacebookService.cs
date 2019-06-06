namespace Test.SocialAuth.Authentication.Providers
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Test.SocialAuth.Contracts.Models;

    public class FacebookService : IFacebookService
    {
        private readonly string nameidentifier = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";
        private readonly string emailaddress = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";
        private readonly string name = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
        private readonly string givenname = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
        private readonly string surname = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";
        private readonly string country = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country";
        private readonly string profession = "urn:facebook:profession";

        public User BuildUserFromClaims(ClaimsPrincipal claimsPrincipal)
        {
            return new User()
            {
                IdentityId = claimsPrincipal.FindFirstValue(nameidentifier),
                UserName = claimsPrincipal.FindFirstValue(name),
                Email = claimsPrincipal.FindFirstValue(emailaddress),
                FirstName = claimsPrincipal.FindFirstValue(givenname),
                LastName = claimsPrincipal.FindFirstValue(surname),
                Country = claimsPrincipal.FindFirstValue(country),
                Provider = Provider.Facebook,
                Profession = claimsPrincipal.FindFirstValue(profession)
            };
        }
    }
}
