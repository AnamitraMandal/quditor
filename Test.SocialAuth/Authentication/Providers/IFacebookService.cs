namespace Test.SocialAuth.Authentication.Providers
{
    using System.Security.Claims;
    using Test.SocialAuth.Contracts.Models;

    public interface IFacebookService
    {
        User BuildUserFromClaims(ClaimsPrincipal claimsPrincipal);
    }
}