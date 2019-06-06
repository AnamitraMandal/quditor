namespace Test.SocialAuth.Authentication.Providers
{
    using System.Security.Claims;
    using Test.SocialAuth.Contracts.Models;

    public interface IGitHubService
    {
        User BuildUserFromClaims(ClaimsPrincipal claimsPrincipal);
    }
}
