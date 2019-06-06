namespace Test.SocialAuth.Authentication.Claims
{
    using System.Security.Claims;

    public interface IClaimService
    {
        ClaimsIdentity GenerateClaimsIdentity(int id, string userName);
    }
}
