namespace Test.SocialAuth.Authentication.Jwt.Services
{
    public interface IRefreshTokenFactory
    {
        string GenerateRefreshToken(int size = 32);
    }
}
