namespace Test.SocialAuth.Services
{
    using System.Threading.Tasks;
    using Test.SocialAuth.Contracts;
    using Test.SocialAuth.Contracts.Models;

    public interface IUserService
    {
        Task<LoginResponse> LocalLogin(LoginRequest loginRequest, string remoteIpAddress);
        Task<ExchangeRefreshTokenResponse> RefreshToken(ExchangeRefreshTokenRequest tokenRequest, string secretKey);
        bool LocalSignUp(RegisterUserRequest signupRequest);
        Task<LoginResponse> ExternalLogin(User user, string remoteIpAddress);
    }
}
