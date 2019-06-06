namespace Test.SocialAuth.Services
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using Test.SocialAuth.Authentication.Jwt.Services;
    using Test.SocialAuth.Authentication.PasswordUtility;
    using Test.SocialAuth.Contracts;
    using Test.SocialAuth.Contracts.Models;
    using Test.SocialAuth.Repositories;

    public class UserService : IUserService
    {
        private readonly IUserRepository userRepository;
        private readonly IRefreshTokenFactory refreshTokenFactory;
        private readonly ITokenService tokenService;
        private object console;

        public UserService(
            IUserRepository userRepository,
            IRefreshTokenFactory refreshTokenFactory,
            ITokenService tokenService)
        {
            this.userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            this.refreshTokenFactory = refreshTokenFactory ?? throw new ArgumentNullException(nameof(refreshTokenFactory));
            this.tokenService = tokenService ?? throw new ArgumentNullException(nameof(tokenService));
        }

        public bool LocalSignUp(RegisterUserRequest signupRequest)
        {
            try
            {
                // TODO: Check whether any user exists with the username/ email already
                User user = new User
                {
                    FirstName = signupRequest.FirstName,
                    LastName = signupRequest.LastName,
                    UserName = signupRequest.UserName,
                    Email = signupRequest.Email,
                    Country = signupRequest.Country,
                    Profession = signupRequest.Profession,
                    PasswordHash = SecurePasswordHasher.Hash(signupRequest.Password)
                };
                this.userRepository.Insert(user);
                this.userRepository.SaveChanges();
                return true;
            }
            catch
            {
                return false;
            }
        }

        public async Task<LoginResponse> LocalLogin(LoginRequest loginRequest, string remoteIpAddress)
        {
            if (!string.IsNullOrEmpty(loginRequest.UserName) && !string.IsNullOrEmpty(loginRequest.Password))
            {
                // TODO: Validate that the user always enter a unique username
                // Get the user by the username
                var user = this.userRepository
                    .GetFirstOrDefault(x => x.UserName == loginRequest.UserName);

                if (user != null)
                {
                    // Validate the user's password
                    if (SecurePasswordHasher.Verify(loginRequest.Password, user.PasswordHash))
                    {
                        // Generate the refresh token for the user
                        var refreshToken = this.refreshTokenFactory.GenerateRefreshToken();
                        user.AddRefreshToken(refreshToken, user.Id, remoteIpAddress);
                        this.userRepository.Update(user);
                        this.userRepository.SaveChanges();

                        // Generate access token
                        var accessToken = await this.tokenService.GenerateEncodedToken(user.Id, user.UserName);
                        return new LoginResponse
                        {
                            AccessToken = accessToken,
                            RefreshToken = refreshToken
                        };
                    }
                }
            }
            return new LoginResponse
            {
                Errors = new[] { new Error { Code = "login_failure", Description = "Invalid username or password." } }
            };
        }

        public async Task<LoginResponse> ExternalLogin(User user, string remoteIpAddress)
        {
            // Check whether the user already exists with such external name identifier
            var userDb = this.userRepository
                .GetFirstOrDefault(predicate: x => x.IdentityId == user.IdentityId);
            if (userDb != null)
            {
                // Generate the refresh token for the user
                var refreshToken = this.refreshTokenFactory.GenerateRefreshToken();
                userDb.AddRefreshToken(refreshToken, userDb.Id, remoteIpAddress);
                this.userRepository.Update(userDb);
                this.userRepository.SaveChanges();

                var accessToken = await this.tokenService.GenerateEncodedToken(userDb.Id, userDb.UserName);

                return new LoginResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                };
            }
            else
            {
                // Register the user
                this.userRepository.Insert(user);
                this.userRepository.SaveChanges();

                // Generate the refresh token for the user
                var refreshToken = this.refreshTokenFactory.GenerateRefreshToken();
                user.AddRefreshToken(refreshToken, user.Id, remoteIpAddress);
                this.userRepository.Update(user);
                this.userRepository.SaveChanges();

                var accessToken = await this.tokenService.GenerateEncodedToken(user.Id, user.UserName);

                return new LoginResponse
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    //Console.WriteLine("dfgd");
                };
            }
        }

        public async Task<ExchangeRefreshTokenResponse> RefreshToken(ExchangeRefreshTokenRequest tokenRequest, string secretKey)
        {
            // Get the principal from the token
            var claimsPrincipal = this.tokenService.GetPrincipalFromToken(tokenRequest.AccessToken, secretKey);

            // Check whether the principal were extracted
            if (claimsPrincipal != null)
            {
                // Get the Identifier from the Claims Principal
                var id = claimsPrincipal.Claims.First(c => c.Type == "id");
                var user = this.userRepository.GetFirstOrDefault(
                    predicate: x => x.Id == int.Parse(id.Value));

                if (user != null)
                {
                    if (user.HasValidRefreshToken(tokenRequest.RefreshToken))
                    {
                        var jwtAccessToken = await this.tokenService.GenerateEncodedToken(user.Id, user.UserName);
                        var refreshToken = this.refreshTokenFactory.GenerateRefreshToken();
                        user.RemoveRefreshToken(tokenRequest.RefreshToken);
                        user.AddRefreshToken(refreshToken, user.Id, "");
                        this.userRepository.Update(user);
                        this.userRepository.SaveChanges();
                        return new ExchangeRefreshTokenResponse
                        {
                            AccessToken = jwtAccessToken,
                            RefreshToken = refreshToken
                        };
                    }
                }
            }
            return null;
        }
    }
}
