namespace Test.SocialAuth.Controllers
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Options;
    using Newtonsoft.Json;
    using Test.SocialAuth.Authentication.Providers;
    using Test.SocialAuth.Authentication.Settings;
    using Test.SocialAuth.Contracts;
    using Test.SocialAuth.Services;

    [AllowAnonymous]
    [Route("[controller]")]
    public class AuthController : Controller
    {
        private readonly ClaimsPrincipal _caller;
        private readonly IAuthProviderService authProviderService;
        private readonly IUserService userService;
        private readonly IFacebookService facebookService;
        private readonly IGitHubService gitHubService;
        private readonly IGoogleService googleService;
        private readonly AuthSettings _authSettings;

        public AuthController(
            IHttpContextAccessor httpContextAccessor,
            IAuthProviderService authProviderService,
            IUserService userService,
            IFacebookService facebookService,
            IGitHubService gitHubService,
            IGoogleService googleService,
            IOptions<AuthSettings> authSettings)
        {
            _caller = httpContextAccessor?.HttpContext?.User;
            this.authProviderService = authProviderService ?? throw new ArgumentNullException(nameof(authProviderService));
            this.userService = userService ?? throw new ArgumentNullException(nameof(userService));
            this.facebookService = facebookService ?? throw new ArgumentNullException(nameof(facebookService));
            this.gitHubService = gitHubService ?? throw new ArgumentNullException(nameof(gitHubService));
            this.googleService = googleService ?? throw new ArgumentNullException(nameof(googleService));
            _authSettings = authSettings.Value;
        }

        [HttpGet]
        [Route("providers")]
        public async Task<IActionResult> GetProviders()
        {
            var result = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (result.Succeeded)
            {
                return Ok("Already Signed In");
            }

            return Ok(this.authProviderService.GetAllAuthenticationSchemes());
        }

        [HttpPost]
        [Route("signup")]
        public bool LocalSignUp([FromBody] RegisterUserRequest signupRequest)
            => this.userService.LocalSignUp(signupRequest);

        [HttpPost]
        [Route("signin")]
        public async Task<LoginResponse> LocalLogin([FromBody]LoginRequest loginRequest)
            => await this.userService.LocalLogin(loginRequest, Request.HttpContext.Connection.RemoteIpAddress?.ToString());

        [HttpPost]
        [Route("refreshtoken")]
        public async Task<ExchangeRefreshTokenResponse> RefreshToken([FromBody] ExchangeRefreshTokenRequest tokenRequest)
            => await this.userService.RefreshToken(tokenRequest, _authSettings.SecretKey);

        //[HttpGet]
        [Route("signin/facebook")]
        [HttpGet]
        public IActionResult FacebookSignIn(string returnUrl = null)
        {
            var profileUrl = !string.IsNullOrWhiteSpace(returnUrl) ?
                $"{Url.Action("LoginFacebookCallback")}?returnUrl={returnUrl}" :
                Url.Action("LoginFacebookCallback");
            //Console.WriteLine("dfgd");
            return Challenge(new AuthenticationProperties { RedirectUri = "https://stackoverflow.com/questions/39356807/returnurl-not-working-and-is-always-null"}, "Facebook");
            
        }

        [HttpGet]
        [Route("signin/github")]
        public IActionResult GitHubSignIn(string returnUrl = null)
        {
            var profileUrl = !string.IsNullOrWhiteSpace(returnUrl) ?
                $"{Url.Action("LoginGitHubCallback")}?returnUrl={returnUrl}" :
                Url.Action("LoginGitHubCallback");

            return Challenge(new AuthenticationProperties { RedirectUri = profileUrl }, "GitHub");
        }

        [HttpGet]
        [Route("signin/google")]
        public IActionResult GoogleSignIn(string returnUrl = null)
        {
            var profileUrl = !string.IsNullOrWhiteSpace(returnUrl) ?
                $"{Url.Action("LoginGoogleCallback")}?returnUrl={returnUrl}" :
                Url.Action("LoginGoogleCallback");

            return Challenge(new AuthenticationProperties { RedirectUri = profileUrl }, "Google");
        }

        [HttpGet]
        [Route("signin/facebook/callback")]
        public async Task<LoginResponse> LoginFacebookCallback()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            
            if (authenticateResult.Succeeded)
            {
                var user = this.facebookService.BuildUserFromClaims(authenticateResult.Principal);
                return await this.userService.ExternalLogin(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString());
            }

            return new LoginResponse() {
                Errors = new Error[] {
                    new Error(){
                        Description = "Invalid Login"
                    }
                }
            };
        }

        [HttpGet]
        [Route("signin/google/callback")]
        public async Task<LoginResponse> GoogleFacebookCallback()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (authenticateResult.Succeeded)
            {
                var user = this.googleService.BuildUserFromClaims(authenticateResult.Principal);
                return await this.userService.ExternalLogin(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString());
            }

            return new LoginResponse()
            {
                Errors = new Error[] {
                    new Error(){
                        Description = "Invalid Login"
                    }
                }
            };
        }

        [HttpGet]
        [Route("signin/github/callback")]
        public async Task<LoginResponse> LoginGitHubCallback()
        {
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            if (authenticateResult.Succeeded)
            {
                var user = this.gitHubService.BuildUserFromClaims(authenticateResult.Principal);
                return await this.userService.ExternalLogin(user, Request.HttpContext.Connection.RemoteIpAddress?.ToString());
            }

            return new LoginResponse()
            {
                Errors = new Error[] {
                    new Error(){
                        Description = "Invalid Login"
                    }
                }
            };
        }

        [HttpGet]
        [Route("status")]
        public async Task<AuthenticateResult> AuthStatus()
        {
            var ipAddress = Request.HttpContext.Connection.RemoteIpAddress?.ToString();
            return await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        }
    }
}
