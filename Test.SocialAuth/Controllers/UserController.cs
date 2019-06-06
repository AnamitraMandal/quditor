namespace Test.SocialAuth.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Newtonsoft.Json;
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Threading.Tasks;
    using Test.SocialAuth.Contracts.Models;
    using Test.SocialAuth.Repositories;

    [Authorize]
    [Produces("application/json")]
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private ClaimsPrincipal _caller;
        private readonly IUserRepository userRepository;

        public UserController(
            IHttpContextAccessor httpContextAccessor,
            IUserRepository userRepository)
        {
            _caller = httpContextAccessor?.HttpContext?.User;
            this.userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
        }

        [HttpGet]
        [Route("get")]
        public string GetUser()
        {
            var userId = _caller?.Claims.Single(c => c.Type == "id");

            var stringId = _caller?.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            int.TryParse(stringId ?? "0", out int JtiId);

            return JsonConvert.SerializeObject(new
            {
                id = userId.Value,
                jtiId = JtiId,
                ip = Request.HttpContext.Connection.RemoteIpAddress?.ToString()
            });
        }
    }
}
