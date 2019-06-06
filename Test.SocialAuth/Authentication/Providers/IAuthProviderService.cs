using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Test.SocialAuth.Authentication.Providers
{
    public interface IAuthProviderService
    {
        Task<IEnumerable<AuthenticationScheme>> GetAllAuthenticationSchemes();
    }
}
