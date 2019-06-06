using Microsoft.AspNetCore.Authentication;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Test.SocialAuth.Authentication.Providers
{
    public class AuthProviderService : IAuthProviderService
    {
        private readonly IAuthenticationSchemeProvider authenticationSchemeProvider;

        public AuthProviderService(IAuthenticationSchemeProvider authenticationSchemeProvider)
        {
            this.authenticationSchemeProvider = authenticationSchemeProvider 
                ?? throw new ArgumentNullException(nameof(authenticationSchemeProvider));
        }

        public async Task<IEnumerable<AuthenticationScheme>> GetAllAuthenticationSchemes()
        {
            return await this.authenticationSchemeProvider.GetRequestHandlerSchemesAsync();
        }
    }
}
