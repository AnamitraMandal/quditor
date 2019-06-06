namespace Test.SocialAuth
{
    using System;
    using System.IO;
    using System.Net;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Authentication.Cookies;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Diagnostics;
    using Microsoft.AspNetCore.Hosting;
    using Microsoft.AspNetCore.Http;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.DependencyInjection.Extensions;
    using Microsoft.IdentityModel.Tokens;
    using Test.SocialAuth.Authentication.Claims;
    using Test.SocialAuth.Authentication.Jwt;
    using Test.SocialAuth.Authentication.Jwt.Services;
    using Test.SocialAuth.Authentication.Providers;
    using Test.SocialAuth.Authentication.Settings;
    using Test.SocialAuth.DataAccess.Initializer;
    using Test.SocialAuth.Extensions;
    using Test.SocialAuth.Repositories;
    using Test.SocialAuth.Services;

    public class Startup
    {
        private readonly IConfiguration configuration;

        public Startup(IConfiguration configuration)
        {
            this.configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        public void ConfigureServices(IServiceCollection services)
        {
            this.InitializeServices(services);

            // Register the ConfigurationBuilder instance of AuthSettings
            var authSettings = this.configuration.GetSection(nameof(AuthSettings));
            services.Configure<AuthSettings>(authSettings);

            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(authSettings[nameof(AuthSettings.SecretKey)]));

            // jwt wire up
            // Get options from app settings
            var jwtAppSettingOptions = this.configuration.GetSection(nameof(JwtIssuerOptions));

            services.Configure<JwtIssuerOptions>(options =>
            {
                options.Issuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                options.Audience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)];
                options.SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
            });

            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)],

                ValidateAudience = true,
                ValidAudience = jwtAppSettingOptions[nameof(JwtIssuerOptions.Audience)],

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                RequireExpirationTime = false,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;    // Update to JwtBearerDefaults.AuthenticationScheme
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;    // For social logins
            })
                .AddJwtBearer(configureOptions =>
                {
                    configureOptions.ClaimsIssuer = jwtAppSettingOptions[nameof(JwtIssuerOptions.Issuer)];
                    configureOptions.TokenValidationParameters = tokenValidationParameters;
                    configureOptions.SaveToken = true;

                    configureOptions.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                            {
                                context.Response.Headers.Add("Token-Expired", "true");
                            }
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddFacebook(options =>
                {
                    options.AppId = "1892236677544878";
                    options.AppSecret = "b30a4fad8fbde14d4996ec9a7e1bb0ff";
                    //AuthenticationScheme = "Facebook"; or "ApplicationCookie";
                    //SignInScheme = "ApplicationCookie";
                })
                .AddGitHub(options =>
                 {
                      options.ClientId = "78b3d0ba5aa6e9c8008a";
                      options.ClientSecret = "e118247467f2cca31e8bf0bae6c05d55cb3d6871";
                //AuthenticationScheme = "GitHub"; or "ApplicationCookie";
                //SignInScheme = "ApplicationCookie"
                })
                .AddGoogle(options =>
                {
                    options.ClientId = "92495618689-f7nlo66hu5ec1ru52b0ha7m9jp6kkivv.apps.googleusercontent.com";
                    options.ClientSecret = "sIQ3jEtxZOUI_ndfsvKIT9vc";
                    //AuthenticationScheme = "GitHub"; or "ApplicationCookie";
                    //SignInScheme = "ApplicationCookie"
                })
                .AddCookie(options =>
                {
                    options.LoginPath = "/api/auth/providers";
                });


            // api user claim policy
            services.AddAuthorization(options =>
            {
                options.AddPolicy("ApiUser",
                    policy => policy.RequireClaim(Constants.Constants.Strings.JwtClaimIdentifiers.Rol, Constants.Constants.Strings.JwtClaims.ApiAccess));
            });

            services.AddMvc();
        }

        private void InitializeServices(IServiceCollection services)
        {
            // Helps in providing the Prototype Data Context to whole application as a single object
            services.AddDbContext<SocialAuthDataContext>(options => {
                options.UseSqlServer(this.configuration.GetSection("ConnectionStrings").GetSection("DefaultConnection").Value);
            });

            // Add HttpContext
            services.TryAddTransient<IHttpContextAccessor, HttpContextAccessor>();

            // Repositories
            services.AddScoped<IUserRepository, UserRepository>();

            // Services
            services.AddScoped<IClaimService, ClaimService>();
            services.AddScoped<IRefreshTokenFactory, RefreshTokenFactory>();
            services.AddScoped<ITokenHandler, TokenHandler>();
            services.AddScoped<ITokenService, TokenService>();
            services.AddScoped<IAuthProviderService, AuthProviderService>();
            services.AddScoped<IUserService, UserService>();
            services.AddScoped<IFacebookService, FacebookService>();
            services.AddScoped<IGoogleService, GoogleService>();
            services.AddScoped<IGitHubService, GitHubService>();
            //services.AddScoped<IFacebookClient, FacebookClient>;
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            /*else
            {
                app.UseExceptionHandler(builder =>
                {
                    builder.Run(async context =>
                    {
                        context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                        context.Response.Headers.Add("Access-Control-Allow-Origin", "*");

                        var error = context.Features.Get<IExceptionHandlerFeature>();
                        if (error != null)
                        {
                            context.Response.AddApplicationError(error.Error.Message);
                            await context.Response.WriteAsync(error.Error.Message).ConfigureAwait(false);
                        }
                    });
                });
            }*/
            app.Use(async (context, next) => {
                await next();
                if (context.Response.StatusCode == 404 &&
                !Path.HasExtension(context.Request.Path.Value) &&
                !context.Request.Path.StartsWithSegments("/auth"))
                {
                    context.Request.Path = "/index.html";
                    await next();
                }
             });

            app.UseMvcWithDefaultRoute();
            app.UseDefaultFiles();
            app.UseStaticFiles();
            app.UseAuthentication();
            app.UseMvc();
        }
    }
}
