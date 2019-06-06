using System;
using System.Collections.Generic;
using System.Linq;

namespace Test.SocialAuth.Contracts.Models
{
    public class User : BaseEntity
    {
        public string FirstName { get; set; } // EF migrations require at least private setter - won't work on auto-property
        public string LastName { get; set; }
        public string IdentityId { get; set; }
        public string UserName { get; set; } // Required by automapper
        public string Email { get; set; }
        public string Country { get; set; }
        public string Profession { get; set; }
        public string PasswordHash { get; set; }
        public Provider Provider { get; set; }
        public string FacebookUrl { get; set; }
        public string GitHubUrl { get; set; }


        private readonly List<RefreshToken> _refreshTokens = new List<RefreshToken>();
        public IReadOnlyCollection<RefreshToken> RefreshTokens => _refreshTokens.AsReadOnly();

        

        public bool HasValidRefreshToken(string refreshToken)
        {
            return _refreshTokens.Any(rt => rt.Token == refreshToken && rt.Active);
        }

        public void AddRefreshToken(string token, int userId, string remoteIpAddress, double daysToExpire = 5)
        {
            _refreshTokens.Add(new RefreshToken() {
                Token = token,
                UserId = userId,
                RemoteIpAddress = remoteIpAddress,
                Expires = DateTime.UtcNow.AddDays(daysToExpire) });
        }

        public void RemoveRefreshToken(string refreshToken)
        {
            _refreshTokens.Remove(_refreshTokens.First(t => t.Token == refreshToken));
        }
    }
}
