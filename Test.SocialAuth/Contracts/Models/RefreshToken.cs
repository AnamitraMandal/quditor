using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Test.SocialAuth.Contracts.Models
{
    public class RefreshToken : BaseEntity
    {
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public int UserId { get; set; }
        public bool Active => DateTime.UtcNow <= Expires;
        public string RemoteIpAddress { get; set; }
    }
}
