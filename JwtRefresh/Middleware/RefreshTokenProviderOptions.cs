using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JwtRefresh.Middleware
{
    public class RefreshTokenProviderOptions
    {
        public string Path { get; set; } = "/refresh";
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public TimeSpan Expiration { get; set; } = TimeSpan.FromMinutes(3600);
        public SigningCredentials SigningCredentials { get; set; }
    }
}
