using JwtRefresh.Data;
using JwtRefresh.Models;
using JwtRefresh.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtRefresh.Middleware
{
    public class TokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private TokenProviderOptions _options;
        private UserManager<ApplicationUser> _userManager;
        private ApplicationDbContext _applicationDbContext;
        public TokenProviderMiddleware(
            RequestDelegate next,
            IOptions<TokenProviderOptions> options

            )
        {
            _next = next;
            _options = options.Value;
        }
        public Task Invoke(HttpContext context,UserManager<ApplicationUser> userManager,ApplicationDbContext applicationDbContext)
        {
            _applicationDbContext = applicationDbContext;
            _userManager = userManager;
            if (!context.Request.Path.Equals(_options.Path, StringComparison.Ordinal))
            {
                return _next(context);
            }
            if (!context.Request.Method.Equals("POST") || !context.Request.HasFormContentType)
            {
                context.Response.StatusCode = 400;
                return context.Response.WriteAsync("Bad Request");
            }
            return GenerateToken(context);
        }
        public async Task GenerateToken(HttpContext context)
        {
            string username = context.Request.Form["username"];
            string password = context.Request.Form["password"];

            ApplicationUser user = null;
            user = _applicationDbContext.Users.Where(x => x.UserName == username).FirstOrDefault();

            var result = _userManager.CheckPasswordAsync(user, password);
            if (result.Result == false)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("Invalid username or password");
                return;
            }
            var now = DateTime.UtcNow;

            var userClaims = await _userManager.GetRolesAsync(user);
            List<Claim> claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.NameIdentifier, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64));
            //claims.AddRange(user.Claims.ToArray());

            foreach (var x in userClaims)
            {
                claims.Add(new Claim(ClaimTypes.Role, x));
            }

            var refreshToken = new RefreshToken
            {
                UserId = user.Id,
                Token = Guid.NewGuid().ToString("N"),
                IssuedUtc = now,
                ExpiresUtc = now.Add(_options.Expiration)
            };
            _applicationDbContext.InsertNew(refreshToken);
            _applicationDbContext.SaveChanges();
            var jwt = new JwtSecurityToken(
                issuer: _options.Issuer,
                audience: _options.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(_options.Expiration),
                signingCredentials: _options.SigningCredentials);

            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);
           
            var response = new LoginResponseData
            {
                access_token = encodedJwt,
                expires_in = (int)_options.Expiration.TotalSeconds,
                userName = user.UserName,
                refresh_token=refreshToken.Token
            };

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, new JsonSerializerSettings { Formatting = Formatting.Indented }));
        }
    }
    public static class TokenProviderMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtTokenProviderMiddleware(this IApplicationBuilder builder,IOptions<TokenProviderOptions> options)
        {
            return builder.UseMiddleware<TokenProviderMiddleware>(options);
        }
    }
    
}
