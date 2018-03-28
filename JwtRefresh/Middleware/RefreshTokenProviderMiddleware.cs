using JwtRefresh.Data;
using JwtRefresh.Models;
using JwtRefresh.Utils;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
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
    public class RefreshTokenProviderMiddleware
    {
        private readonly RequestDelegate _next;
        private RefreshTokenProviderOptions _options;
        private UserManager<ApplicationUser> _userManager;
        private SignInManager<ApplicationUser> _signInManager;
        private ApplicationDbContext _applicationDbContext;
        public RefreshTokenProviderMiddleware(
            RequestDelegate next,
            IOptions<RefreshTokenProviderOptions> options

            )
        {
            _next = next;
            _options = options.Value;
        }
        public Task Invoke(HttpContext context, UserManager<ApplicationUser> userManager, ApplicationDbContext applicationDbContext,SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;
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
            var refreshToken = context.Request.Form["refreshToken"];
            if (String.IsNullOrEmpty(refreshToken))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("User must relogin");
                return;
            }
            var refreshTokenModel = _applicationDbContext.RefreshTokens.Include(i =>i.User).FirstOrDefault(f=>f.Token==refreshToken);
            if (refreshTokenModel == null)
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync("User must relogin");
                return;
            }
            if(!await _signInManager.CanSignInAsync(refreshTokenModel.User))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync(" User is unable to login.");
                return;
            }
            if(_userManager.SupportsUserLockout && await _userManager.IsLockedOutAsync(refreshTokenModel.User))
            {
                context.Response.StatusCode = 400;
                await context.Response.WriteAsync(" User is locked out.");
                return;
            }
            var user = refreshTokenModel.User;
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

            refreshTokenModel.IssuedUtc = now;
            refreshTokenModel.ExpiresUtc = now.Add(_options.Expiration);
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
                refresh_token = refreshTokenModel.Token
            };

            context.Response.ContentType = "application/json";
            await context.Response.WriteAsync(JsonConvert.SerializeObject(response, new JsonSerializerSettings { Formatting = Formatting.Indented }));
        }
    }
    public static class RefreshTokenProviderMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtRefreshTokenProviderMiddleware(this IApplicationBuilder builder,IOptions<RefreshTokenProviderOptions> options)
        {
            return builder.UseMiddleware<RefreshTokenProviderMiddleware>(options);
        }
        
    }
}
