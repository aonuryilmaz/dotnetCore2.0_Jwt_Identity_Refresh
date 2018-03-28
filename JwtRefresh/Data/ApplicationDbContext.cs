using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using JwtRefresh.Models;

namespace JwtRefresh.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public void InsertNew(RefreshToken token)
        {
            var tokenModel = RefreshTokens.SingleOrDefault(i => i.UserId == token.UserId);
            if (tokenModel != null)
            {
                RefreshTokens.Remove(tokenModel);
                SaveChanges();
            }
            RefreshTokens.Add(token);
            SaveChanges();
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.Entity<RefreshToken>()
                       .HasAlternateKey(c => c.UserId)
                .HasName(" refreshToken_UserId ");
            builder.Entity<RefreshToken>()
                      .HasAlternateKey(c => c.Token)
                .HasName(" refreshToken_Token");
            base.OnModelCreating(builder);

        }
    }
}
