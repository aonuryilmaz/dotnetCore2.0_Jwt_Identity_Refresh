using JwtRefresh.Data;
using JwtRefresh.Models;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace JwtRefresh.Extensions
{
    public static class ControllerExtension
    {
        public static ApplicationUser GetDbUser(this Controller controller, ApplicationDbContext db)
        {
            try
            {

                string userId = controller.User.Claims.Where(x => x.Type == ClaimTypes.NameIdentifier).First().Value;
                ApplicationUser user = db.Users.Where(x => x.Id == userId).First();
                return user;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
