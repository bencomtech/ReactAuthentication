using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using ReactAuthentication.API.Models;
using System;

namespace ReactAuthentication.API
{
    public class AuthRepository : IDisposable
    {
        private readonly AuthContext authContext;
        private readonly UserManager<IdentityUser> userManager;

        public AuthRepository()
        {
            authContext = new AuthContext();
            userManager = new UserManager<IdentityUser>(new UserStore<IdentityUser>(authContext));
        }

        public IdentityResult Register(UserModel userModel)
        {
            IdentityUser identityUser = new IdentityUser()
            {
                UserName = userModel.UserName
            };

            return userManager.Create(identityUser, userModel.Password);
        }

        public IdentityUser FindUser(string userName, string password)
        {
            return userManager.Find(userName, password);
        }

        public void Dispose()
        {
            userManager.Dispose();
            authContext.Dispose();
        }
    }
}