using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using ReactAuthentication.API.Entities;
using ReactAuthentication.API.Models;
using System;
using System.Collections.Generic;
using System.Linq;

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

        public Client FindClient(string clientId)
        {
            return authContext.Clients.Find(clientId);
        }

        public List<RefreshToken> GetAllRefreshTokens()
        {
            return authContext.RefreshTokens.ToList();
        }

        public bool AddRefreshToken(RefreshToken token)
        {
            RefreshToken refreshToken = authContext.RefreshTokens.Where(r => r.Subject == token.Subject)
                .Where(r => r.ClientId == token.ClientId)
                .FirstOrDefault();

            if (refreshToken != null)
                RemoveRefreshToken(refreshToken);

            authContext.RefreshTokens.Add(token);

            return authContext.SaveChanges() > 0;
        }

        public bool RemoveRefreshToken(RefreshToken refreshToken)
        {
            authContext.RefreshTokens.Remove(refreshToken);

            return authContext.SaveChanges() > 0;
        }

        public bool RemoveRefreshToken(string refreshTokenId)
        {
            RefreshToken refreshToken = authContext.RefreshTokens.Find(refreshTokenId);

            if (refreshToken != null)
            {
                authContext.RefreshTokens.Remove(refreshToken);

                return authContext.SaveChanges() > 0;
            }

            return false;
        }

        public RefreshToken FindRefreshToken(string refreshTokenId)
        {
            return authContext.RefreshTokens.Find(refreshTokenId);
        }

        public void Dispose()
        {
            userManager.Dispose();
            authContext.Dispose();
        }
    }
}