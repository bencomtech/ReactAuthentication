using Microsoft.AspNet.Identity.EntityFramework;
using ReactAuthentication.API.Entities;
using System.Data.Entity;

namespace ReactAuthentication.API
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public AuthContext() : base("AuthContext")
        {
        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}