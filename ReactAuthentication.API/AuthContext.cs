using Microsoft.AspNet.Identity.EntityFramework;

namespace ReactAuthentication.API
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public AuthContext() : base("AuthContext")
        {
        }
    }
}