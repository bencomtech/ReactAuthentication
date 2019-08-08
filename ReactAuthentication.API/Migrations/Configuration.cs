namespace ReactAuthentication.API.Migrations
{
    using System.Data.Entity.Migrations;

    internal sealed class Configuration : DbMigrationsConfiguration<AuthContext>
    {
        public Configuration()
        {
            AutomaticMigrationsEnabled = false;
            ContextKey = "ReactAuthentication.API.AuthContext";
        }

        protected override void Seed(AuthContext context)
        {
            context.Clients.AddOrUpdate(new Entities.Client()
            {
                Id = "reactApp",
                Secret = Helper.GetHash("ben123456"),
                Name = "ReactAuthentication",
                Active = true,
                RefreshTokenLifeTime = 60 * 24 * 10, // 10 days
                AllowedOrigin = "*"
            });
        }
    }
}
