namespace Test.SocialAuth.DataAccess.Initializer
{
    using Microsoft.EntityFrameworkCore;
    using Test.SocialAuth.Contracts;
    using Test.SocialAuth.Contracts.Models;

    public class SocialAuthDataContext : DbContext
    {
        public SocialAuthDataContext()
        {
        }

        public SocialAuthDataContext(DbContextOptions<SocialAuthDataContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }

        public DbSet<RefreshToken> RefreshTokens { get; set; }

        /// <inheritdoc/>
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.HasDefaultSchema("SocialAuth");
        }
    }
}
