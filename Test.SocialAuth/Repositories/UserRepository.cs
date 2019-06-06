namespace Test.SocialAuth.Repositories
{
    using Test.SocialAuth.Contracts.Models;
    using Test.SocialAuth.DataAccess.Initializer;
    using Test.SocialAuth.UnitOfWork;

    public class UserRepository : Repository<User>, IUserRepository
    {
        public UserRepository(SocialAuthDataContext dataContext)
            : base(dataContext)
        {
        }
    }
}
