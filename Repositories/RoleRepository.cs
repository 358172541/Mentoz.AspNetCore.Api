namespace Mentoz.AspNetCore.Api
{
    public class RoleRepository : MentozRepository<Role>, IRoleRepository
    {
        public RoleRepository(ITransaction transaction) : base(transaction) { }
    }
}