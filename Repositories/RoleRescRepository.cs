﻿namespace Mentoz.AspNetCore.Api
{
    public class RoleRescRepository : MentozRepository<RoleResc>, IRoleRescRepository
    {
        public RoleRescRepository(ITransaction transaction) : base(transaction) { }
    }
}