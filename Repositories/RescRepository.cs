﻿namespace Mentoz.AspNetCore.Api
{
    public class RescRepository : MentozRepository<Resc>, IRescRepository
    {
        public RescRepository(ITransaction transaction) : base(transaction) { }
    }
}