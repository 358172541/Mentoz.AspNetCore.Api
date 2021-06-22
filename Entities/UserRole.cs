using System;

namespace Mentoz.AspNetCore.Api
{
    public class UserRole
    {
        public Guid UserId { get; set; }
        public Guid RoleId { get; set; }
    }
}