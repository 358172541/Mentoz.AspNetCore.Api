using System;

namespace Mentoz.AspNetCore.Api
{
    public class RoleModel
    {
        public Guid Id { get; set; }
        public string Display { get; set; }
        public bool Available { get; set; }
        public string AvailableDisplay { get; set; }
    }
}