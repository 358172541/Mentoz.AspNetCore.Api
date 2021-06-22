using System;

namespace Mentoz.AspNetCore.Api
{
    public class UserModel
    {
        public Guid Id { get; set; }
        public string Account { get; set; }
        public string Password { get; set; }
        public string Display { get; set; }
        public bool Available { get; set; }
        public string AvailableDisplay { get; set; }
    }
}