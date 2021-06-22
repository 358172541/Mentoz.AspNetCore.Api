using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Mentoz.AspNetCore.Api
{
    public class RoleCreateModel
    {
        [Required]
        public string Display { get; set; }
        public bool Available { get; set; }
        public List<Guid> RescIds { get; set; } = new List<Guid>();
        public List<Guid> UserIds { get; set; } = new List<Guid>();
    }
}