﻿using System;
using System.Collections.Generic;

namespace Mentoz.AspNetCore.Api
{
    public class RoleUpdateModel
    {
        public Guid Id { get; set; }
        public string Display { get; set; }
        public bool Available { get; set; }
        public List<Guid> RescIds { get; set; } = new List<Guid>();
        public List<Guid> UserIds { get; set; } = new List<Guid>();
        public string Version { get; set; }
    }
}