using Autofac;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Mentoz.AspNetCore.Api
{
    public class SecurityAttribute : Attribute, IAsyncAuthorizationFilter
    {
        public string[] Identities { get; }
        public SecurityAttribute(params string[] identities)
        {
            Identities = identities;
        }
        public async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            var currentUser = await CurrentUser(context);
            if (currentUser == null) PermissionDenied(context);
            if (currentUser.Type == UserType.MANAGER == false)
            {
                var currentUserRoleIds = await CurrentUserRoleIds(context, currentUser.UserId);
                var currentUserRescIds = await CurrentUserRescIds(context, currentUserRoleIds);
                var convertAttrRescIds = await ConvertAttrRescIds(context);
                if (currentUserRescIds.Intersect(convertAttrRescIds).Any() == false) PermissionDenied(context);
            }
        }
        private async Task<User> CurrentUser(AuthorizationFilterContext context)
        {
            var identity = context.HttpContext.User.Identity as ClaimsIdentity;
            var subject = identity.FindFirst(x => x.Type == JwtRegisteredClaimNames.Sub);
            var currentUserId = subject == null ? Guid.Empty : Guid.Parse(subject.Value);
            var serviceProvider = context.HttpContext.RequestServices;
            var repository = serviceProvider.GetRequiredService<IUserRepository>();
            return await repository.FindAsync(currentUserId);
        }
        private async Task<List<Guid>> CurrentUserRoleIds(AuthorizationFilterContext context, Guid currentUserId)
        {
            var serviceProvider = context.HttpContext.RequestServices;
            var repository = serviceProvider.GetRequiredService<IUserRoleRepository>();
            return await repository.Entities.AsNoTracking()
                .Where(x => x.UserId == currentUserId)
                .Select(x => x.RoleId)
                .ToListAsync();
        }
        private async Task<List<Guid>> CurrentUserRescIds(AuthorizationFilterContext context, List<Guid> currentUserRoleIds)
        {
            var serviceProvider = context.HttpContext.RequestServices;
            var repository = serviceProvider.GetRequiredService<IRoleRescRepository>();
            return await repository.Entities.AsNoTracking()
                .Where(x => currentUserRoleIds.Contains(x.RoleId))
                .Select(x => x.RescId)
                .ToListAsync();
        }
        private async Task<List<Guid>> ConvertAttrRescIds(AuthorizationFilterContext context)
        {
            var serviceProvider = context.HttpContext.RequestServices;
            var repository = serviceProvider.GetRequiredService<IRescRepository>();
            return await repository.Entities.AsNoTracking()
                .Where(x => Identities.Contains(x.Identity))
                .Select(x => x.RescId)
                .ToListAsync();
        }
        private void PermissionDenied(AuthorizationFilterContext context)
        {
            context.HttpContext.Response.Headers.Add("X-Permission", "Denied");
            context.Result = new ObjectResult(JsonConvert.SerializeObject(new string[] { "Permission denied." })) { StatusCode = StatusCodes.Status403Forbidden };
        }
    }
}