using Autofac;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Newtonsoft.Json;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Mentoz.AspNetCore.Api
{
    public class ActionFilter : IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (context.ModelState.IsValid)
                await next();
            else
                HandleModelStateErrors(context);
        }
        private void HandleModelStateErrors(ActionExecutingContext context)
        {
            var validationResults = new List<string>();
            var modelErrorCollection = context.ModelState.Where(x => x.Value.Errors.Any()).Select(x => new { x.Key, x.Value.Errors });
            foreach (var item in modelErrorCollection)
                validationResults.AddRange(item.Errors.Select(x => string.IsNullOrEmpty(x.ErrorMessage) ? x.Exception.Message : x.ErrorMessage)); // item.Key
            context.HttpContext.Response.Headers.Add("X-Validation", "Failed");
            context.Result = new ObjectResult(JsonConvert.SerializeObject(validationResults)) { StatusCode = StatusCodes.Status400BadRequest };
        }
    }
}