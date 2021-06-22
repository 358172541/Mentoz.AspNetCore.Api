using Autofac;
using Autofac.Extensions.DependencyInjection;
using AutoMapper;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json.Serialization;
using Serilog;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Reflection;

namespace Mentoz.AspNetCore.Api
{
    public class Mentoz
    {
        public static string Audience = "https://api.mentoz.com";
        public static string Issuer = "https://api.mentoz.com";
        public static string Secret = "Wjagjbmui5ZBCC0nV6HMdTsEYjznXJGqhOVIRbH50P8=";
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }
        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(budr =>
                {
                    budr.ConfigureServices((cntx, svcs) =>
                    {
                        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();
                        svcs.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                            .AddJwtBearer(opts =>
                            {
                                opts.TokenValidationParameters = new TokenValidationParameters
                                {
                                    IssuerSigningKey = new SymmetricSecurityKey(Convert.FromBase64String(Mentoz.Secret)),
                                    RequireExpirationTime = true,
                                    ValidAudience = Mentoz.Audience,
                                    ValidIssuer = Mentoz.Issuer,
                                    ValidateAudience = true,
                                    ValidateIssuer = true,
                                    ValidateIssuerSigningKey = true,
                                    ValidateLifetime = true
                                };
                            });
                        svcs.AddAutoMapper(Assembly.GetExecutingAssembly());
                        svcs.AddControllers(opts =>
                        {
                            opts.Filters.Add(typeof(ActionFilter));
                            opts.Filters.Add(typeof(ExceptionFilter));
                        }).AddNewtonsoftJson(opts =>
                        {
                            opts.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
                        });
                        svcs.AddCors(opts =>
                        {
                            opts.AddDefaultPolicy(budr =>
                            {
                                budr.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()
                                    .WithExposedHeaders("X-Permission", "X-Token", "X-Validation", "X-Version");
                            });
                        });
                        svcs.AddDbContext<MentozContext>(budr =>
                        {
                            budr.UseSqlServer(cntx.Configuration.GetConnectionString("DefaultConnection"));
                        });
                        svcs.AddHttpContextAccessor();
                        svcs.AddSwaggerGen(opts =>
                        {
                            opts.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
                            {
                                Description = "Please enter into field the word 'Bearer' followed by a space and the JWT value",
                                Name = "Authorization",
                                In = ParameterLocation.Header,
                                Type = SecuritySchemeType.ApiKey
                            });
                            opts.AddSecurityRequirement(new OpenApiSecurityRequirement
                            {
                                {
                                    new OpenApiSecurityScheme {
                                        Reference = new OpenApiReference {
                                            Id = "Bearer",
                                            Type = ReferenceType.SecurityScheme
                                        }
                                    }, Array.Empty<string>()
                                }
                            });
                            opts.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, $"{Assembly.GetExecutingAssembly().GetName().Name}.xml"), true);
                            opts.SwaggerDoc("v1", new OpenApiInfo
                            {
                                Title = "Mentoz.AspNetCore.Api Title",
                                Version = "v1",
                                Description = "Mentoz.AspNetCore.Api Description",
                                Contact = new OpenApiContact
                                {
                                    Name = "Mentoz",
                                    Email = "mentoz@hotmail.com"
                                }
                            });
                        });
                    });

                    budr.Configure((cntx, budr) =>
                    {
                        budr.UseSerilogRequestLogging();
                        budr.UseDefaultFiles();
                        budr.UseStaticFiles();
                        budr.UseRouting();
                        budr.UseCors();
                        budr.UseAuthentication();
                        budr.UseAuthorization();
                        budr.UseEndpoints(x => x.MapControllers());
                        budr.UseSwagger(x => x.RouteTemplate = "swagger/{documentName}/swagger.json");
                        budr.UseSwaggerUI(x => x.SwaggerEndpoint("v1/swagger.json", "The Mentoz API"));
                    });
                })
                .UseSerilog((cntx, logr) => logr.ReadFrom.Configuration(cntx.Configuration))
                .UseServiceProviderFactory(cntx => new AutofacServiceProviderFactory(budr =>
                {
                    budr.RegisterType<MentozContext>()
                        .As<ITransaction>()
                        .InstancePerLifetimeScope();
                    budr.RegisterAssemblyTypes(Assembly.GetExecutingAssembly())
                        .AsClosedTypesOf(typeof(IRepository<>))
                        .InstancePerLifetimeScope();
                }));
    }
}

// SecurityTokenExpiredException

/*
//  <PackageReference Include = "Serilog.Sinks.Exceptionless" Version="3.1.2" />
//  <PackageReference Include = "Serilog.Sinks.Seq" Version="4.0.0" />
//  docker run -d --restart unless-stopped --name seq -e ACCEPT_EULA=Y -v D:\Logs:/data -p 8088:80 datalust/seq:latest
{
    "Name": "File",
    "Args": {
        "path": "D:\\Logs\\log.txt",
        "outputTemplate": "{Timestamp:G} {Message}{NewLine:1}{Exception:1}"
    }
},
{
    "Name": "File",
    "Args": {
        "path": "D:\\Logs\\log.json",
        "formatter": "Serilog.Formatting.Json.JsonFormatter, Serilog"
    }
},
{
    "Name": "Seq",
    "Args": {
        "serverUrl": "http://localhost:8088"
    }
},
{
    "Name": "Exceptionless",
    "Args": {
        "apiKey": "N5Hamc1pDNVODtihfMLQXjUIgMWDOSktcwiOyExN"
    }
}
*/