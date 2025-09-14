using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using TagTool.SyncAzFunction;

var builder = FunctionsApplication.CreateBuilder(args)
    .ConfigureFunctionsWebApplication();

builder.Logging
    .AddConsole()
    .SetMinimumLevel(LogLevel.Information);

builder.UseMiddleware<JwtValidationMiddleware>();
builder.UseMiddleware<AuthorizationMiddleware>();

builder.Services
    .AddApplicationInsightsTelemetryWorkerService()
    .ConfigureFunctionsApplicationInsights();

builder
    .Build()
    .Run();
