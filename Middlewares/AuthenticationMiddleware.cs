namespace TagTool.SyncAzFunctions.Middlewares;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using System.Net;

public class JwtValidationMiddleware : IFunctionsWorkerMiddleware
{
    private const string Domain = "dev-y5nz4h20ek8xt3ux.us.auth0.com";
    private const string ValidAudiences = "https://APP_NAME.azurewebsites.net/api/tag-tool-sync-az-function/";
    private const string Issuer = "https://dev-y5nz4h20ek8xt3ux.us.auth0.com/";

    private static readonly IConfigurationManager<OpenIdConnectConfiguration> _configManager =
        new ConfigurationManager<OpenIdConnectConfiguration>(
            $"https://{Domain}/.well-known/openid-configuration",
            new OpenIdConnectConfigurationRetriever(),
            new HttpDocumentRetriever())
        {
            AutomaticRefreshInterval = TimeSpan.FromHours(24),
            RefreshInterval = TimeSpan.FromMinutes(5),
        };

    private readonly JsonWebTokenHandler _handler = new();

    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        var request = await context.GetHttpRequestDataAsync();

        if (request is null)
        {
            return;
        }

        if (!request.Headers.TryGetValues("Authorization", out var authHeaders))
        {
            var response = request.CreateResponse();
            response.StatusCode = HttpStatusCode.Unauthorized;
            context.GetInvocationResult().Value = response;
            return;
        }

        var token = authHeaders.First().Split(" ").Last();

        try
        {
            var discoveryDocument = await _configManager.GetConfigurationAsync(context.CancellationToken);

            var validationParams = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = Issuer,
                ValidateAudience = true,
                ValidAudience = ValidAudiences,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                IssuerSigningKeys = discoveryDocument.SigningKeys,
            };

            var tokenValidationResult = await _handler.ValidateTokenAsync(token, validationParams);

            if (!tokenValidationResult.IsValid)
            {
                var response = request.CreateResponse();
                response.StatusCode = HttpStatusCode.Unauthorized;
                context.GetInvocationResult().Value = response;
            }

            context.Items["UserClaims"] = tokenValidationResult.Claims;

            await next(context);
        }
        catch
        {
            var response = request.CreateResponse();
            response.StatusCode = HttpStatusCode.InternalServerError;
            context.GetInvocationResult().Value = response;
        }
    }
}
