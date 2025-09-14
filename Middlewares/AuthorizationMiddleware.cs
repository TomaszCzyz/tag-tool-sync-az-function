namespace TagTool.SyncAzFunctions.Middlewares;

using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Middleware;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;

public class AuthorizationMiddleware : IFunctionsWorkerMiddleware
{
    public async Task Invoke(FunctionContext context, FunctionExecutionDelegate next)
    {
        var request = await context.GetHttpRequestDataAsync();
        Debug.Assert(request != null, nameof(request) + " != null");

        try
        {
            if (!context.Items.TryGetValue("UserClaims", out var claims)
                || !TryGetPermissionsClaim(claims, out var permissions)
                || !permissions.Contains("write:storage"))
            {
                var response = request.CreateResponse();
                response.StatusCode = HttpStatusCode.Unauthorized;
                context.GetInvocationResult().Value = response;
                return;
            }

            await next(context);
        }
        catch
        {
            var response = request.CreateResponse();
            response.StatusCode = HttpStatusCode.InternalServerError;
            context.GetInvocationResult().Value = response;
        }
    }

    private static bool TryGetPermissionsClaim(object claims, [NotNullWhen(true)] out IEnumerable<object>? permissions)
    {
        permissions = null;
        if (claims is not IEnumerable<KeyValuePair<string, object>> userClaims)
        {
            return false;
        }

        var t = userClaims.FirstOrDefault(c => c.Key == "permissions");

        if (t.Value is not IEnumerable<object> permissionsClaim)
        {
            return false;
        }

        permissions = permissionsClaim;
        return true;
    }
}
