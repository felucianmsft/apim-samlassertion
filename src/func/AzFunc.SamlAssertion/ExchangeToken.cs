using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;

namespace AzFunc.SamlAssertion
{
    public class ExchangeToken
    {
        private class RequestBody
        {
            public string grant_type { get; set; }
            public string assertion { get; set; }
        }

        private readonly ILogger<ExchangeToken> _logger;

        public ExchangeToken(ILogger<ExchangeToken> logger)
        {
            _logger = logger;
        }

        [Function("ExchangeToken")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function,"post")] HttpRequest req)
        {
            _logger.LogInformation("C# HTTP trigger function processed a request.");

            
            var data = await System.Text.Json.JsonSerializer.DeserializeAsync<RequestBody>(req.Body);

            if (data.grant_type == "urn:ietf:params:oauth:grant-type:saml2-bearer")
            {
                // Validate the SAML assertion
                // Exchange the SAML assertion for an OAuth token
                return new JsonResult(new {access_token=$"this_is_a_jwt_access_token_generated_at_{DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ")}"});
            }
            else
            {
                return new BadRequestObjectResult("Invalid grant_type");
            }
        }
    }
}
