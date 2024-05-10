using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

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
        private readonly JsonWebTokenHandler _jwtHandler = new JsonWebTokenHandler();
        private readonly ClaimsIdentity _subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("name", "username"),
                    new Claim("role", "role")
                });
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
                return new JsonResult(new {access_token=await GenerateJWT()});
            }
            else
            {
                return new BadRequestObjectResult("Invalid grant_type");
            }
        }

        private async Task<string> GenerateJWT()
        {
            SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = _subject,
                Expires = DateTime.UtcNow.AddMinutes(60),
                Audience = "testaudience",
                Issuer = "testissuer"
            };
            return _jwtHandler.CreateToken(securityTokenDescriptor);
        }
    }
}
