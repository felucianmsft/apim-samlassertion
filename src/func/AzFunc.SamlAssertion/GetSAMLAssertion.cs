using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.IdentityModel.Tokens.Saml;
using Microsoft.IdentityModel.Tokens.Saml2;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace AzFunc.SamlAssertion
{
    public class GetSAMLAssertion
    {
        private class RequestBody
        {
            public string nameID { get; set; }
        }

        private readonly IConfiguration config;
        private readonly ILogger<GetSAMLAssertion> _logger;
        private readonly string issuer;
        private readonly string audience;
        private readonly X509Certificate2 certificate;
        private readonly SigningCredentials signingCredentials;
        private readonly Saml2SecurityTokenHandler handler = new Saml2SecurityTokenHandler();
        private readonly Saml2AuthenticationContext authnContext;
        private readonly Uri recipient;
        private readonly Uri subjectConfirmationMethod;
        private readonly Uri nameIDFormat;
        private readonly bool signAssertion;
        private readonly int assertionDurationMins;

        public GetSAMLAssertion(IConfiguration config, ILogger<GetSAMLAssertion> logger)
        {
            this.config = config;
            _logger = logger;

            recipient = new Uri(config["recipient"]);
            signAssertion = bool.Parse(config["signAssertion"]);
            issuer = config["issuer"];
            nameIDFormat = new Uri(config["nameIDFormat"]);
            audience = config["audience"];
            assertionDurationMins = int.Parse(config["assertionDurationMins"]);

            subjectConfirmationMethod = new Uri(config["subjectConfirmationMethod"]);

            authnContext = new Saml2AuthenticationContext(new Uri(config["authnContextClassRef"]));
            if (signAssertion)
            {
                using (X509Store certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                {
                    certStore.Open(OpenFlags.ReadOnly);

                    X509Certificate2Collection certCollection = certStore.Certificates.Find(
                                                X509FindType.FindByThumbprint,
                                                // Replace below with your certificate's thumbprint
                                                config["certificateThumbprint"],
                                                false);

                    // Get the first cert with the thumbprint
                    certificate = certCollection.OfType<X509Certificate2>().FirstOrDefault();

                    if (certificate is null)
                        throw new Exception($"Certificate with thumbprint {config["certificateThumbprint"]} was not found.");

                    signingCredentials = new SigningCredentials(new X509SecurityKey(certificate), SecurityAlgorithms.RsaSha256Signature);
                }
            }
        }

        [Function("GetSAMLAssertion")]
        public async Task<IActionResult> Run([HttpTrigger(AuthorizationLevel.Function, "post")] HttpRequest req)
        {

            string nameID;

            var body = await System.Text.Json.JsonSerializer.DeserializeAsync<RequestBody>(req.Body);
            nameID = body.nameID;

            SecurityTokenDescriptor descriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.NameIdentifier, nameID) }),
                Audience = audience,
                Issuer = issuer,
                SigningCredentials = signingCredentials
            };

            Saml2SecurityToken token = handler.CreateToken(descriptor) as Saml2SecurityToken;

            Saml2AuthenticationStatement authnStatement = new Saml2AuthenticationStatement(authnContext)
            {
                SessionNotOnOrAfter = DateTime.UtcNow.AddMinutes(assertionDurationMins)
            };

            Saml2SubjectConfirmationData subjectConfirmationData = new Saml2SubjectConfirmationData()
            {
                Recipient = recipient,
                NotOnOrAfter = DateTime.UtcNow.AddMinutes(assertionDurationMins)
            };

            Saml2SubjectConfirmation subjectConfirmation = new Saml2SubjectConfirmation(subjectConfirmationMethod, subjectConfirmationData);
            token.Assertion.Statements.Add(authnStatement);
            var attributeStatement = token.Assertion.Statements.FirstOrDefault(s => s is Saml2AttributeStatement) as Saml2AttributeStatement;
            if (attributeStatement != null)
            {
                token.Assertion.Statements.Remove(attributeStatement);
            }
            token.Assertion.Subject.NameId = new Saml2NameIdentifier(nameID, nameIDFormat);
            token.Assertion.Subject.SubjectConfirmations.Clear();
            token.Assertion.Subject.SubjectConfirmations.Add(subjectConfirmation);

            string assertionXml = handler.WriteToken(token);

            return new JsonResult(new { 
                samlAssertionBase64URLEncoded = Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(assertionXml))
            });
        }
    }
}
