using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace tokenGeneration
{
    public static class TypeConverterExtension
    {
        public static byte[] ToByteArray(this string value) =>
               Convert.FromBase64String(value);
    }

    public class RSAJwtHandler : IJwtHandler
    {

        private const string publickey = "public.pem";
        private const string privatekey = "private.pem";



        public string CreateToken(int minutsDeValidesa)
        {
            // var privateKey = privatekey.ToByteArray();

            var privatePem = File.ReadAllText(privatekey);

            using RSA rsa = RSA.Create();
            // rsa.ImportRSAPrivateKey(privateKey, out _);
            rsa.ImportFromPem(privatePem);

            var signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            var now = DateTime.Now;
            var unixTimeSeconds = new DateTimeOffset(now).ToUnixTimeSeconds();
            var aBitOfSalt =
                Guid
                .NewGuid()
                .ToString()
                .Split("-")
                .Last();
            var id = $"{1}";

            var expiration = DateTimeOffset
                .UtcNow
                .AddMinutes(minutsDeValidesa)
                .AddSeconds(0)
                .ToUnixTimeSeconds();


            var jwt = new JwtSecurityToken(
                audience: "http://locahost:5000",
                issuer: "http://aliga3.udg.cat",
                claims: new Claim[] {
                    new Claim(JwtRegisteredClaimNames.Iat, unixTimeSeconds.ToString(), ClaimValueTypes.Integer64), // El podria fer amb atributs però és per fer-lo diferent
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(nameof(aBitOfSalt), aBitOfSalt),
                    new Claim(nameof(id), id),
                },
                notBefore: now,
                expires: now.AddMinutes(minutsDeValidesa),
                signingCredentials: signingCredentials
            );

            string token = new JwtSecurityTokenHandler().WriteToken(jwt);

            return token;
        }



        public bool ValidateToken(string token)
        {

            // var publicKey = publickey.ToByteArray();
            // rsa.ImportRSAPublicKey(publicKey, out _);

            var publicPem = File.ReadAllText(publickey);
            using RSA rsa = RSA.Create();

            rsa.ImportFromPem(publicPem);

            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = "http://aliga3.udg.cat",
                ValidAudience = "http://locahost:5000",
                IssuerSigningKey = new RsaSecurityKey(rsa),
                CryptoProviderFactory = new CryptoProviderFactory()
                {
                    CacheSignatureProviders = false
                },
                ClockSkew = TimeSpan.Zero   // sinó es posa dóna un marge de 5 minuts ..
            };

            try
            {
                var handler = new JwtSecurityTokenHandler();
                handler.ValidateToken(token, validationParameters, out var validatedSecurityToken);
            }
            catch
            {
                return false;
            }

            return true;
        }
    }
}

