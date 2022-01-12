
// gerador de jws / jwe
using JWT.Algorithms;
using JWT.Builder;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace tokenGeneration
{
    public class Program
    {
        public static void Main(string[] args)
        {

            IJwtHandler jwtCreator = new RSAJwtHandler();

            // Genera un token a partir de la clau privada
            var token = jwtCreator.CreateToken();
            Console.WriteLine($"Token: {token}");


            // Verifica el token, però només fa servir la clau pública
            Console.WriteLine($"Valida: {jwtCreator.ValidateToken(token)}");

        }

    }
}