
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

            var minutesValid = 1;

            // Genera un token a partir de la clau privada
            var token = jwtCreator.CreateToken(minutesValid);
            Console.WriteLine($"Token: {token}");

            Console.WriteLine();
            Console.WriteLine(DateTime.Now);
            // Verifica el token, però només fa servir la clau pública
            Console.WriteLine($"Valida: {jwtCreator.ValidateToken(token)}");

            Console.WriteLine("Esperant una estona (ves que no sigui per fer caducar el token)");
            Task.Delay(6 * minutesValid * 10000 + 20000).Wait();
            // Verifica si el token ha caducat
            Console.WriteLine(DateTime.Now);
            Console.WriteLine($"Valida: {jwtCreator.ValidateToken(token)}");

        }

    }
}