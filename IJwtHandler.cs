public interface IJwtHandler {
    string CreateToken();
    bool ValidateToken(string token);
}