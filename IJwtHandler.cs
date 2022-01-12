public interface IJwtHandler {
    string CreateToken(int minutsDeValidesa = 10);
    bool ValidateToken(string token);
}