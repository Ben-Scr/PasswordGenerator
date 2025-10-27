using BenScr.Security.Password;
public static class Program
{
    public static void Main(string[] args)
    {
        PasswordUtility.Initialize();
        Password pwd = new Password();
        Console.WriteLine($"Generated Password \"{pwd.Next()}\"");
        Console.WriteLine(PasswordUtility.ClassifyPassword(pwd.Next()));
        Password pwd2 = new Password();
    }
}