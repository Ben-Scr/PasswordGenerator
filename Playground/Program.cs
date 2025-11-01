using BenScr.Security;
public static class Program
{
    public static void Main(string[] args)
    {
        PasswordUtility.Initialize();
        Password pwd = new Password().SetLength(16);
        Console.WriteLine($"Generated Password \"{pwd.Next()}\"");
        Console.WriteLine(PasswordUtility.ClassifyPassword(pwd.Next()));
        Password pwd2 = new Password();
    }
}