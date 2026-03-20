using BenScr.Security;
public static class Program
{
    public static void Main(string[] args)
    {
        PasswordUtility.Initialize();
        Password pwd = new Password().SetLength(32);

        pwd.SetIncludeFlags(IncludeFlags.Digits | IncludeFlags.Uppercase);

        Console.WriteLine($"Generated Password \"{pwd.Next()}\"");
        Console.WriteLine(PasswordUtility.ClassifyPassword(pwd.Next()));
    }
}