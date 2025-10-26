using PasswordGeneratorCS;
public static class Program
{
    public static void Main(string[] args)
    {
        PasswordUtility.Initialize();
        Password pwd = new Password();
        Console.WriteLine($"Generated Password \"{pwd.Next()}\"");
        Password pwd2 = new Password();
    }
}