# Password Generator
A C# `.Net 9.0` Password Generator

## Usage
- Generation of Safe Passwords
- Hashing of Passwords
- Utitlies for Classifying Passwords and detecting common used passwords

## How to use
```csharp
using BenScr.Security;
```
```csharp
Password pwd = new Password();
pwd.SetIncludeFlags(IncludeFlags.Digits | IncludeFlags.Uppercase);
pwd.SetLength(32);
string password = pwd.Next();

PasswordHasher hasher = new PasswordHasher();
string hash = hasher.ToHash(password);
```
## External Libraries
- [Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography/tree/master/Konscious.Security.Cryptography.Argon2) - Hashing Algorithm

## Example Project
An example Project using this PasswordGenerator is [`PasswordGeneratorWPF`](https://github.com/Ben-Scr/PasswordGeneratorWPF)
