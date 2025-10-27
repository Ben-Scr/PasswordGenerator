# Password Generator
An extremly safe C# `Net 9.0` Password Generator

## Usage
- Generation of Safe Password
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
