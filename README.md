# Password Generator
A C# `Net 9.0` Password Generator

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
## Example Project
An example Project using this PasswordGenerator is [`PasswordGeneratorWPF`](https://github.com/Ben-Scr/PasswordGeneratorWPF)
