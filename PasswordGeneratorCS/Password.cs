using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace PasswordGeneratorCS
{
    [Flags]
    public enum IncludeFlags
    {
        None = 0,
        Digits = 1 << 0,
        Uppercase = 1 << 1,
        Lowercase = 1 << 2,
        Symbols = 1 << 3,
        All = Digits | Uppercase | Lowercase | Symbols
    }

    public class Password
    {
        private const int MIN_PWD_LENGTH = 16;
        private const string DIGITS = "0123456789";
        private const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string LOWER = "abcdefghijklmnopqrstuvwxyz";
        private const string SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        private string includeCharset = string.Empty;
        private string excludeCharset = string.Empty;

        private int length = MIN_PWD_LENGTH;
        private IncludeFlags flags = IncludeFlags.All;

        public void SetLength(int length)
        {
            this.length = Math.Clamp(length, MIN_PWD_LENGTH, 4096);
        }
        public void SetFlags(IncludeFlags flags)
        {
            this.flags = flags;
        }
        public void RemoveFlags(IncludeFlags flags)
        {
            this.flags &= ~flags;
        }

        public void IncludeCharset(string charset) => includeCharset = charset;
        public void ExcludeCharset(string charset) => excludeCharset = charset;


        private char[] BuildCharset()
        {
            var set = new HashSet<char>();

            foreach (var c in includeCharset) set.Add(c);

            if (flags.HasFlag(IncludeFlags.Digits)) foreach (var c in DIGITS) set.Add(c);
            if (flags.HasFlag(IncludeFlags.Uppercase)) foreach (var c in UPPER) set.Add(c);
            if (flags.HasFlag(IncludeFlags.Lowercase)) foreach (var c in LOWER) set.Add(c);
            if (flags.HasFlag(IncludeFlags.Symbols)) foreach (var c in SYMBOLS) set.Add(c);

            foreach (var c in excludeCharset) set.Remove(c);

            if (set.Count == 0) throw new InvalidOperationException("Charset empty");
            return set.ToArray();
        }

        private static int NextIndex(int maxExclusive) => RandomNumberGenerator.GetInt32(maxExclusive);

        public string Next()
        {
            if (length <= 0) throw new InvalidOperationException("Invalid length");

            var charset = BuildCharset();
            var required = new List<char>();

            if (flags.HasFlag(IncludeFlags.Lowercase)) required.Add(LOWER[NextIndex(LOWER.Length)]);
            if (flags.HasFlag(IncludeFlags.Uppercase)) required.Add(UPPER[NextIndex(UPPER.Length)]);
            if (flags.HasFlag(IncludeFlags.Digits)) required.Add(DIGITS[NextIndex(DIGITS.Length)]);
            if (flags.HasFlag(IncludeFlags.Symbols)) required.Add(SYMBOLS[NextIndex(SYMBOLS.Length)]);

            for (int i = 0; i < required.Count; i++)
            {
                while (Array.IndexOf(charset, required[i]) < 0)
                {
                    char newC = required[i];
                    if (LOWER.Contains(required[i])) newC = LOWER[NextIndex(LOWER.Length)];
                    else if (UPPER.Contains(required[i])) newC = UPPER[NextIndex(UPPER.Length)];
                    else if (DIGITS.Contains(required[i])) newC = DIGITS[NextIndex(DIGITS.Length)];
                    else newC = SYMBOLS[NextIndex(SYMBOLS.Length)];
                    required[i] = newC;
                }
            }

            var result = new char[length];
            int pos = 0;

            foreach (var c in required)
            {
                if (pos < result.Length) result[pos++] = c;
            }


            while (pos < result.Length)
                result[pos++] = charset[NextIndex(charset.Length)];

            for (int i = result.Length - 1; i > 0; i--)
            {
                int j = NextIndex(i + 1);
                (result[i], result[j]) = (result[j], result[i]);
            }

            return new string(result);
        }

        internal static int CharsetLength(string password)
        {
            int size = 0;
            if (password.IndexOfAny(LOWER.ToCharArray()) >= 0) size += LOWER.Length;
            if (password.IndexOfAny(UPPER.ToCharArray()) >= 0) size += UPPER.Length;
            if (password.IndexOfAny(DIGITS.ToCharArray()) >= 0) size += DIGITS.Length;
            if (password.IndexOfAny(SYMBOLS.ToCharArray()) >= 0) size += SYMBOLS.Length;
            return size;
        }
    }
}
