using System.Security.Cryptography;

namespace BenScr.Security
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

    public sealed class Password
    {
        public static int MinPasswordLength = 16;

        private const string DIGITS = "0123456789";
        private const string UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        private const string LOWER = "abcdefghijklmnopqrstuvwxyz";
        private const string SYMBOLS = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

        private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();

        private string includeCharset = string.Empty;
        private string excludeCharset = string.Empty;

        private int length = MinPasswordLength;
        private IncludeFlags flags = IncludeFlags.All;

        public static Password Default() => new Password();
        public Password(int length = 16)
        {
            this.length = Math.Clamp(length, MinPasswordLength, 4096);
        }

        public Password(int length, IncludeFlags flag, string includeCharset = "", string excludeCharset = "")
        {
            flags = flag;
            this.length = Math.Clamp(length, MinPasswordLength, 4096);

            this.includeCharset = includeCharset;
            this.excludeCharset = excludeCharset;
        }

        public Password(int length, bool upper, bool lower, bool digits, bool symbols, string includeCharset = "", string excludeCharset = "")
        {
            flags = IncludeFlags.None;
            this.length = Math.Clamp(length, MinPasswordLength, 4096);

            if (upper) flags |= IncludeFlags.Uppercase;
            if (lower) flags |= IncludeFlags.Lowercase;
            if (digits) flags |= IncludeFlags.Digits;
            if (symbols) flags |= IncludeFlags.Symbols;

            this.includeCharset = includeCharset;
            this.excludeCharset = excludeCharset;
        }

        public Password SetLength(int length)
        {
            this.length = Math.Clamp(length, MinPasswordLength, 4096);
            return this;
        }
        public Password SetIncludeFlags(IncludeFlags flags)
        {
            this.flags = flags;
            return this;
        }
        public Password RemoveIncludeFlags(IncludeFlags flags)
        {
            this.flags &= ~flags;
            return this;
        }

        public Password SetIncludeCharset(string charset)
        {
            includeCharset = charset;
            return this;
        }
        public Password SetExcludeCharset(string charset)
        {
            excludeCharset = charset;
            return this;
        }


        private char[] BuildCharset()
        {
            var charSet = new HashSet<char>();

            foreach (var c in includeCharset) charSet.Add(c);

            if (flags.HasFlag(IncludeFlags.Digits)) foreach (var c in DIGITS) charSet.Add(c);
            if (flags.HasFlag(IncludeFlags.Uppercase)) foreach (var c in UPPER) charSet.Add(c);
            if (flags.HasFlag(IncludeFlags.Lowercase)) foreach (var c in LOWER) charSet.Add(c);
            if (flags.HasFlag(IncludeFlags.Symbols)) foreach (var c in SYMBOLS) charSet.Add(c);

            foreach (var c in excludeCharset) charSet.Remove(c);

            if (charSet.Count == 0) throw new InvalidOperationException("Charset is empty");
            return charSet.ToArray();
        }

        private static int NextIndex(int maxExclusive) => RandomNumberGenerator.GetInt32(maxExclusive);

        public string Next()
        {
            if (length <= 0) throw new InvalidOperationException($"Invalid length: {length}");

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
