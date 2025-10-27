using Konscious.Security.Cryptography;
using System.Security.Cryptography;
using System.Text;

namespace BenScr.Security
{
    public sealed class PasswordHasher
    {
        private int iterations = 3;
        private int memoryKB = 64 * 1024;
        private int parallelCoresLength = 2;
        private int saltLength = 16;
        private int hashLength = 32;

        public static PasswordHasher Default() => new PasswordHasher();

        public PasswordHasher HashLength(int length)
        {
            hashLength = Math.Clamp(length, 16, 64);
            return this;
        }
        public PasswordHasher Iterations(int count)
        {
            iterations = Math.Clamp(count, 1, 10);
            return this;
        }
        public PasswordHasher MemoryKB(int kb)
        {
            memoryKB = Math.Clamp(kb, 8, 512) * 1024;
            return this;
        }
        public PasswordHasher Parallel(int length)
        {
            parallelCoresLength = Math.Clamp(length, 1, 12);
            return this;
        }
        public PasswordHasher SaltLength(int length)
        {
            saltLength = Math.Clamp(length, 16, 64);
            return this;
        }

        public string ToHash(string password)
        {
            if (password is null) throw new ArgumentNullException(nameof(password));


            byte[] salt = new byte[saltLength];
            RandomNumberGenerator.Fill(salt);


            byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
            byte[] hash = ComputeArgon2id(pwdBytes, salt, memoryKB, iterations, parallelCoresLength, hashLength);


            string saltB64 = Convert.ToBase64String(salt);
            string hashB64 = Convert.ToBase64String(hash);
            return $"$argon2id$v=19$m={memoryKB},t={iterations},p={parallelCoresLength}${saltB64}${hashB64}";
        }
        public bool Verify(string hash, string password)
        {
            if (hash is null) throw new ArgumentNullException(nameof(hash));
            if (password is null) throw new ArgumentNullException(nameof(password));

            if (!TryParseFormattedHash(hash, out var pars))
                return false;

            byte[] pwdBytes = Encoding.UTF8.GetBytes(password);
            byte[] computed = ComputeArgon2id(
                pwdBytes,
                pars.Salt,
                pars.MemoryKb,
                pars.Iterations,
                pars.Parallelism,
                pars.HashLength
            );

            return FixedTimeEquals(computed, pars.Hash);
        }
        private byte[] ComputeArgon2id(byte[] password,byte[] salt,int memoryKb,int iterations,int parallelism, int hashLength)
        {
            var argon2 = new Argon2id(password)
            {
                Salt = salt,
                DegreeOfParallelism = Math.Max(1, parallelism),
                Iterations = Math.Max(1, iterations),
                MemorySize = Math.Max(8 * 1024, memoryKb)
            };
            return argon2.GetBytes(hashLength);
        }
        private bool TryParseFormattedHash(string formatted, out ParsedHash pars)
        {
            pars = default;


            var parts = formatted.Split('$', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length != 5) return false;
            if (!parts[0].Equals("argon2id", StringComparison.OrdinalIgnoreCase)) return false;
            if (!parts[1].Equals("v=19", StringComparison.OrdinalIgnoreCase)) return false;


            int memoryKb = 0, iterations = 0, parallel = 0;
            foreach (var kv in parts[2].Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var pair = kv.Split('=', 2);
                if (pair.Length != 2) return false;
                switch (pair[0])
                {
                    case "m": if (!int.TryParse(pair[1], out memoryKb)) return false; break;
                    case "t": if (!int.TryParse(pair[1], out iterations)) return false; break;
                    case "p": if (!int.TryParse(pair[1], out parallel)) return false; break;
                    default: return false;
                }
            }

            byte[] salt, hash;
            try
            {
                salt = Convert.FromBase64String(parts[3]);
                hash = Convert.FromBase64String(parts[4]);
            }
            catch
            {
                return false;
            }

            pars = new ParsedHash
            {
                MemoryKb = memoryKb,
                Iterations = iterations,
                Parallelism = parallel,
                Salt = salt,
                Hash = hash,
                HashLength = hash.Length
            };
            return true;
        }
        private bool FixedTimeEquals(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++)
                diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private struct ParsedHash
        {
            public int MemoryKb;
            public int Iterations;
            public int Parallelism;
            public int HashLength;
            public byte[] Salt;
            public byte[] Hash;
        }
    }
}
