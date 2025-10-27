using System.Globalization;
using System.Numerics;

namespace BenScr.Security.Password
{
    public enum PasswordStrength
    {
        VeryWeak,
        Weak,
        Medium,
        Strong,
        ExtremeStrong
    }

    public enum CrackSpeed : ulong
    {
        VerySlow = 1,
        Slow = 100,
        Medium = 10_000,
        Fast = 1_000_000,
        VeryFast = 100_000_000,
        UltraFast = 10_000_000_000,
        Insane = 1_000_000_000_000
    }

    public enum HashAlgorithm : int
    {
        RawHash = 1,
        PBKDF2_Medium = 200,
        PBKDF2_High = 1000,
        Bcrypt_12 = 800,
        Argon2id_64MB_t3 = 20000,
        Argon2id_512MB_t4 = 200000
    }

    public static class PasswordUtility
    {
        private static string[] passwords;
        private static string[] names;

        public static void Initialize()
        {
            passwords = File.ReadAllLines("Resources/Passwords.txt");
            names = File.ReadAllLines("Resources/Names.txt");
        }

        internal static string FormattedValue(BigInteger value)
        {
            var culture = CultureInfo.InvariantCulture;
            decimal number;

            string suffix;
            if (value < 1_000)
            {
                return value.ToString(culture);
            }
            else if (value < 1_000_000)
            {
                number = (decimal)value / 1_000m;
                suffix = "Thousand";
            }
            else if (value < 1_000_000_000)
            {
                number = (decimal)value / 1_000_000m;
                suffix = "Million";
            }
            else if (value < 1_000_000_000_000)
            {
                number = (decimal)value / 1_000_000_000m;
                suffix = "Billion";
            }
            else if (value < 1_000_000_000_000_000)
            {
                number = (decimal)value / 1_000_000_000_000m;
                suffix = "Trillion";
            }
            else
            {
                return value.ToString("0.###E+0", culture);
            }


            string formatted = number % 1 == 0 ? number.ToString("0", culture) : number.ToString("0.##", culture);

            return formatted + " " + suffix;
        }
        public static string RequiredTimeToCrack(BigInteger combinations, CrackSpeed attackerSpeed = CrackSpeed.Medium, HashAlgorithm algorithm = HashAlgorithm.RawHash)
        {
            if (combinations <= 0)
                return "0 seconds";


            BigInteger attempts = (combinations + 1) / 2;
            double baseRate = Convert.ToDouble((ulong)attackerSpeed);


            double multiplier = (double)algorithm;
            if (multiplier <= 0) multiplier = 1.0;


            double effectiveRateDouble = baseRate / multiplier;
            if (effectiveRateDouble < 1.0) effectiveRateDouble = 1.0;


            ulong effectiveRate;
            if (effectiveRateDouble >= (double)ulong.MaxValue)
                effectiveRate = ulong.MaxValue;
            else
                effectiveRate = (ulong)Math.Floor(effectiveRateDouble);

            BigInteger rate = new BigInteger(effectiveRate);


            if (rate <= 0) rate = BigInteger.One;

            BigInteger totalSeconds = BigInteger.DivRem(attempts, rate, out BigInteger remainderAttempts);

            BigInteger millis = 0;
            if (remainderAttempts > 0)
                millis = (remainderAttempts * 1000) / rate;


            BigInteger secPerMinute = 60;
            BigInteger secPerHour = 60 * secPerMinute;
            BigInteger secPerDay = 24 * secPerHour;
            BigInteger secPerYear = 365 * secPerDay;

            BigInteger years = totalSeconds / secPerYear;
            BigInteger rem = totalSeconds % secPerYear;

            BigInteger days = rem / secPerDay;
            rem = rem % secPerDay;

            BigInteger hours = rem / secPerHour;
            rem = rem % secPerHour;

            BigInteger minutes = rem / secPerMinute;
            BigInteger seconds = rem % secPerMinute;

            var culture = CultureInfo.InvariantCulture;


            string secsFormatted;
            if (millis > 0)
            {
                decimal secWithMs = (decimal)seconds + ((decimal)millis / 1000m);
                secsFormatted = secWithMs % 1 == 0
                    ? ((long)secWithMs).ToString(culture)
                    : secWithMs.ToString("0.###", culture);
            }
            else
            {
                secsFormatted = seconds.ToString(culture);
            }

            var parts = new List<string>();
            if (years > 0) parts.Add($"{FormattedValue(years)} year{(years == 1 ? "" : "s")}");
            if (days > 0) parts.Add($"{days.ToString(culture)} day{(days == 1 ? "" : "s")}");
            if (hours > 0) parts.Add($"{hours.ToString(culture)} hour{(hours == 1 ? "" : "s")}");
            if (minutes > 0) parts.Add($"{minutes.ToString(culture)} minute{(minutes == 1 ? "" : "s")}");
            if (parts.Count == 0)
            {
                if (totalSeconds == 0 && millis == 0)
                    return "less than 1 millisecond";

                parts.Add($"{secsFormatted} second{(secsFormatted == "1" ? "" : "s")}");
            }
            else
            {
                if (seconds > 0 || millis > 0)
                    parts.Add($"{secsFormatted} second{(secsFormatted == "1" ? "" : "s")}");
            }

            return string.Join(", ", parts);
        }
        public static int DifferentCharsCount(string password)
        {
            if (string.IsNullOrEmpty(password))
                return 0;

            return password.Distinct().Count();
        }
        public static string ClassifyPassword(string password)
        {
            float strength = GetPasswordStrength(password);
            bool containsName = names.Contains(password, StringComparer.OrdinalIgnoreCase);

            if (passwords.Contains(password.ToLower()))
            {
                return "one of the most common passwords" + (containsName ? " and contains a name" : "");
            }
            else if (containsName)
            {
                return "contains a name";
            }

            int differentChars = DifferentCharsCount(password);

            if (differentChars <= 2)
            {
                return "very weak since it follows a very simple pattern";
            }
            else if (differentChars <= 3)
            {
                return "weak since it follows a very simple pattern";
            }


            if (strength < 0.1f) return "Very Weak";
            else if (strength < 0.2f) return "Weak";
            else if (strength < 0.3f) return "Bad";
            else if (strength < 0.4f) return "Not Safe";
            else if (strength < 0.5f) return "Medium";
            else if (strength < 0.6f) return "Okay";
            else if (strength < 0.7f) return "Safe";
            else if (strength < 0.8f) return "Very Safe";
            else if (strength <= 0.9f) return "Extreme Safe";
            else if (strength > 0.9f) return "Ultra Safe";

            return "No classification found";
        }

        public static BigInteger PossibleCombinations(int passwordLength, int charsetLength)
        {
            if (charsetLength <= 0 || passwordLength <= 0)
                return BigInteger.Zero;

            BigInteger result = BigInteger.One;

            for (int i = 0; i < passwordLength; i++)
            {
                result *= charsetLength;
            }

            return result;
        }

        public static BigInteger PossibleCombinations(string password)
        {
            int charsetLength = Password.CharsetLength(password);
            int passwordLength = password.Length;

            if (charsetLength <= 0 || passwordLength <= 0)
                return BigInteger.Zero;

            BigInteger result = BigInteger.One;

            for (int i = 0; i < passwordLength; i++)
            {
                result *= charsetLength;
            }

            return result;
        }


        // Returns a value from 0 to 1 defining the strength of the Password 0 = Low Strength 1 = High Strength
        public static float GetPasswordStrength(string password)
            => GetPasswordStrength(Password.CharsetLength(password), password.Length);

        public static float GetPasswordStrength(BigInteger combinations, float targetBits = 128.0f)
        {
            if (combinations <= 1)
                return 0f;

            double bits = BigInteger.Log(combinations, 2);
            float strength = (float)(bits / targetBits);
            return Math.Clamp(strength, 0.0f, 1.0f);
        }
    }
}
