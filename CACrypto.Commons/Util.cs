using MersenneTwister;
using System.Diagnostics;

namespace CACrypto.Commons
{
    public class Util
    {
        public static int CalculateBlockCount(int plainTextLengthInBytes, int blockSizeInBytes)
        {
            var blockCount = (plainTextLengthInBytes / blockSizeInBytes);
            if (plainTextLengthInBytes % blockSizeInBytes != 0)
            {
                blockCount++;
            }
            return blockCount;
        }

        internal static Rule[] ConvertOctalArrayToR1RuleArray(int[] octalArray, bool isLeftDirected = true)
        {
            Rule[] directedRules;
            if (isLeftDirected)
            {
                directedRules = new Rule[] {
                new Rule("01111000"), // R30
                new Rule("10110100"), // R45
                new Rule("11010010"), // R75
                new Rule("00011110"), // R120
                new Rule("11100001"), // R135
                new Rule("00101101"), // R180
                new Rule("01001011"), // R210
                new Rule("10000111")  // R225
            };
            }
            else
            {
                directedRules = new Rule[] {
                new Rule("01101010"), // R86
                new Rule("10011010"), // R89
                new Rule("10100110"), // R101
                new Rule("01010110"), // R106
                new Rule("10101001"), // R149
                new Rule("01011001"), // R154
                new Rule("01100101"), // R166
                new Rule("10010101")  // R169
            };
            }
            return octalArray.Select(octal => directedRules[octal]).ToArray();
        }

        public static byte[] DeepClone(byte[] oldArray)
        {
            var newArray = new byte[oldArray.Length];
            Buffer.BlockCopy(oldArray, 0, newArray, 0, oldArray.Length);
            return newArray;
        }

        public static string CreateUniqueTempDirectory()
        {
            var uniqueTempDir = Path.GetFullPath(Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString()));
            Directory.CreateDirectory(uniqueTempDir);
            return uniqueTempDir;
        }

        public static void CopyByteArrayTo(byte[] originArray, byte[] dstArray)
        {
            Buffer.BlockCopy(originArray, 0, dstArray, 0, originArray.Length);
        }

        public static int[] CopyLatticeExpandingForWrap(int[] oldLattice, int expansionSize)
        {
            var newLattice = new int[oldLattice.Length + 2 * expansionSize];
            Buffer.BlockCopy(oldLattice, 0, newLattice, expansionSize * sizeof(int), oldLattice.Length * sizeof(int));

            for (int wrapIdx = 0; wrapIdx < expansionSize; ++wrapIdx)
            {
                newLattice[wrapIdx] = newLattice[newLattice.Length - (2 * expansionSize) + wrapIdx];
                newLattice[newLattice.Length - expansionSize + wrapIdx] = newLattice[(2 * expansionSize) + wrapIdx];
            }
            return newLattice;
        }

        public static int[] CopyLatticeShrinking(int[] oldLattice, int shrinkageSize)
        {
            var newLattice = new int[oldLattice.Length - 2 * shrinkageSize];
            Buffer.BlockCopy(oldLattice, shrinkageSize * sizeof(int), newLattice, 0, newLattice.Length * sizeof(int));
            return newLattice;
        }

        public static int GetBitParityFromOctalArray(int[] octalArray)
        {
            bool parity = false;
            foreach (int octal in octalArray)
            {
                if (octal == 1 || octal == 2 || octal == 4 || octal == 7)
                    parity = !parity;
            }
            return parity ? 1 : 0;
        }

        // Usage: Benchmark(() => { /* your code */ }, 100);
        public static void Benchmark(Action act, int iterations, bool newLine = true)
        {
            GC.Collect();
            act.Invoke(); // run once outside of loop to avoid initialization costs
            Stopwatch sw = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
            {
                act.Invoke();
            }
            sw.Stop();
            if (newLine)
                Console.WriteLine(((double)sw.ElapsedMilliseconds / (double)iterations).ToString() + " ms");
            else
                Console.Write(((double)sw.ElapsedMilliseconds / (double)iterations).ToString() + " ms" + Environment.NewLine);
            //Console.WriteLine((sw.ElapsedMilliseconds).ToString() + " ms");
        }

        public static void CopyDirectory(string sourceDirectory, string targetDirectory)
        {
            var diSource = new DirectoryInfo(sourceDirectory);
            var diTarget = new DirectoryInfo(targetDirectory);

            CopyAll(diSource, diTarget);
        }

        public static void CopyAll(DirectoryInfo source, DirectoryInfo target)
        {
            Directory.CreateDirectory(target.FullName);

            // Copy each file into the new directory.
            foreach (FileInfo fi in source.GetFiles())
            {
                fi.CopyTo(Path.Combine(target.FullName, fi.Name), true);
            }

            // Copy each subdirectory using recursion.
            foreach (DirectoryInfo diSourceSubDir in source.GetDirectories())
            {
                DirectoryInfo nextTargetSubDir =
                    target.CreateSubdirectory(diSourceSubDir.Name);
                CopyAll(diSourceSubDir, nextTargetSubDir);
            }
        }

        public static byte[] XOR(byte[] w1, byte[] w2)
        {
            if (w1.Length != w2.Length)
            {
                throw new Exception("Words to be XORed had different size");
            }

            byte[] xorArray = new byte[w1.Length];
            for (int idx = 0; idx < xorArray.Length; ++idx)
            {
                xorArray[idx] = (byte)(w1[idx] ^ w2[idx]);
            }
            return xorArray;
        }

        public static void XOR(byte[] src01, int src01BeginIdx, byte[] src02, int src02BeginIdx, int xorLength, byte[] dst, int dstBeginIdx)
        {
            for (int idx = 0; idx < xorLength; ++idx)
            {
                dst[dstBeginIdx + idx] = (byte)(src01[src01BeginIdx + idx] ^ src02[src02BeginIdx + idx]);
            }
        }

        public static byte[] ChangeRandomBit(byte[] originalArray, bool changeOriginal = false)
        {
            var newArray = changeOriginal ? originalArray : Util.DeepClone(originalArray);

            var randomBitIdx = Util.GetRandomNumber(0, 8 * (originalArray.Length));
            ToggleBit(newArray, randomBitIdx);

            return newArray;
        }

        public static IEnumerable<byte[]> GetSecureRandomByteArrays(int sequenceSize, int sequenceCount)
        {
            return Enumerable
                .Repeat(0, sequenceCount)
                .Select(n => Util.GetSecureRandomByteArray(sequenceSize));
        }

        public static int CountBits(byte[] sequence)
        {
            var sum = 0;
            foreach (var b in sequence)
            {
                for (var i = 0; i < 8; i++)
                {
                    sum += (0x1) & (b >> i);
                }
            }
            return sum;
        }

        public static float SpatialEntropyCalculusForBinary(int[] word)
        {
            double windowSideDec = (Math.Log(word.Length) / Math.Log(2)); //windowSideDec = 7, word.Length = 128
            if (windowSideDec % 1 != 0)
                throw new Exception("Word length must be a power of two");

            int windowSize = (int)windowSideDec; // 7
            int[] ocurrence = new int[word.Length]; // int[128] ocurrence
            for (int wIdx = 0; wIdx < word.Length; wIdx++) // 0 <= wIdx < 128
            {
                //int windowIdx = 8 * word[wIdx] + 4 * word[(wIdx + 1) % word.Length] + 2 * word[(wIdx + 2) % word.Length] + word[(wIdx + 3) % word.Length];

                int windowIdx = 0;
                for (int i = 0; i < windowSize; i++) // 0 <= i < 7
                {
                    windowIdx *= 2;
                    windowIdx += word[(wIdx + i) % word.Length];
                }

                ocurrence[windowIdx]++;
            }

            double entropySum = 0.0D;
            foreach (int ocNumber in ocurrence)
            {
                if (ocNumber != 0)
                {
                    entropySum += (((float)ocNumber / word.Length) * (Math.Log((float)ocNumber / word.Length) / Math.Log(2)));
                }
            }
            return (-1 * (float)entropySum) / windowSize;
        }

        public static float SpatialEntropyCalculusForOctal(int[] binaryWord)
        {
            double windowSideDec = (Math.Log(binaryWord.Length / 3) / Math.Log(2)); //windowSideDec = 7, word.Length = 128
            if (windowSideDec % 1 != 0)
                throw new Exception("Word length must be a power of two");

            int windowSize = (int)windowSideDec; // 7
            int[] ocurrence = new int[binaryWord.Length / 3]; // int[128] ocurrence
            for (int wIdx = 0; wIdx < binaryWord.Length; wIdx++) // 0 <= wIdx < 128
            {
                //int windowIdx = 8 * word[wIdx] + 4 * word[(wIdx + 1) % word.Length] + 2 * word[(wIdx + 2) % word.Length] + word[(wIdx + 3) % word.Length];

                int windowIdx = 0;
                for (int i = 0; i < windowSize; i++) // 0 <= i < 7
                {
                    windowIdx *= 2;
                    windowIdx += binaryWord[(wIdx + i) % binaryWord.Length];
                }

                ocurrence[windowIdx]++;
            } // ocurrence = Array de 2^7 posições 

            double entropySum = 0.0D;
            foreach (int ocNumber in ocurrence)
            {
                if (ocNumber != 0)
                {
                    entropySum += (((float)ocNumber / (3 * binaryWord.Length)) * (Math.Log((float)ocNumber / (3 * binaryWord.Length)) / Math.Log(2)));
                }
            }
            return (-1 * (float)entropySum) / windowSize;
        }

        public static int[] XOR(int[] w1, int[] w2)
        {
            if (w1.Length != w2.Length)
            {
                throw new Exception("Words to be XORed had different size");
            }

            int[] xorArray = new int[w1.Length];
            for (int idx = 0; idx < xorArray.Length; ++idx)
            {
                xorArray[idx] = w1[idx] ^ w2[idx];
            }
            return xorArray;
        }

        public static char[] XOR_str(int[] w1, int[] w2, int cap)
        {
            if (w1.Length != w2.Length)
            {
                throw new Exception("Words to be XORed had different size");
            }

            var xorArray = new char[cap];
            for (int idx = 0; idx < cap; ++idx)
            {
                xorArray[idx] = (((w1[idx] ^ w2[idx]) == 1) ? '1' : '0');
            }
            return xorArray;
        }

        public static object ByteArrayToBinaryString(byte[] plainText)
        {
            return BitArrayToString(ByteArrayToBinaryArray(plainText));
        }

        public static double SampleStandardDeviation(IEnumerable<int> values)
        {
            double ret = 0;
            if (values.Count() > 1)
            {
                //Compute the Average      
                double avg = values.Average();
                //Perform the Sum of (value-avg)_2_2      
                double sum = values.Sum(d => Math.Pow(d - avg, 2));
                //Put it all together      
                ret = Math.Sqrt((sum) / (values.Count() - 1));
            }
            return ret;
        }

        public static double PopulationStandardDeviation(IEnumerable<int> values)
        {
            double avg = values.Average();
            return Math.Sqrt(values.Average(v => Math.Pow(v - avg, 2)));
        }
        public static double PopulationStandardDeviation(IEnumerable<float> values)
        {
            double avg = values.Average();
            return Math.Sqrt(values.Average(v => Math.Pow(v - avg, 2)));
        }

        public static int[] StringToBitArray(string str)
        {
            return str.Select(c => (int)c - 48).ToArray();
        }

        public static string BitArrayToString(int[] bitArray, char falseChar = '0', char trueChar = '1')
        {
            return String.Join("", bitArray.Select(a => (a == 0 ? falseChar : trueChar)).ToArray());
        }

        public static double PopulationStandardDeviation(IEnumerable<double> values)
        {
            double avg = values.Average();
            return Math.Sqrt(values.Average(v => Math.Pow(v - avg, 2)));
        }

        public static IEnumerable<int[]> GenerateAllBinarySequences(int length)
        {
            return
                Enumerable.Range(0, (int)Math.Pow(2, length))
                .Select(n => Convert.ToString(n, 2).PadLeft(length, '0'))
                .Select(nb => nb.ToCharArray().Select(c => c - (int)'0').ToArray());
        }

        public static T GetRandomElement<T>(IList<T> list)
        {
            return list[Randoms.Next(0, list.Count)];
        }

        public static byte[] GetSecureRandomByteArray(int length)
        {
            var byteArray = new byte[length];
            Randoms.FastestInt32.NextBytes(byteArray);
            return byteArray;
        }

        public static int[] GetSecureRandomBinaryArray(int length)
        {
            var binaryArray = new int[(length / 8) * 8];
            var bytes = length / 8;
            var byteArray = new byte[bytes];
            Randoms.FastestInt32.NextBytes(byteArray);
            for (int i = 0; i < bytes; i++)
            {
                var Byte = Convert.ToInt32(byteArray[i]);
                var basePos = i * 8;
                if (Byte >= 128) { binaryArray[basePos] = 1; Byte -= 128; }
                if (Byte >= 64) { binaryArray[basePos + 1] = 1; Byte -= 64; }
                if (Byte >= 32) { binaryArray[basePos + 2] = 1; Byte -= 32; }
                if (Byte >= 16) { binaryArray[basePos + 3] = 1; Byte -= 16; }
                if (Byte >= 8) { binaryArray[basePos + 4] = 1; Byte -= 8; }
                if (Byte >= 4) { binaryArray[basePos + 5] = 1; Byte -= 4; }
                if (Byte >= 2) { binaryArray[basePos + 6] = 1; Byte -= 2; }
                if (Byte >= 1) { binaryArray[basePos + 7] = 1; }
            }
            return binaryArray.Take(length).ToArray();
        }

        public static int[] ByteArrayToBinaryArray(byte[] byteArray)
        {
            int length = byteArray.Length;
            var binaryArray = new int[8 * length];
            for (int i = 0; i < length; i++)
            {
                var Byte = Convert.ToInt32(byteArray[i]);
                var basePos = i * 8;
                if (Byte >= 128) { binaryArray[basePos] = 1; Byte -= 128; }
                if (Byte >= 64) { binaryArray[basePos + 1] = 1; Byte -= 64; }
                if (Byte >= 32) { binaryArray[basePos + 2] = 1; Byte -= 32; }
                if (Byte >= 16) { binaryArray[basePos + 3] = 1; Byte -= 16; }
                if (Byte >= 8) { binaryArray[basePos + 4] = 1; Byte -= 8; }
                if (Byte >= 4) { binaryArray[basePos + 5] = 1; Byte -= 4; }
                if (Byte >= 2) { binaryArray[basePos + 6] = 1; Byte -= 2; }
                if (Byte >= 1) { binaryArray[basePos + 7] = 1; }
            }
            return binaryArray;
        }

        public static byte[] ByteArrayToBinaryByteArray(byte[] byteArray)
        {
            int length = byteArray.Length;
            var binaryArray = new byte[8 * length];
            for (int i = 0; i < length; i++)
            {
                var Byte = Convert.ToInt32(byteArray[i]);
                var basePos = i * 8;
                if (Byte >= 128) { binaryArray[basePos] = 1; Byte -= 128; }
                if (Byte >= 64) { binaryArray[basePos + 1] = 1; Byte -= 64; }
                if (Byte >= 32) { binaryArray[basePos + 2] = 1; Byte -= 32; }
                if (Byte >= 16) { binaryArray[basePos + 3] = 1; Byte -= 16; }
                if (Byte >= 8) { binaryArray[basePos + 4] = 1; Byte -= 8; }
                if (Byte >= 4) { binaryArray[basePos + 5] = 1; Byte -= 4; }
                if (Byte >= 2) { binaryArray[basePos + 6] = 1; Byte -= 2; }
                if (Byte >= 1) { binaryArray[basePos + 7] = 1; }
            }
            return binaryArray;
        }

        public static int[] ByteArrayToBinaryArray(byte[] byteArray, int blockStartIdx, int blockSizeInBytes)
        {
            var binaryArray = new int[8 * blockSizeInBytes];
            for (int i = 0; i < blockSizeInBytes; i++)
            {
                var Byte = Convert.ToInt32(byteArray[blockStartIdx + i]);
                var basePos = i * 8;
                if (Byte >= 128) { binaryArray[basePos] = 1; Byte -= 128; }
                if (Byte >= 64) { binaryArray[basePos + 1] = 1; Byte -= 64; }
                if (Byte >= 32) { binaryArray[basePos + 2] = 1; Byte -= 32; }
                if (Byte >= 16) { binaryArray[basePos + 3] = 1; Byte -= 16; }
                if (Byte >= 8) { binaryArray[basePos + 4] = 1; Byte -= 8; }
                if (Byte >= 4) { binaryArray[basePos + 5] = 1; Byte -= 4; }
                if (Byte >= 2) { binaryArray[basePos + 6] = 1; Byte -= 2; }
                if (Byte >= 1) { binaryArray[basePos + 7] = 1; }
            }
            return binaryArray;
        }

        public static List<int> ByteArrayToBinaryList(byte[] byteArray)
        {
            var byteArrayLength = byteArray.Length;
            var result = new List<int>(8 * byteArray.Length);

            for (int byteIdx = 0; byteIdx < byteArrayLength; ++byteIdx)
            {
                var currentByte = byteArray[byteIdx];

                for (int bitIdx = 7; bitIdx >= 0; --bitIdx)
                {
                    result.Add(((currentByte & (1 << bitIdx)) != 0) ? 1 : 0);
                }
            }
            return result;
        }

        public static byte[] BinaryArrayToByteArray(int[] binaryArray)
        {
            int length = binaryArray.Length;
            if (length % 8 != 0)
                throw new ArgumentException("O Array Binario nao tem comprimento multiplo de 8 pra conversao em Byte");

            var byteLength = length / 8;
            var byteArray = new byte[byteLength];
            for (int i = 0; i < byteLength; i++)
            {
                var byteValue = 0;
                var basePos = i * 8;
                if (binaryArray[basePos] == 1) { byteValue += 128; }
                if (binaryArray[basePos + 1] == 1) { byteValue += 64; }
                if (binaryArray[basePos + 2] == 1) { byteValue += 32; }
                if (binaryArray[basePos + 3] == 1) { byteValue += 16; }
                if (binaryArray[basePos + 4] == 1) { byteValue += 8; }
                if (binaryArray[basePos + 5] == 1) { byteValue += 4; }
                if (binaryArray[basePos + 6] == 1) { byteValue += 2; }
                if (binaryArray[basePos + 7] == 1) { byteValue += 1; }
                byteArray[i] = (byte)byteValue;
            }
            return byteArray;
        }

        public static byte[] BinaryByteArrayToByteArray(byte[] binaryArray)
        {
            int length = binaryArray.Length;
            if (length % 8 != 0)
                throw new ArgumentException("O Array Binario nao tem comprimento multiplo de 8 pra conversao em Byte");

            var byteLength = length / 8;
            var byteArray = new byte[byteLength];
            for (int i = 0; i < byteLength; i++)
            {
                var byteValue = 0;
                var basePos = i * 8;
                if (binaryArray[basePos] == 1) { byteValue += 128; }
                if (binaryArray[basePos + 1] == 1) { byteValue += 64; }
                if (binaryArray[basePos + 2] == 1) { byteValue += 32; }
                if (binaryArray[basePos + 3] == 1) { byteValue += 16; }
                if (binaryArray[basePos + 4] == 1) { byteValue += 8; }
                if (binaryArray[basePos + 5] == 1) { byteValue += 4; }
                if (binaryArray[basePos + 6] == 1) { byteValue += 2; }
                if (binaryArray[basePos + 7] == 1) { byteValue += 1; }
                byteArray[i] = (byte)byteValue;
            }
            return byteArray;
        }

        public static void WriteBinaryArrayToByteArray(int[] binaryArray, byte[] byteArray, int blockStartIdx)
        {
            int length = binaryArray.Length;
            if (length % 8 != 0)
                throw new ArgumentException("O Array Binario nao tem comprimento multiplo de 8 pra conversao em Byte");

            var byteLength = length / 8;
            //var byteArray = new byte[byteLength];
            for (int i = 0; i < byteLength; i++)
            {
                var byteValue = 0;
                var basePos = i * 8;
                if (binaryArray[basePos] == 1) { byteValue += 128; }
                if (binaryArray[basePos + 1] == 1) { byteValue += 64; }
                if (binaryArray[basePos + 2] == 1) { byteValue += 32; }
                if (binaryArray[basePos + 3] == 1) { byteValue += 16; }
                if (binaryArray[basePos + 4] == 1) { byteValue += 8; }
                if (binaryArray[basePos + 5] == 1) { byteValue += 4; }
                if (binaryArray[basePos + 6] == 1) { byteValue += 2; }
                if (binaryArray[basePos + 7] == 1) { byteValue += 1; }
                byteArray[blockStartIdx + i] = (byte)byteValue;
            }
            //return byteArray;
        }

        public static int[] GetSecureRandomOctalArray(int length)
        {
            var octalArray = new int[length];
            int bitsForOctal = 3;
            var bitsInByte = 8;

            // Quantos Bytes Gerados Aleatoriamente será necessário pra conseguir meus Octais
            var bytesLength = ((length * bitsForOctal) - 1) / bitsInByte + 1; // Math.Ceiling
            var byteArray = new byte[bytesLength];
            Randoms.FastestInt32.NextBytes(byteArray);

            return ConvertByteArrayToOctalArray(byteArray);
        }

        public static int[] GetSecureRandomBitArrayWithMinEntropyCoefficient(int keyLengthInBits, double minEntropy = 0.75)
        {
            var randomBits = Util.GetSecureRandomBinaryArray(keyLengthInBits);
            while (Util.SpatialEntropyCalculusForBinary(randomBits) <= 0.75)
            {
                randomBits = Util.GetSecureRandomBinaryArray(keyLengthInBits);
            }
            return randomBits;
        }

        public static int[] GetSecureRandomOctalBitArrayWithMinEntropyCoefficient(int keyLengthInBits, double minEntropy = 0.75)
        {
            int[] octalArray = new int[keyLengthInBits / 3];
            int[] randomBits;
            while (true)
            {
                randomBits = Util.GetSecureRandomBinaryArray(keyLengthInBits);
                var part01 = randomBits.Take(keyLengthInBits / 3).ToArray();
                var part02 = randomBits.Skip(keyLengthInBits / 3).Take(keyLengthInBits / 3).ToArray();
                var part03 = randomBits.Skip(keyLengthInBits / 3).Skip(keyLengthInBits / 3).ToArray();
                var entropy01 = Util.SpatialEntropyCalculusForBinary(part01);
                if (entropy01 <= 0.75)
                    continue;
                var entropy02 = Util.SpatialEntropyCalculusForBinary(part02);
                if (entropy02 <= 0.75)
                    continue;
                var entropy03 = Util.SpatialEntropyCalculusForBinary(part03);
                if (entropy02 > 0.75)
                    break;
            }
            return randomBits;
            //while (Util.SpatialEntropyCalculusForOctal(randomBits) <= 0.75)
            //{
            //    randomBits = Util.GetSecureRandomBinaryArray(keyLengthInBits);
            //}
            /*
            int currentOctalIdx = 0;
            for (int idxBit=0; idxBit < keyLengthInBits; idxBit += 3)
            {
                int currentOctalValue = (randomBits[idxBit] << 2) + (randomBits[idxBit + 1] << 1) + randomBits[idxBit+2];
                octalArray[currentOctalIdx] = currentOctalValue;
                currentOctalIdx++;
            }
            return octalArray;
            */
        }

        public static int[] ConvertBitArrayToOctalArray(int[] bitArray)
        {
            var octalArray = new int[bitArray.Length / 3];
            int currentOctalIdx = 0;
            for (int idxBit = 0; idxBit < bitArray.Length; idxBit += 3)
            {
                int currentOctalValue = (bitArray[idxBit] << 2) + (bitArray[idxBit + 1] << 1) + bitArray[idxBit + 2];
                octalArray[currentOctalIdx] = currentOctalValue;
                currentOctalIdx++;
            }
            return octalArray;
        }

        public static int[] ConvertByteArrayToOctalArray(byte[] byteArray)
        {
            int bitsForOctal = 3;
            var bitsInByte = 8;
            var octalArray = new int[(byteArray.Length * bitsInByte) / bitsForOctal];

            int octalArrayIdx = 0;
            var currentLetterHas = 0;
            foreach (var currentByte in byteArray)
            {
                if (currentLetterHas == 0)
                {
                    octalArray[octalArrayIdx++] = currentByte >> 5;
                    octalArray[octalArrayIdx++] = ((currentByte << 3) & 0xFF) >> 5;
                    octalArray[octalArrayIdx] = ((currentByte << 6) & 0xFF) >> 5;
                    currentLetterHas = 2;
                }
                else if (currentLetterHas == 1)
                {
                    octalArray[octalArrayIdx++] += currentByte >> 6;
                    octalArray[octalArrayIdx++] = ((currentByte << 2) & 0xFF) >> 5;
                    octalArray[octalArrayIdx++] = ((currentByte << 5) & 0xFF) >> 5;
                    currentLetterHas = 0;
                }
                else if (currentLetterHas == 2)
                {
                    octalArray[octalArrayIdx++] += currentByte >> 7;
                    octalArray[octalArrayIdx++] = ((currentByte << 1) & 0xFF) >> 5;
                    octalArray[octalArrayIdx++] = ((currentByte << 4) & 0xFF) >> 5;
                    octalArray[octalArrayIdx] = ((currentByte << 7) & 0xFF) >> 5;
                    currentLetterHas = 1;
                }
            }
            return octalArray;
        }

        [Obsolete("Use GetSecureRandomOctalArray.")]
        public static int[] GetSecureRandomOctalArray_Old(int length)
        {
            var resultArray = new int[length];
            int bitsForOctal = 3;
            var bitsInByte = 8;

            // Quantos Bytes Gerados Aleatoriamente será necessário pra conseguir meus Octais
            var bytesLength = ((length * bitsForOctal) - 1) / bitsInByte + 1; // Math.Ceiling
            var byteArray = new byte[bytesLength];
            Randoms.FastestInt32.NextBytes(byteArray);

            var octalIdx = 0;
            var byteIdx = 0;
            var posValueInByte = 128;
            var posValueInOctal = 4;

            while (octalIdx < length)
            {
                if (byteArray[byteIdx] >= posValueInByte)
                {
                    resultArray[octalIdx] += posValueInOctal;
                    byteArray[byteIdx] -= (byte)posValueInByte;
                }

                if (posValueInOctal == 1) { posValueInOctal = 4; ++octalIdx; }
                else { posValueInOctal /= 2; }

                if (posValueInByte == 1) { posValueInByte = 128; ++byteIdx; }
                else { posValueInByte /= 2; }
            }
            return resultArray;
        }

        public static T GetRandomElement<T>(IEnumerable<T> list)
        {
            // If there are no elements in the collection, return the default value of T
            if (!list.Any())
                return default(T);

            // Guids as well as the hash code for a guid will be unique and thus random        
            int hashCode = Math.Abs(Guid.NewGuid().GetHashCode());
            return list.ElementAt(hashCode % list.Count());
        }

        public static int GetRandomNumber(int minValue, int maxValueExclusive)
        {
            var randomPosIdx = Randoms.Next(minValue, maxValueExclusive);
            return randomPosIdx;
        }

        public static IEnumerable<IEnumerable<T>> GetPermutations<T>(IEnumerable<T> list, int length)
        {
            if (length == 1) return list.Select(t => new T[] { t });

            return GetPermutations(list, length - 1)
                .SelectMany(t => list.Where(e => !t.Contains(e)),
                    (t1, t2) => t1.Concat(new T[] { t2 }));
        }

        public static IEnumerable<T[]> Permutations<T>(T[] values, int fromInd = 0)
        {
            if (fromInd + 1 == values.Length)
                yield return values;
            else
            {
                foreach (var v in Permutations(values, fromInd + 1))
                    yield return v;

                for (var i = fromInd + 1; i < values.Length; i++)
                {
                    SwapValues(values, fromInd, i);
                    foreach (var v in Permutations(values, fromInd + 1))
                        yield return v;
                    SwapValues(values, fromInd, i);
                }
            }
        }

        private static void SwapValues<T>(T[] values, int pos1, int pos2)
        {
            if (pos1 != pos2)
            {
                T tmp = values[pos1];
                values[pos1] = values[pos2];
                values[pos2] = tmp;
            }
        }

        public static int[] LeftShift(int[] array)
        {
            return Enumerable.Concat(array.Skip(1), array.Take(1)).ToArray();
        }

        public static int[] RightShift(int[] array)
        {
            return Enumerable.Concat(array.Skip(array.Length - 1), array.Take(array.Length - 1)).ToArray();
        }

        public static int OppositeBit(int bit)
        {
            if (bit == 0) return 1;
            else return 0;
        }

        public static int CircularIdx(int x, int window)
        {
            if (x >= 0)
            {
                return x % window;
            }
            else
            {
                x = -1 * x;
                x = x % window;
                return window - x;
            }
        }

        public static void Shuffle<T>(IList<T> source)
        {
            var length = source.Count;

            for (var currentIndex = 0; currentIndex < length; currentIndex++)
            {
                var swapIndex = Randoms.Next(currentIndex, length);
                Swap(source, currentIndex, swapIndex);
            }
        }

        public static void ShuffleStrong<T>(IList<T> source)
        {
            var length = source.Count;

            for (var currentIndex = 0; currentIndex < length; currentIndex++)
            {
                var swapIndex = Randoms.Next(currentIndex, length);
                Swap(source, currentIndex, swapIndex);
            }
        }

        public static void Swap<T>(ref T firstObj, ref T secondObj)
        {
            (firstObj, secondObj) = (secondObj, firstObj);
        }

        internal static void Swap<T>(IList<T> source, int firstIndex, int secondIndex)
        {
            var temp = source[firstIndex];
            source[firstIndex] = source[secondIndex];
            source[secondIndex] = temp;
        }

        public static string GetCurrentProjectDirectoryPath()
        {
            var currentProjectName = System.Reflection.Assembly.GetCallingAssembly().GetName().Name;
            var currentDirectory = new DirectoryInfo(AppDomain.CurrentDomain.BaseDirectory);
            while (currentDirectory.Name != currentProjectName)
            {
                currentDirectory = currentDirectory.Parent;
            }
            return currentDirectory.FullName;
        }

        public static void SetBit(byte[] self, int index, bool value)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            self[byteIndex] = (byte)(value ? (self[byteIndex] | mask) : (self[byteIndex] & ~mask));
        }

        public static void ToggleBit(byte[] self, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            self[byteIndex] ^= mask;
        }

        public static bool GetBit(byte[] self, int index)
        {
            int byteIndex = index / 8;
            int bitIndex = index % 8;
            byte mask = (byte)(1 << bitIndex);

            return (self[byteIndex] & mask) != 0;
        }
    }
}