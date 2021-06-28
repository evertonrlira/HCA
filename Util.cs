using MersenneTwister;
using System;
using System.Collections.Generic;
using System.Linq;

namespace HCA_Crypto
{
    public class Util
    {
        public static CryptoRandom RNG = new CryptoRandom();

        public static void XOR(byte[] src01, int src01BeginIdx, byte[] src02, int src02BeginIdx, int xorLength, byte[] dst, int dstBeginIdx)
        {
            for (int idx = 0; idx < xorLength; ++idx)
            {
                dst[dstBeginIdx + idx] = (byte)(src01[src01BeginIdx + idx] ^ src02[src02BeginIdx + idx]);
            }
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

        public static int GetRandomNumber(int minValue, int maxValueExclusive)
        {
            var randomPosIdx = RNG.Next(minValue, maxValueExclusive);
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
    }
}
