using System;
using System.Buffers.Binary;
using System.Threading.Tasks;

namespace HCA_Crypto
{
    public class HCA
    {
        public static readonly int BlockSizeInBytes = 16;
        public static readonly int BlockSizeInBits = 128;
        private static readonly int Radius = 4;
        private static readonly int DoubleRadius = 8;

        public enum ToggleDirection { Left, Right };

        public class HCACryptoKey
        {
            public ToggleDirection Direction { get; private set; }

            public int[] KeyBits { get; private set; }

            private HCACryptoKey(int[] keyBits, int directionBit)
            {
                KeyBits = keyBits;
                Direction = (directionBit == 1) ? ToggleDirection.Right : ToggleDirection.Left;
            }

            public static HCACryptoKey GenerateRandomKey()
            {
                var ruleBitsCount = 256;

                var directionBit = Util.GetRandomNumber(0, 2);

                var keyBits = Util.GetSecureRandomBinaryArray(ruleBitsCount);
                while (Util.SpatialEntropyCalculusForBinary(keyBits) <= 0.75)
                {
                    keyBits = Util.GetSecureRandomBinaryArray(ruleBitsCount);
                }
                return new HCACryptoKey(keyBits, directionBit);
            }
        }

        /// <summary>
        /// Encrypt plaintext using HCA and CTR (counter) mode of operation
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cryptoKey"></param>
        /// <param name="initializationVector"></param>
        /// <returns></returns>
        public static byte[] Encrypt_CTR(byte[] plainText, HCACryptoKey cryptoKey, byte[] initializationVector)
        {
            int blockCount = ((plainText.Length / HCA.BlockSizeInBytes) + 1);
            var paddedPlaintext = new Byte[blockCount * HCA.BlockSizeInBytes];
            Buffer.BlockCopy(plainText, 0, paddedPlaintext, 0, plainText.Length);

            var cipherText = new Byte[paddedPlaintext.Length];

            Rule[] mainRules;
            Rule[] borderRules;
            if (cryptoKey.Direction == ToggleDirection.Left)
            {
                mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateLeftSensibleMarginRules();
            }
            else
            {
                mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateRightSensibleMarginRules();
            }

            Parallel.For(0, blockCount, (counterIdx) =>
            {
                var input = new Byte[HCA.BlockSizeInBytes];
                BinaryPrimitives.WriteInt64BigEndian(input, counterIdx);
                Buffer.BlockCopy(initializationVector, 0, input, BlockSizeInBytes / 2, BlockSizeInBytes / 2);

                var encrypted = BlockEncrypt(input, mainRules, borderRules, iterations: HCA.BlockSizeInBits);

                var src01 = encrypted;
                var src01BeginIdx = 0;
                var src02 = paddedPlaintext;
                var src02BeginIdx = counterIdx * BlockSizeInBytes;
                var xorLength = BlockSizeInBytes;
                var dst = cipherText;
                var dstBeginIdx = counterIdx * BlockSizeInBytes;
                Util.XOR(src01, src01BeginIdx, src02, src02BeginIdx, xorLength, dst, dstBeginIdx);
            });
            return cipherText;
        }

        protected static byte[] BlockEncrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int iterations)
        {
            int[] image = Util.ByteArrayToBinaryArray(initialLattice);
            int[] preImage = new int[image.Length];
            int[] finalLattice;

            int[] swapAux;

            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                var mainRule = mainRules[iterationIdx % mainRules.Length];
                var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                PreImageCalculusBits(image, mainRule, borderRule, iterationIdx, preImage);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
            }
            finalLattice = image;
            return Util.BinaryArrayToByteArray(finalLattice);
        }

        private static void PreImageCalculusBits(int[] image, Rule mainRule, Rule borderRule, int execIdx, int[] preImage)
        {
            var stateLength = image.Length;
            var borderLength = DoubleRadius;
            var borderShift = DoubleRadius;

            if (borderRule.IsLeftSensible) // Cálculo da Direita pra Esquerda
            {
                int neighSum = 0;
                // Região de Borda (Contorno = 2*Raio)
                int borderStartIdx = Util.CircularIdx(-1 * (borderShift * execIdx), stateLength);
                int equivalentSensibleBitInPreImageIdx;
                int borderResultingBitInImageIdx;
                for (int borderStepIdx = 0; borderStepIdx < borderLength; ++borderStepIdx)
                {
                    borderResultingBitInImageIdx = Util.CircularIdx(borderStartIdx + borderStepIdx, stateLength);
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - Radius, stateLength);
                    if (borderRule.Bits[0] == 0)
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = image[borderResultingBitInImageIdx];
                    }
                    else
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = Util.OppositeBit(image[borderResultingBitInImageIdx]);
                    }
                    neighSum |= preImage[equivalentSensibleBitInPreImageIdx];
                    neighSum <<= 1;
                }

                borderResultingBitInImageIdx = borderStartIdx;
                // Região Principal
                for (int mainStepIdx = stateLength - borderLength - 1; mainStepIdx >= 0; mainStepIdx--)
                {
                    borderResultingBitInImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - 1, stateLength);
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - Radius, stateLength);

                    // Apaga o Antigo LSB
                    neighSum >>= 1;
                    if (mainRule.Bits[neighSum] == image[borderResultingBitInImageIdx])
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = 0;
                    }
                    else
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = 1;
                    }
                    // Coloca Novo Bit como MSB
                    neighSum |= (preImage[equivalentSensibleBitInPreImageIdx] << (DoubleRadius));
                }
            }
            else
            {
                int binaryCutMask = 0x7FFFFFFF >> (30 - (DoubleRadius));
                int neighSum = 0;
                int borderResultingBitInImageIdx = 0;
                // Região de Borda (Contorno = 2*Raio)
                int borderStartIdx = Util.CircularIdx((borderShift * execIdx), stateLength);
                int equivalentSensibleBitInPreImageIdx;
                for (int borderStepIdx = 0; borderStepIdx < borderLength; ++borderStepIdx)
                {
                    borderResultingBitInImageIdx = Util.CircularIdx(borderStartIdx + borderStepIdx, stateLength);
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + Radius, stateLength);
                    if (borderRule.Bits[0] == 0)
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = image[borderResultingBitInImageIdx];
                    }
                    else
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = Util.OppositeBit(image[borderResultingBitInImageIdx]);
                    }
                    neighSum |= preImage[equivalentSensibleBitInPreImageIdx];
                    neighSum <<= 1;
                }

                // Região Principal
                for (int mainStepIdx = stateLength - borderLength - 1; mainStepIdx >= 0; mainStepIdx--)
                {
                    borderResultingBitInImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + 1, stateLength);
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + Radius, stateLength);

                    // Apaga o Antigo LSB

                    if (mainRule.Bits[neighSum] == image[borderResultingBitInImageIdx])
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = 0;
                    }
                    else
                    {
                        preImage[equivalentSensibleBitInPreImageIdx] = 1;
                    }
                    // Coloca Novo Bit como novo LSB
                    neighSum |= (preImage[equivalentSensibleBitInPreImageIdx]);
                    // Corta Antigo MSB
                    neighSum <<= 1; neighSum &= binaryCutMask;
                }
            }
        }

        /// <summary>
        /// Decrypt ciphertext using HCA and CTR (counter) mode of operation
        /// </summary>
        /// <param name="cipherText"></param>
        /// <param name="cryptoKey"></param>
        /// <param name="initializationVector"></param>
        /// <returns></returns>
        public static byte[] Decrypt_CTR(byte[] cipherText, HCACryptoKey cryptoKey, byte[] initializationVector)
        {
            var paddedPlaintext = new byte[cipherText.Length];

            Rule[] mainRules;
            Rule[] borderRules;
            if (cryptoKey.Direction == ToggleDirection.Left)
            {
                mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateLeftSensibleMarginRules();
            }
            else
            {
                mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateRightSensibleMarginRules();
            }

            var blockCount = (cipherText.Length / BlockSizeInBytes);
            Parallel.For(0, blockCount, (counterIdx) =>
            {
                var input = new Byte[HCA.BlockSizeInBytes];
                BinaryPrimitives.WriteInt64BigEndian(input, counterIdx);
                Buffer.BlockCopy(initializationVector, 0, input, BlockSizeInBytes / 2, BlockSizeInBytes / 2);

                var encrypted = BlockEncrypt(input, mainRules, borderRules, iterations: HCA.BlockSizeInBits);

                var src01 = encrypted;
                var src01BeginIdx = 0;
                var src02 = cipherText;
                var src02BeginIdx = counterIdx * BlockSizeInBytes;
                var xorLength = BlockSizeInBytes;
                var dst = paddedPlaintext;
                var dstBeginIdx = counterIdx * BlockSizeInBytes;
                Util.XOR(src01, src01BeginIdx, src02, src02BeginIdx, xorLength, dst, dstBeginIdx);
            });
            return paddedPlaintext;
        }

        protected static byte[] BlockDecrypt(byte[] initialLattice, Rule[] mainRules, Rule[] borderRules, int iterations)
        {
            int[] preImage = Util.ByteArrayToBinaryArray(initialLattice);
            int[] image = new int[preImage.Length];
            int[] finalLattice;

            int[] swapAux;

            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                var mainRule = mainRules[(iterations - iterationIdx - 1) % mainRules.Length];
                var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                SequentialEvolveBits(preImage, mainRule, borderRule, (iterations - iterationIdx - 1), image);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
            }
            finalLattice = preImage;
            return Util.BinaryArrayToByteArray(finalLattice);
        }

        private static int[] SequentialEvolveBits(int[] preImage, Rule mainRule, Rule borderRule, int execIdx, int[] image)
        {
            var stateLength = preImage.Length;
            var marginLength = DoubleRadius;
            int binaryCutMask = 0x7FFFFFFF >> (30 - (DoubleRadius));

            int borderNeighStartIdx;
            if (borderRule.IsLeftSensible)
            {
                borderNeighStartIdx = Util.CircularIdx((-1 * (marginLength * execIdx)) - Radius, stateLength);
            }
            else
            {
                borderNeighStartIdx = Util.CircularIdx((marginLength * execIdx) - Radius, stateLength);
            }

            var neighSum = 0;

            // Initial Bits
            var currentInitialBitInPreImageIdx = borderNeighStartIdx;
            for (int initialBitsIdx = 0; initialBitsIdx < marginLength; initialBitsIdx++)
            {
                neighSum |= preImage[currentInitialBitInPreImageIdx];
                currentInitialBitInPreImageIdx = Util.CircularIdx(currentInitialBitInPreImageIdx + 1, stateLength);
                neighSum <<= 1;
            }

            // Border Bits
            var currentBorderBitInPreImageIdx = currentInitialBitInPreImageIdx;
            int resultBitInImageIdx;
            for (int borderStepIdx = 0; borderStepIdx < marginLength; borderStepIdx++)
            {
                resultBitInImageIdx = Util.CircularIdx(currentBorderBitInPreImageIdx - Radius, stateLength);
                neighSum |= preImage[currentBorderBitInPreImageIdx];
                image[resultBitInImageIdx] = borderRule.Bits[neighSum];
                currentBorderBitInPreImageIdx = Util.CircularIdx(currentBorderBitInPreImageIdx + 1, stateLength);
                neighSum <<= 1; neighSum &= binaryCutMask;
            }

            // Main Bits
            var currentMainBitInPreImageIdx = currentBorderBitInPreImageIdx;
            for (int mainStepIdx = 0; mainStepIdx < stateLength - marginLength; mainStepIdx++)
            {
                resultBitInImageIdx = Util.CircularIdx(currentMainBitInPreImageIdx - Radius, stateLength);
                neighSum |= preImage[currentMainBitInPreImageIdx];
                image[resultBitInImageIdx] = mainRule.Bits[neighSum];
                currentMainBitInPreImageIdx = Util.CircularIdx(currentMainBitInPreImageIdx + 1, stateLength);
                neighSum <<= 1; neighSum &= binaryCutMask;
            }
            return image;
        }
    }
}
