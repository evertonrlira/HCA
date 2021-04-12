using CA_1D.Algorithm.Common;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CA_1D.Algorithm
{
    public class HCA : ICACryptoMethod
    {
        const int _BlockSizeInBytes = 16;

        public int Radius { get; }

        public enum ToggleDirection { Left, Right };

        public class HCACryptoKey
        {
            public ToggleDirection Direction { get; private set; }

            public int[] KeyBits { get; private set; }

            public int Radius { get; private set; }

            private HCACryptoKey(int[] keyBits, int directionBit, int radius)
            {
                KeyBits = keyBits;
                Direction = (directionBit == 1) ? ToggleDirection.Right : ToggleDirection.Left;
                Radius = radius;
            }

            public static HCACryptoKey GenerateRandomKey(int radius = 4)
            {
                var ruleLengthForRadius = Rule.GetRuleLengthForRadius(radius);

                var directionBit = Util.GetRandomNumber(0, 2);
                int[] keyBits;
                if (radius == 1)
                {
                    var validNuclei = new int[][] {
                    new int[] { 1, 0, 1, 1 },
                    new int[] { 0, 1, 1, 0 },
                    new int[] { 0, 0, 1, 1 },
                    new int[] { 0, 0, 1, 0 },
                    new int[] { 1, 1, 0, 0 },
                    new int[] { 0, 0, 0, 1 },
                    new int[] { 0, 1, 0, 0 },
                    new int[] { 1, 0, 0, 0 },
                    new int[] { 1, 1, 0, 1 },
                    new int[] { 1, 1, 1, 0 },
                    new int[] { 1, 0, 0, 1 },
                    new int[] { 0, 1, 1, 1 } };
                    keyBits = validNuclei[Util.GetRandomNumber(0, 12)];
                }
                else
                {
                    keyBits = Util.GetSecureRandomBinaryArray(ruleLengthForRadius / 2);
                    while (Util.SpatialEntropyCalculusForBinary(keyBits) <= 0.75)
                    {
                        keyBits = Util.GetSecureRandomBinaryArray(ruleLengthForRadius / 2);
                    }
                }
                return new HCACryptoKey(keyBits, directionBit, radius);
            }

            public static HCACryptoKey FromCACryptoKey(CACryptoKey cryptoKey)
            {
                var keyBits = cryptoKey.Bits.Take(cryptoKey.Bits.Length - 1).ToArray();
                int directionBit = cryptoKey.Bits[cryptoKey.Bits.Length - 1];
                var radius = Rule.GetRadiusForRuleLength(2 * keyBits.Length);
                return new HCACryptoKey(keyBits, directionBit, radius);
            }
        }

        public override CACryptoKey GenerateRandomGenericKey(int blockSizeInBytes)
        {
            var ruleLengthForRadius = Rule.GetRuleLengthForRadius(Radius);

            int[] randomBits;
            if (Radius == 1)
            {
                var validNuclei = new int[][] { 
                    new int[] { 1, 0, 1, 1 }, 
                    new int[] { 0, 1, 1, 0 },
                    new int[] { 0, 0, 1, 1 },
                    new int[] { 0, 0, 1, 0 },
                    new int[] { 1, 1, 0, 0 },
                    new int[] { 0, 0, 0, 1 },
                    new int[] { 0, 1, 0, 0 },
                    new int[] { 1, 0, 0, 0 },
                    new int[] { 1, 1, 0, 1 },
                    new int[] { 1, 1, 1, 0 },
                    new int[] { 1, 0, 0, 1 },
                    new int[] { 0, 1, 1, 1 } };
                randomBits = validNuclei[Util.GetRandomNumber(0, 12)];
            }
            else
            {
                randomBits = Util.GetSecureRandomBinaryArray(ruleLengthForRadius / 2);
                while (Util.SpatialEntropyCalculusForBinary(randomBits) <= 0.75)
                {
                    randomBits = Util.GetSecureRandomBinaryArray(ruleLengthForRadius / 2);
                }
            }

            var directionBit = Util.GetRandomNumber(0, 2);
            List<int> keyBits = new List<int>(randomBits);
            keyBits.Add(directionBit);
            return CACryptoKey.FromBits(keyBits.ToArray());
        }

        public HCA(int radius)
        {
            Radius = radius;
        }

        public override string GetMethodName()
        {
            return string.Format("HCA (RAIO {0})", Radius);
        }

        public override string GetFolderNameForGeneratedFiles()
        {
            return string.Format("HCA_R{0}", Radius);
        }

        public override int GetDefaultBlockSizeInBits()
        {
            return 8 * _BlockSizeInBytes;
        }

        public override byte[] Encrypt(byte[] plainText, CACryptoKey cryptoKey, byte[] initializationVector, CipherMode cipherMode)
        {
            //if (plainText.Length % BlockSizeInBytes != 0)
            //{
            //    throw new Exception("Padding needed and still not implemented");
            //}

            int BlockSizeInBytes = (plainText.Length < _BlockSizeInBytes) ? plainText.Length : _BlockSizeInBytes;
            int BlockSizeInBits = 8 * BlockSizeInBytes;

            if ((cipherMode == CipherMode.CBC) &&(initializationVector.Length % BlockSizeInBytes != 0))
            {
                throw new ArgumentException("The IV length must be equal to the block size");
            }

            if (cipherMode != CipherMode.CBC && cipherMode != CipherMode.ECB)
            {
                throw new ArgumentException("Requested CipherMode not implemented");
            }

            var hcaCryptoKey = HCACryptoKey.FromCACryptoKey(cryptoKey);
            var blockCount = (plainText.Length / BlockSizeInBytes);
            var cipherText = new byte[blockCount * BlockSizeInBytes];

            Rule[] mainRules;
            Rule[] borderRules;
            if (hcaCryptoKey.Direction == ToggleDirection.Left)
            {
                mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(hcaCryptoKey.KeyBits);
                borderRules = Rule.GenerateLeftSensibleMarginRulesForRadius(hcaCryptoKey.Radius);
            }
            else
            {
                mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(hcaCryptoKey.KeyBits);
                borderRules = Rule.GenerateRightSensibleMarginRulesForRadius(hcaCryptoKey.Radius);
            }

            if (cipherMode == CipherMode.ECB)
            {
                Parallel.For(0, blockCount, (blockIdx) => {
                    BlockEncrypt(plainText, blockIdx * BlockSizeInBytes, BlockSizeInBytes, cipherText, mainRules, borderRules, hcaCryptoKey.Radius, iterations: BlockSizeInBits);
                    /*
                    var newBlock = new byte[BlockSizeInBytes];
                    Buffer.BlockCopy(plainText, blockIdx * BlockSizeInBytes, newBlock, 0, BlockSizeInBytes);

                    newBlock = BlockEncrypt(newBlock, hcaCryptoKey, iterations: BlockSizeInBits);
                    Buffer.BlockCopy(newBlock, 0, cipherText, blockIdx * BlockSizeInBytes, BlockSizeInBytes);
                    */
                });
            }
            else if (cipherMode == CipherMode.CBC)
            {
                var xorVector = Util.CloneByteArray(initializationVector);

                for (int blockIdx = 0; blockIdx < blockCount; ++blockIdx)
                {
                    var newBlock = new byte[BlockSizeInBytes];
                    Buffer.BlockCopy(plainText, blockIdx * BlockSizeInBytes, newBlock, 0, BlockSizeInBytes);

                    if (cipherMode == CipherMode.CBC)
                    {
                        for (int byteIdx = 0; byteIdx < BlockSizeInBytes; ++byteIdx)
                        {
                            newBlock[byteIdx] ^= xorVector[byteIdx];
                        }
                    }

                    newBlock = BlockEncrypt_Old(newBlock, hcaCryptoKey, iterations: BlockSizeInBits);
                    if (cipherMode == CipherMode.CBC)
                        Buffer.BlockCopy(newBlock, 0, xorVector, 0, BlockSizeInBytes);
                    Buffer.BlockCopy(newBlock, 0, cipherText, blockIdx * BlockSizeInBytes, BlockSizeInBytes);
                }
            }
            return cipherText;
        }

        public override byte[] EncryptNoSplit(byte[] plaintext, CACryptoKey cryptoKey)
        {
            int BlockSizeInBytes = plaintext.Length;
            int BlockSizeInBits = 8 * BlockSizeInBytes;

            var hcaCryptoKey = HCACryptoKey.FromCACryptoKey(cryptoKey);
            var cipherText = BlockEncrypt_Old(plaintext, hcaCryptoKey, iterations: BlockSizeInBits);

            return cipherText;
        }

        protected static void BlockEncrypt(byte[] plaintext, int blockStartIdx, int blockSizeInBytes, byte[] ciphertext, Rule[] mainRules, Rule[] borderRules, int radius, int iterations)
        {
            //if (initialLattice.Length != BlockSizeInBytes)
            //{
            //    throw new ArgumentException("The initial lattice length must be equal to the block size");
            //}

            int[] image = Util.ByteArrayToBinaryArray(plaintext, blockStartIdx, blockSizeInBytes);
            int[] preImage = new int[image.Length];
            int[] finalLattice;

            int[] swapAux;

            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                var mainRule = mainRules[iterationIdx % mainRules.Length];
                var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                PreImageCalculusBits(image, mainRule, borderRule, radius, iterationIdx, preImage);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
            }
            finalLattice = image;
            Util.WriteBinaryArrayToByteArray(finalLattice, ciphertext, blockStartIdx);
        }

        protected static byte[] BlockEncrypt_Old(byte[] initialLattice, HCACryptoKey cryptoKey, int iterations)
        {
            //if (initialLattice.Length != BlockSizeInBytes)
            //{
            //    throw new ArgumentException("The initial lattice length must be equal to the block size");
            //}

            int[] image = Util.ByteArrayToBinaryArray(initialLattice);
            int[] preImage = new int[image.Length];
            int[] finalLattice;
            
            int[] swapAux;

            Rule[] mainRules;
            Rule[] borderRules;
            if (cryptoKey.Direction == ToggleDirection.Left)
            {
                mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateLeftSensibleMarginRulesForRadius(cryptoKey.Radius);
            }
            else
            {
                mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateRightSensibleMarginRulesForRadius(cryptoKey.Radius);
            }

            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                var mainRule = mainRules[iterationIdx % mainRules.Length];
                var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                PreImageCalculusBits(image, mainRule, borderRule, cryptoKey.Radius, iterationIdx, preImage);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
            }
            finalLattice = image;
            return Util.BinaryArrayToByteArray(finalLattice);
        }

        private static void PreImageCalculusBits(int[] image, Rule mainRule, Rule borderRule, int radius, int execIdx, int[] preImage)
        {
            var stateLength = image.Length;
            var borderLength = 2 * radius;
            var borderShift = 2 * radius;

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
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - radius, stateLength);
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
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx - radius, stateLength);

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
                    neighSum |= (preImage[equivalentSensibleBitInPreImageIdx] << (2*radius));
                }
            }
            else
            {
                int binaryCutMask = 0x7FFFFFFF >> (30 - (2 * radius));
                int neighSum = 0;
                int borderResultingBitInImageIdx = 0;
                // Região de Borda (Contorno = 2*Raio)
                int borderStartIdx = Util.CircularIdx((borderShift * execIdx), stateLength);
                int equivalentSensibleBitInPreImageIdx;
                for (int borderStepIdx = 0; borderStepIdx < borderLength; ++borderStepIdx)
                {
                    borderResultingBitInImageIdx = Util.CircularIdx(borderStartIdx + borderStepIdx, stateLength);
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + radius, stateLength);
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
                    equivalentSensibleBitInPreImageIdx = Util.CircularIdx(borderResultingBitInImageIdx + radius, stateLength);

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

        public override byte[] Decrypt(byte[] cipherText, CACryptoKey cryptoKey, byte[] initializationVector, CipherMode cipherMode)
        {
            int BlockSizeInBytes = (cipherText.Length < _BlockSizeInBytes) ? cipherText.Length : _BlockSizeInBytes;
            int BlockSizeInBits = 8 * BlockSizeInBytes;

            if ((cipherMode == CipherMode.CBC) && (initializationVector.Length % BlockSizeInBytes != 0))
            {
                throw new ArgumentException("The IV length must be equal to the block size");
            }

            if (cipherMode != CipherMode.CBC && cipherMode != CipherMode.ECB)
            {
                throw new ArgumentException("Requested CipherMode not implemented");
            }

            var hcaCryptoKey = HCACryptoKey.FromCACryptoKey(cryptoKey);

            var blockCount = (cipherText.Length / BlockSizeInBytes);

            var plainText = new byte[blockCount * BlockSizeInBytes];
            Parallel.For(0, blockCount, (blockIdx) => {
                var newBlock = new byte[BlockSizeInBytes];
                Buffer.BlockCopy(cipherText, blockIdx * BlockSizeInBytes, newBlock, 0, BlockSizeInBytes);

                newBlock = BlockDecrypt(newBlock, hcaCryptoKey, iterations: BlockSizeInBits);

                if (cipherMode == CipherMode.CBC)
                {
                    byte[] xorVector;
                    if (blockIdx != 0)
                    {
                        xorVector = new byte[BlockSizeInBytes];
                        Buffer.BlockCopy(cipherText, (blockIdx - 1) * BlockSizeInBytes, xorVector, 0, BlockSizeInBytes);
                    }
                    else
                    {
                        xorVector = Util.CloneByteArray(initializationVector);
                    }

                    for (int byteIdx = 0; byteIdx < BlockSizeInBytes; ++byteIdx)
                    {
                        newBlock[byteIdx] ^= xorVector[byteIdx];
                    }
                }

                Buffer.BlockCopy(newBlock, 0, plainText, blockIdx * BlockSizeInBytes, BlockSizeInBytes);
            });
            return plainText;
        }

        protected static byte[] BlockDecrypt(byte[] initialLattice, HCACryptoKey cryptoKey, int iterations)
        {
            //if (initialLattice.Length != BlockSizeInBytes)
            //{
            //    throw new ArgumentException("The initial lattice length must be equal to the block size");
            //}

            int[] preImage = Util.ByteArrayToBinaryArray(initialLattice); 
            int[] image = new int[preImage.Length];
            int[] finalLattice;
            
            int[] swapAux;

            Rule[] mainRules;
            Rule[] borderRules;
            if (cryptoKey.Direction == ToggleDirection.Left)
            {
                mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateLeftSensibleMarginRulesForRadius(cryptoKey.Radius);
            }
            else
            {
                mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                borderRules = Rule.GenerateRightSensibleMarginRulesForRadius(cryptoKey.Radius);
            }

            for (int iterationIdx = 0; iterationIdx < iterations; ++iterationIdx)
            {
                var mainRule = mainRules[(iterations - iterationIdx - 1) % mainRules.Length];
                var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                SequentialEvolveBits(preImage, mainRule, borderRule, cryptoKey.Radius, (iterations - iterationIdx - 1), image);

                // Prepare for Next Iteration
                swapAux = image;
                image = preImage;
                preImage = swapAux;
            }
            finalLattice = preImage;
            return Util.BinaryArrayToByteArray(finalLattice);
        }

        private static int[] SequentialEvolveBits(int[] preImage, Rule mainRule, Rule borderRule, int radius, int execIdx, int[] image)
        {
            var stateLength = preImage.Length;
            var marginLength = 2 * radius;
            int binaryCutMask = 0x7FFFFFFF >> (30 - (2 * radius));

            int borderNeighStartIdx;
            if (borderRule.IsLeftSensible)
            {
                borderNeighStartIdx = Util.CircularIdx((-1 * (marginLength * execIdx)) - radius, stateLength);
            }
            else
            {
                borderNeighStartIdx = Util.CircularIdx((marginLength * execIdx) - radius, stateLength);
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
                resultBitInImageIdx = Util.CircularIdx(currentBorderBitInPreImageIdx - radius, stateLength);
                neighSum |= preImage[currentBorderBitInPreImageIdx];
                image[resultBitInImageIdx] = borderRule.Bits[neighSum];
                currentBorderBitInPreImageIdx = Util.CircularIdx(currentBorderBitInPreImageIdx + 1, stateLength);
                neighSum <<= 1; neighSum &= binaryCutMask;
            }

            // Main Bits
            var currentMainBitInPreImageIdx = currentBorderBitInPreImageIdx;
            for (int mainStepIdx = 0; mainStepIdx < stateLength - marginLength; mainStepIdx++)
            {
                resultBitInImageIdx = Util.CircularIdx(currentMainBitInPreImageIdx - radius, stateLength);
                neighSum |= preImage[currentMainBitInPreImageIdx];
                image[resultBitInImageIdx] = mainRule.Bits[neighSum];
                currentMainBitInPreImageIdx = Util.CircularIdx(currentMainBitInPreImageIdx + 1, stateLength);
                neighSum <<= 1; neighSum &= binaryCutMask;
            }
            return image;
        }

        public override int CountStepsUntilCycleRepeats(byte[] plaintext, CACryptoKey cryptoKey)
        {
            int BlockSizeInBytes = plaintext.Length;
            int BlockSizeInBits = 8 * BlockSizeInBytes;
            int cycleLimit = (int)Math.Pow(BlockSizeInBits, 3); //(BlockSizeInBytes > 2) ? (BlockSizeInBits * BlockSizeInBits * BlockSizeInBits) : int.MaxValue;

            var hcaCryptoKey = HCACryptoKey.FromCACryptoKey(cryptoKey);
            int[] image = Util.ByteArrayToBinaryArray(plaintext);
            int[] preImage = new int[image.Length];

            int[] swapAux;

            Rule[] mainRules;
            Rule[] borderRules;
            if (hcaCryptoKey.Direction == ToggleDirection.Left)
            {
                mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(hcaCryptoKey.KeyBits);
                borderRules = Rule.GenerateLeftSensibleMarginRulesForRadius(hcaCryptoKey.Radius);
            }
            else
            {
                mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(hcaCryptoKey.KeyBits);
                borderRules = Rule.GenerateRightSensibleMarginRulesForRadius(hcaCryptoKey.Radius);
            }

            var plaintextStr = Util.BitArrayToString(image);
            int cycleCount = 0;

            while (true)
            {
                for (int iterationIdx = 0; iterationIdx < BlockSizeInBits; ++iterationIdx)
                {
                    var mainRule = mainRules[iterationIdx % mainRules.Length];
                    var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                    PreImageCalculusBits(image, mainRule, borderRule, hcaCryptoKey.Radius, iterationIdx, preImage);

                    // Prepare for Next Iteration
                    swapAux = image;
                    image = preImage;
                    preImage = swapAux;
                }
                ++cycleCount;
                var imageStr = Util.BitArrayToString(image);
                if ((imageStr == plaintextStr) || ((cycleCount == cycleLimit)))
                {
                    return cycleCount;
                }
            }
        }

        public override IEnumerable<string> GenerateBinaryFile(int sequenceSizeInBits, int howManySequences, string outputDir)
        {
            if (!Directory.Exists(outputDir))
                Directory.CreateDirectory(outputDir);

            var dirNameForMethod = GetFolderNameForGeneratedFiles();
            var dirCombined = Path.Combine(outputDir, dirNameForMethod);
            if (!Directory.Exists(dirCombined))
                Directory.CreateDirectory(dirCombined);

            var fileBag = new ConcurrentBag<string>();
            Parallel.For(0, howManySequences, new ParallelOptions() { MaxDegreeOfParallelism = 10 }, (index) =>
            {
                using (var newFile = File.Create(string.Format("{0}.bin", Path.Combine(dirCombined, Path.GetRandomFileName()))))
                {
                    var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
                    var defaultBlockSizeInBytes = defaultBlockSizeInBits / 8;
                    var initialSeed = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
                    var cryptoKey = HCACryptoKey.GenerateRandomKey(Radius);
                    Rule[] mainRules;
                    Rule[] borderRules;
                    if (cryptoKey.Direction == ToggleDirection.Left)
                    {
                        mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                        borderRules = Rule.GenerateLeftSensibleMarginRulesForRadius(cryptoKey.Radius);
                    }
                    else
                    {
                        mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                        borderRules = Rule.GenerateRightSensibleMarginRulesForRadius(cryptoKey.Radius);
                    }
                    var executions = (sequenceSizeInBits / defaultBlockSizeInBits);
                    int[] image = Util.ByteArrayToBinaryArray(initialSeed);
                    int[] preImage = new int[image.Length];
                    int[] swapAux;
                    byte[] plainText = initialSeed;
                    for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
                    {
                        for (int iterationIdx = 0; iterationIdx < defaultBlockSizeInBits; ++iterationIdx)
                        {
                            var mainRule = mainRules[iterationIdx % mainRules.Length];
                            var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                            PreImageCalculusBits(image, mainRule, borderRule, cryptoKey.Radius, iterationIdx, preImage);

                            // Prepare for Next Iteration
                            swapAux = image;
                            image = preImage;
                            preImage = swapAux;
                        }
                        var ciphertext = Util.BinaryArrayToByteArray(image);

                        for (int byteIdx = 0; byteIdx < defaultBlockSizeInBytes; ++byteIdx)
                        {
                            newFile.WriteByte((byte)(ciphertext[byteIdx] ^ plainText[byteIdx]));
                        }
                        plainText = ciphertext;
                    }
                    fileBag.Add(newFile.Name);
                }
            });
            return fileBag;
        }

        public IEnumerable<string> GenerateBinaryFile_Old(int sequenceSizeInBits, int howManySequences, string outputDir)
        {
            var fileBag = new ConcurrentBag<string>();
            Parallel.For(0, howManySequences, (index) =>
            {
                if (!Directory.Exists(outputDir))
                    Directory.CreateDirectory(outputDir);

                var dirNameForMethod = GetFolderNameForGeneratedFiles();
                var dirCombined = Path.Combine(outputDir, dirNameForMethod);
                if (!Directory.Exists(dirCombined))
                    Directory.CreateDirectory(dirCombined);

                using (var newFile = File.Create(string.Format("{0}.bin", Path.Combine(dirCombined, Path.GetRandomFileName()))))
                {
                    var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
                    var defaultBlockSizeInBytes = defaultBlockSizeInBits / 8;
                    var initialSeed = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
                    var cryptoKey = HCACryptoKey.GenerateRandomKey(Radius);
                    Rule[] mainRules;
                    Rule[] borderRules;
                    if (cryptoKey.Direction == ToggleDirection.Left)
                    {
                        mainRules = Rule.GetAllLeftSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                        borderRules = Rule.GenerateLeftSensibleMarginRulesForRadius(cryptoKey.Radius);
                    }
                    else
                    {
                        mainRules = Rule.GetAllRightSensibleRulesByShiftingNuclei(cryptoKey.KeyBits);
                        borderRules = Rule.GenerateRightSensibleMarginRulesForRadius(cryptoKey.Radius);
                    }
                    var executions = (sequenceSizeInBits / defaultBlockSizeInBits);
                    int[] image = Util.ByteArrayToBinaryArray(initialSeed);
                    int[] preImage = new int[image.Length];
                    int[] swapAux;
                    for (int executionIdx = 0; executionIdx < executions; ++executionIdx)
                    {
                        for (int iterationIdx = 0; iterationIdx < defaultBlockSizeInBits; ++iterationIdx)
                        {
                            var mainRule = mainRules[iterationIdx % mainRules.Length];
                            var borderRule = borderRules[Util.OppositeBit(mainRule.Bits[0])];
                            PreImageCalculusBits(image, mainRule, borderRule, cryptoKey.Radius, iterationIdx, preImage);

                            // Prepare for Next Iteration
                            swapAux = image;
                            image = preImage;
                            preImage = swapAux;
                        }
                        var ciphertext = Util.BinaryArrayToByteArray(image);

                        for (int byteIdx = 0; byteIdx < defaultBlockSizeInBytes; ++byteIdx)
                        {
                            newFile.WriteByte((byte)(ciphertext[byteIdx] ^ initialSeed[byteIdx]));
                        }
                    }
                    fileBag.Add(newFile.Name);
                }
            });
            return fileBag;
        }

        public override byte[] GenerateBinaryStream(int sequenceSizeInBits)
        {
            throw new NotImplementedException();
        }
    }
}
