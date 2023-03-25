using System.Security.Cryptography;

namespace CACrypto.Commons
{
    public abstract class PermutiveCACryptoMethodBase : CryptoMethodBase
    {
        public abstract byte[] Encrypt(byte[] plainText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, CipherMode cipherMode = CipherMode.CBC);

        public abstract byte[] Decrypt(byte[] cipherText, PermutiveCACryptoKey cryptoKey, byte[] initializationVector, CipherMode cipherMode = CipherMode.CBC);

        public abstract PermutiveCACryptoKey GenerateRandomGenericKeyInBits(int blockSizeInBits);

        public abstract PermutiveCACryptoKey GenerateRandomGenericKey(int blockSize);

        public abstract byte[] EncryptAsSingleBlock(byte[] plainText, PermutiveCACryptoKey cryptoKey);

        public override byte[] GeneratePseudoRandomSequence(int sequenceSizeInBytes)
        {
            using var stream = new MemoryStream();
            var defaultBlockSizeInBits = GetDefaultBlockSizeInBits();
            var defaultBlockSizeInBytes = GetDefaultBlockSizeInBytes();
            var initialSeed = Util.GetSecureRandomByteArray(defaultBlockSizeInBytes);
            var cryptoKey = GenerateRandomGenericKeyInBits(defaultBlockSizeInBits);
            byte[] plainText = initialSeed;

            WritePseudoRandomGeneratedSequenceToBinaryStream(stream, initialSeed, cryptoKey, sequenceSizeInBytes);

            return stream.ToArray();
        }

        protected abstract void WritePseudoRandomGeneratedSequenceToBinaryStream(MemoryStream stream, byte[] initialSeed, PermutiveCACryptoKey cryptoKey, int sequenceSizeInBytes);
    }
}