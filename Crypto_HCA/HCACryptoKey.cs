using CACrypto.Commons;
using static CACrypto.Commons.PermutiveCACryptoKey;

namespace HCA_Crypto
{
    public class HCACryptoKey
    {
        public ToggleDirection Direction { get; private set; }

        public byte[] KeyBytes { get; private set; }

        public HCACryptoKey(byte[] keyBytes, int directionBit)
        {
            KeyBytes = keyBytes;

            Direction = (directionBit == 1) ? ToggleDirection.Right : ToggleDirection.Left;
        }

        public static HCACryptoKey GenerateRandomKey(int? directionBit = null)
        {
            if (directionBit is null)
            {
                directionBit = Util.GetRandomNumber(0, 2);
            }

            var keyBytes = Util.GetSecureRandomByteArray(HCA.KeySizeInBytes);
            while (Util.SpatialEntropyCalculusForBinary(Util.ByteArrayToBinaryArray(keyBytes)) <= 0.75)
            {
                keyBytes = Util.GetSecureRandomByteArray(HCA.KeySizeInBytes);
            }
            return new HCACryptoKey(keyBytes, directionBit.Value);
        }
    }
}
