namespace CACrypto.Commons
{
    public class PermutiveCACryptoKey : CryptoKeyBase
    {
        public ToggleDirection Direction { get; set; }

        public enum ToggleDirection { Left = 0, Right = 1 };

        public PermutiveCACryptoKey(byte[] bytes, int directionBit) : base(bytes)
        {
            Direction = (ToggleDirection)Enum.ToObject(typeof(ToggleDirection), directionBit);
        }
    }
}
