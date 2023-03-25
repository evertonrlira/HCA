namespace CACrypto.Commons
{
    public abstract class CryptoKeyBase
    {
        public byte[] Bytes { get; private set; }


        protected CryptoKeyBase(byte[] bytes)
        {
            Bytes = bytes;
        }

        public void ChangeRandomBit()
        {
            Util.ChangeRandomBit(Bytes, true);
        }
    }
}