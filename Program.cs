using System;
using System.Text;
using static HCA_Crypto.HCA;

namespace HCA_Crypto
{
    class Program
    {
        static void Main()
        {
            var plaintextString = "Avocado is a delicious and nutritive fruit.";
            Console.WriteLine($"- Original Plaintext: {plaintextString}");

            var plaintextBytes = Encoding.ASCII.GetBytes(plaintextString);
            Console.WriteLine($"- Non-Padded Plaintext Bytes: {BitConverter.ToString(plaintextBytes)}");

            var cryptoKey = HCACryptoKey.GenerateRandomKey();

            var initializationVector = Util.GetSecureRandomByteArray(HCA.BlockSizeInBytes / 2);

            var ciphertext = HCA.Encrypt_CTR(plaintextBytes, cryptoKey, initializationVector);
            Console.WriteLine($"- Ciphertext Bytes: {BitConverter.ToString(ciphertext)}");

            var decryptedPlaintext = HCA.Decrypt_CTR(ciphertext, cryptoKey, initializationVector);

            var recoveredString = Encoding.ASCII.GetString(decryptedPlaintext).TrimEnd('\0');
            Console.WriteLine($"- Deciphered Plaintext: {recoveredString}");
            Console.ReadKey();
        }
    }
}
