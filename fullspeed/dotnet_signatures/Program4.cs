using System;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;

class Program
{
    static void Main(string[] args)
    {
        // Define the key and nonce for both ChaCha20 and Salsa20
        byte[] key = new byte[32]; // 256-bit key
        byte[] nonce = new byte[12]; // ChaCha20 nonce (12 bytes)
        byte[] salsaNonce = new byte[8]; // Salsa20 nonce (8 bytes)
        byte[] data = new byte[64]; // Example data

        // Fill key, nonce, and data with random values for testing
        Random random = new Random();
        random.NextBytes(key);
        random.NextBytes(nonce);
        random.NextBytes(salsaNonce);
        random.NextBytes(data);

        // Perform a lot of ChaCha20 and Salsa20 operations
        for (int i = 0; i < 1000000; i++) // Loop to maximize operations
        {
            // ChaCha20 encryption and decryption
            byte[] encryptedChaCha20 = PerformChaCha20(key, nonce, data);
            byte[] decryptedChaCha20 = PerformChaCha20(key, nonce, encryptedChaCha20);

            // Verify that decrypted data matches original
            if (!CompareArrays(data, decryptedChaCha20))
                throw new Exception("ChaCha20 decryption failed!");

            // Salsa20 encryption and decryption
            byte[] encryptedSalsa20 = PerformSalsa20(key, salsaNonce, data);
            byte[] decryptedSalsa20 = PerformSalsa20(key, salsaNonce, encryptedSalsa20);

            // Verify that decrypted data matches original
            if (!CompareArrays(data, decryptedSalsa20))
                throw new Exception("Salsa20 decryption failed!");
        }

        Console.WriteLine("Completed encryption and decryption operations successfully.");
    }

    static byte[] PerformChaCha20(byte[] key, byte[] nonce, byte[] data)
    {
        ChaChaEngine chaCha = new ChaChaEngine(20); // 20 rounds
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV parameters = new ParametersWithIV(keyParam, nonce);
        chaCha.Init(true, parameters);

        byte[] output = new byte[data.Length];
        chaCha.ProcessBytes(data, 0, data.Length, output, 0);
        return output;
    }

    static byte[] PerformSalsa20(byte[] key, byte[] nonce, byte[] data)
    {
        Salsa20Engine salsa = new Salsa20Engine();
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV parameters = new ParametersWithIV(keyParam, nonce);
        salsa.Init(true, parameters);

        byte[] output = new byte[data.Length];
        salsa.ProcessBytes(data, 0, data.Length, output, 0);
        return output;
    }

    static bool CompareArrays(byte[] original, byte[] decrypted)
    {
        if (original.Length != decrypted.Length)
            return false;

        for (int i = 0; i < original.Length; i++)
        {
            if (original[i] != decrypted[i])
                return false;
        }

        return true;
    }
}
