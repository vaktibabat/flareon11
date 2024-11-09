using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using System;
using System.Text;
using System.IO;

namespace BouncyCastleAOTExample
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Starting BouncyCastle AOT Example...");

            // Hashing example with SHA-256
            Console.WriteLine("Hashing with SHA-256");
            var hash = HashWithSha256("Hello, World!");

            // RSA key generation and encryption/decryption
            Console.WriteLine("Generating RSA keys");
            var rsaKeys = GenerateRsaKeys();
            var encryptedMessage = RsaEncrypt(rsaKeys.Public, "Hello, RSA Encryption");
            var decryptedMessage = RsaDecrypt(rsaKeys.Private, encryptedMessage);

            // AES encryption with CBC mode
            Console.WriteLine("AES Encryption with CBC");
            var aesKey = GenerateAesKey();
            var aesCipherText = AesEncrypt("Hello AES", aesKey);

            // ECDSA (Elliptic Curve Digital Signature Algorithm) signature
            Console.WriteLine("ECDSA Signature Generation and Verification");
            var ecKeys = GenerateECDSAKeys();
            var message = "Hello, ECDSA!";
            var signature = SignWithEcdsa(ecKeys.Private, message);
            var isVerified = VerifyEcdsaSignature(ecKeys.Public, message, signature);

            Console.WriteLine("Hash (SHA-256): " + BitConverter.ToString(hash));
            Console.WriteLine("Decrypted RSA message: " + decryptedMessage);
            Console.WriteLine("AES Ciphertext: " + BitConverter.ToString(aesCipherText));
            Console.WriteLine("ECDSA Signature Verified: " + isVerified);

            Console.WriteLine("BouncyCastle AOT Example Completed.");
        }

        // Hashing with SHA-256
        static byte[] HashWithSha256(string input)
        {
            var digest = new Sha256Digest();
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            digest.BlockUpdate(inputBytes, 0, inputBytes.Length);
            byte[] result = new byte[digest.GetDigestSize()];
            digest.DoFinal(result, 0);
            return result;
        }

        // RSA Key Generation
        static (AsymmetricKeyParameter Public, AsymmetricKeyParameter Private) GenerateRsaKeys()
        {
            var keyGen = new RsaKeyPairGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();
            return (keyPair.Public, keyPair.Private);
        }

        // RSA Encryption
        static byte[] RsaEncrypt(AsymmetricKeyParameter publicKey, string input)
        {
            var engine = new RsaEngine();
            engine.Init(true, publicKey);
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);
            return engine.ProcessBlock(inputBytes, 0, inputBytes.Length);
        }

        // RSA Decryption
        static string RsaDecrypt(AsymmetricKeyParameter privateKey, byte[] input)
        {
            var engine = new RsaEngine();
            engine.Init(false, privateKey);
            byte[] decrypted = engine.ProcessBlock(input, 0, input.Length);
            return Encoding.UTF8.GetString(decrypted);
        }

        // AES Key Generation
        static byte[] GenerateAesKey()
        {
            var keyGen = new CipherKeyGenerator();
            keyGen.Init(new KeyGenerationParameters(new SecureRandom(), 256)); // AES-256
            return keyGen.GenerateKey();
        }

        // AES Encryption (CBC mode with PKCS7 padding)
        static byte[] AesEncrypt(string plaintext, byte[] key)
        {
            var engine = new AesEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher);
            var keyParam = new KeyParameter(key);
            var iv = new byte[blockCipher.GetBlockSize()];
            new SecureRandom().NextBytes(iv); // Generate random IV
            cipher.Init(true, new ParametersWithIV(keyParam, iv));

            byte[] inputBytes = Encoding.UTF8.GetBytes(plaintext);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];
            int length = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return outputBytes;
        }

        // ECDSA Key Generation
        static (AsymmetricKeyParameter Public, AsymmetricKeyParameter Private) GenerateECDSAKeys()
        {
            var ecParams = SecNamedCurves.GetByName("secp256k1");
            var keyGen = new ECKeyPairGenerator();
            var genParams = new ECKeyGenerationParameters(new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H), new SecureRandom());
            keyGen.Init(genParams);
            var keyPair = keyGen.GenerateKeyPair();
            return (keyPair.Public, keyPair.Private);
        }

        // ECDSA Signing
        static byte[] SignWithEcdsa(AsymmetricKeyParameter privateKey, string message)
        {
            var signer = new ECDsaSigner();
            signer.Init(true, privateKey);

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            BigInteger[] signature = signer.GenerateSignature(messageBytes);

            // Convert signature to byte array (R + S)
            byte[] r = signature[0].ToByteArray();
            byte[] s = signature[1].ToByteArray();

            // Return concatenated signature
            byte[] sig = new byte[r.Length + s.Length];
            Array.Copy(r, 0, sig, 0, r.Length);
            Array.Copy(s, 0, sig, r.Length, s.Length);
            return sig;
        }

        // ECDSA Verification
        static bool VerifyEcdsaSignature(AsymmetricKeyParameter publicKey, string message, byte[] signature)
        {
            var signer = new ECDsaSigner();
            signer.Init(false, publicKey);

            byte[] messageBytes = Encoding.UTF8.GetBytes(message);

            // Split signature into R and S
            int sigLength = signature.Length / 2;
            byte[] r = new byte[sigLength];
            byte[] s = new byte[sigLength];
            Array.Copy(signature, 0, r, 0, sigLength);
            Array.Copy(signature, sigLength, s, 0, sigLength);

            return signer.VerifySignature(messageBytes, new BigInteger(r), new BigInteger(s));
        }
    }
}
