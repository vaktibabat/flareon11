using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;

public class Program
{
    // NIST P-256 parameters
    private static readonly X9ECParameters ecParams = ECNamedCurveTable.GetByName("P-256");
    private static readonly ECDomainParameters domainParams = new ECDomainParameters(ecParams.Curve, ecParams.G, ecParams.N, ecParams.H);
    private static readonly SecureRandom random = new SecureRandom();

    public static void Main(string[] args)
    {
        // Start the server in a separate thread
        var serverTask = System.Threading.Tasks.Task.Run(() => server());

        // Give the server some time to start
        System.Threading.Thread.Sleep(1000);

        // Run the client
        client();

        // Wait for server to finish
        serverTask.Wait();
    }

    public static void server()
    {
        try
        {
            TcpListener listener = new TcpListener(IPAddress.Parse("127.0.0.1"), 1337);
            listener.Start();
            Console.WriteLine("Server listening on port 1337...");

            using (TcpClient client = listener.AcceptTcpClient())
            using (NetworkStream stream = client.GetStream())
            {
                // Generate server's ECC key pair (c, d)
                AsymmetricCipherKeyPair serverKeyPair = GenerateECKeyPair();
                ECPublicKeyParameters serverPublicKey = (ECPublicKeyParameters)serverKeyPair.Public;
                ECPrivateKeyParameters serverPrivateKey = (ECPrivateKeyParameters)serverKeyPair.Private;

                // Read client's public key (a, b)
                byte[] clientPublicKeyBytes = new byte[65];
                stream.Read(clientPublicKeyBytes, 0, clientPublicKeyBytes.Length);
                ECPublicKeyParameters clientPublicKey = new ECPublicKeyParameters(ecParams.Curve.DecodePoint(clientPublicKeyBytes), domainParams);

                // Derive shared secret S and hash it with SHA-512
                BigInteger sharedSecret = DeriveSharedSecret(serverPrivateKey, clientPublicKey);
                byte[] secretKey = HashSharedSecretWithSHA512(sharedSecret);

                // Use ChaCha20 to encrypt the message "HELLO"
                string message = "HELLO";
                byte[] messageBytes = Encoding.UTF8.GetBytes(message);
                byte[] encryptedMessage = EncryptWithChaCha20(secretKey, messageBytes);

                // Send server's public key (c, d) and encrypted message
                byte[] serverPublicKeyBytes = serverPublicKey.Q.GetEncoded(false);
                stream.Write(serverPublicKeyBytes, 0, serverPublicKeyBytes.Length);
                stream.Write(encryptedMessage, 0, encryptedMessage.Length);

                Console.WriteLine("Server: Sent public key and encrypted message.");
            }

            listener.Stop();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Server error: {ex.Message}");
        }
    }

    public static void client()
    {
        try
        {
            using (TcpClient client = new TcpClient("127.0.0.1", 1337))
            using (NetworkStream stream = client.GetStream())
            {
                // Generate client's ECC key pair (a, b)
                AsymmetricCipherKeyPair clientKeyPair = GenerateECKeyPair();
                ECPublicKeyParameters clientPublicKey = (ECPublicKeyParameters)clientKeyPair.Public;
                ECPrivateKeyParameters clientPrivateKey = (ECPrivateKeyParameters)clientKeyPair.Private;

                // Send client's public key (a, b) to server
                byte[] clientPublicKeyBytes = clientPublicKey.Q.GetEncoded(false);
                stream.Write(clientPublicKeyBytes, 0, clientPublicKeyBytes.Length);

                // Read server's public key (c, d) and encrypted message
                byte[] serverPublicKeyBytes = new byte[65];
                stream.Read(serverPublicKeyBytes, 0, serverPublicKeyBytes.Length);
                ECPublicKeyParameters serverPublicKey = new ECPublicKeyParameters(ecParams.Curve.DecodePoint(serverPublicKeyBytes), domainParams);

                byte[] encryptedMessage = new byte[5];  // Size of the "HELLO" message
                stream.Read(encryptedMessage, 0, encryptedMessage.Length);

                // Derive shared secret S and hash it with SHA-512
                BigInteger sharedSecret = DeriveSharedSecret(clientPrivateKey, serverPublicKey);
                byte[] secretKey = HashSharedSecretWithSHA512(sharedSecret);

                // Decrypt the message with ChaCha20
                byte[] decryptedMessage = DecryptWithChaCha20(secretKey, encryptedMessage);
                string decryptedString = Encoding.UTF8.GetString(decryptedMessage);

                Console.WriteLine($"Client: Decrypted message is '{decryptedString}'");

                if (decryptedString == "HELLO")
                {
                    Console.WriteLine("Client: Message verification successful!");
                }
                else
                {
                    Console.WriteLine("Client: Message verification failed.");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Client error: {ex.Message}");
        }
    }

    // Generate an EC key pair
    private static AsymmetricCipherKeyPair GenerateECKeyPair()
    {
        ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
        keyGen.Init(new ECKeyGenerationParameters(domainParams, random));
        return keyGen.GenerateKeyPair();
    }

    // Derive a shared secret using ECDH
    private static BigInteger DeriveSharedSecret(ECPrivateKeyParameters privateKey, ECPublicKeyParameters publicKey)
    {
        ECDHBasicAgreement agreement = new ECDHBasicAgreement();
        agreement.Init(privateKey);
        return agreement.CalculateAgreement(publicKey);
    }

    // Hash the shared secret with SHA-512
    private static byte[] HashSharedSecretWithSHA512(BigInteger sharedSecret)
    {
        Sha512Digest sha512 = new Sha512Digest();
        byte[] secretBytes = sharedSecret.ToByteArrayUnsigned();
        sha512.BlockUpdate(secretBytes, 0, secretBytes.Length);
        byte[] hashedSecret = new byte[sha512.GetDigestSize()];
        sha512.DoFinal(hashedSecret, 0);
        return hashedSecret;
    }

    // ChaCha20 encryption
    private static byte[] EncryptWithChaCha20(byte[] key, byte[] data)
    {
        ChaChaEngine engine = new ChaChaEngine(20);
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV keyWithIv = new ParametersWithIV(keyParam, new byte[12]); // IV should be 12 bytes

        engine.Init(true, keyWithIv);
        byte[] encrypted = new byte[data.Length];
        engine.ProcessBytes(data, 0, data.Length, encrypted, 0);

        return encrypted;
    }

    // ChaCha20 decryption
    private static byte[] DecryptWithChaCha20(byte[] key, byte[] cipherText)
    {
        ChaChaEngine engine = new ChaChaEngine(20);
        KeyParameter keyParam = new KeyParameter(key);
        ParametersWithIV keyWithIv = new ParametersWithIV(keyParam, new byte[12]); // IV should be 12 bytes

        engine.Init(false, keyWithIv);
        byte[] decrypted = new byte[cipherText.Length];
        engine.ProcessBytes(cipherText, 0, cipherText.Length, decrypted, 0);

        return decrypted;
    }
}
