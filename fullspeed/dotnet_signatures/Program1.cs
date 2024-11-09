using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

class Program
{
    // BCrypt.dll imports
    [DllImport("bcrypt.dll", CharSet = CharSet.Auto)]
    public static extern int BCryptOpenAlgorithmProvider(out IntPtr hAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Auto)]
    public static extern int BCryptGenRandom(IntPtr hAlgorithm, byte[] pbBuffer, uint cbBuffer, uint dwFlags);

    // ntdll.dll imports
    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern uint NtQuerySystemTime(ref long systemTime);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern int RtlGetVersion(ref OSVERSIONINFOEX versionInfo);

    // kernel32.dll imports
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Beep(uint dwFreq, uint dwDuration);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr LoadLibrary(string lpLibFileName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CreateDirectory(string lpPathName, IntPtr lpSecurityAttributes);

    // advapi32.dll imports
    [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID luid);

    // ole32.dll imports
    [DllImport("ole32.dll")]
    public static extern int CoInitialize(IntPtr pvReserved);

    [DllImport("ole32.dll")]
    public static extern void CoUninitialize();

    // WS2_32.dll imports
    [DllImport("WS2_32.dll", SetLastError = true)]
    public static extern int gethostname(byte[] name, int namelen);

    // BouncyCastle usage (RSA encryption)
    static void BouncyCastleRSAEncrypt()
    {
        var rsa = new RsaEngine();
        rsa.Init(true, new RsaKeyParameters(false, new Org.BouncyCastle.Math.BigInteger("10001", 16), new Org.BouncyCastle.Math.BigInteger("D8E8FCA2DC0F896FD7CB4EB25663AB45", 16)));
        byte[] input = Encoding.UTF8.GetBytes("Hello RSA");
        byte[] output = rsa.ProcessBlock(input, 0, input.Length);
        Console.WriteLine("BouncyCastle RSA Encrypted: " + BitConverter.ToString(output).Replace("-", ""));
    }

    static void BouncyCastleRandom()
    {
        SecureRandom random = new SecureRandom(new DigestRandomGenerator(new Sha256Digest()));
        byte[] randomBytes = new byte[16];
        random.NextBytes(randomBytes);
        Console.WriteLine("BouncyCastle Random Data: " + BitConverter.ToString(randomBytes).Replace("-", ""));
    }

    static void BouncyCastleSHA1Digest()
    {
        Sha1Digest sha1 = new Sha1Digest();
        byte[] input = Encoding.UTF8.GetBytes("Hello BouncyCastle SHA-1");
        sha1.BlockUpdate(input, 0, input.Length);

        byte[] result = new byte[sha1.GetDigestSize()];
        sha1.DoFinal(result, 0);

        Console.WriteLine("BouncyCastle SHA-1 Digest: " + BitConverter.ToString(result).Replace("-", ""));
    }

    // OS version structure (ntdll.dll usage)
    [StructLayout(LayoutKind.Sequential)]
    public struct OSVERSIONINFOEX
    {
        public uint dwOSVersionInfoSize;
        public uint dwMajorVersion;
        public uint dwMinorVersion;
        public uint dwBuildNumber;
        public uint dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    // Sorting operations
    static void SortingOperations()
    {
        List<int> numbers = new List<int> { 3, 8, 2, 7, 1, 9, 5 };
        Console.WriteLine("Before Sorting: " + string.Join(", ", numbers));

        numbers.Sort();
        Console.WriteLine("After Sorting (Ascending): " + string.Join(", ", numbers));

        numbers.Sort((a, b) => b.CompareTo(a));
        Console.WriteLine("After Sorting (Descending): " + string.Join(", ", numbers));
    }

    // String manipulation operations
    static void StringManipulationOperations()
    {
        string original = "Hello, .NET! This is a string manipulation test.";
        string upper = original.ToUpper();
        string lower = original.ToLower();
        string substring = original.Substring(0, 12);
        string replaced = original.Replace(".NET", "World");

        Console.WriteLine("Original: " + original);
        Console.WriteLine("Uppercase: " + upper);
        Console.WriteLine("Lowercase: " + lower);
        Console.WriteLine("Substring: " + substring);
        Console.WriteLine("Replaced: " + replaced);
    }

    // Base64 operations
    static void Base64Operations()
    {
        string original = "This is a test string for Base64.";
        string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(original));
        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));

        Console.WriteLine("Original String: " + original);
        Console.WriteLine("Base64 Encoded: " + encoded);
        Console.WriteLine("Base64 Decoded: " + decoded);
    }

    // Socket operations
    static void SocketOperations()
    {
        try
        {
            // Create a socket
            Socket sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

            // Establish the remote endpoint for the socket
            IPHostEntry ipHost = Dns.GetHostEntry("localhost");
            IPAddress ipAddr = ipHost.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddr, 11000);

            // Connect the socket
            sender.Connect(remoteEP);
            Console.WriteLine("Socket connected to {0}", sender.RemoteEndPoint.ToString());

            // Send data through the socket
            string message = "This is a test message from client";
            byte[] msg = Encoding.ASCII.GetBytes(message);
            int bytesSent = sender.Send(msg);

            // Receive response from the socket
            byte[] buffer = new byte[1024];
            int bytesRec = sender.Receive(buffer);
            Console.WriteLine("Received from server: {0}", Encoding.ASCII.GetString(buffer, 0, bytesRec));

            // Release the socket
            sender.Shutdown(SocketShutdown.Both);
            sender.Close();
        }
        catch (Exception e)
        {
            Console.WriteLine("Socket Error: {0}", e.ToString());
        }
    }

    // Connecting to a web page using WebClient
    static void ConnectToExampleDotCom()
    {
        try
        {
            using (WebClient client = new WebClient())
            {
                string response = client.DownloadString("https://example.com");
                Console.WriteLine("Response from https://example.com: ");
                Console.WriteLine(response.Substring(0, 200)); // Display first 200 characters
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error fetching webpage: " + ex.Message);
        }
    }

    static void Main(string[] args)
    {
        // BCrypt usage
        IntPtr hAlgorithm;
        if (BCryptOpenAlgorithmProvider(out hAlgorithm, "RNG", null, 0) == 0)
        {
            byte[] randomData = new byte[16];
            BCryptGenRandom(hAlgorithm, randomData, (uint)randomData.Length, 0);
            Console.WriteLine("BCrypt Random Data: " + BitConverter.ToString(randomData).Replace("-", ""));
        }

        // ntdll usage - Query system time
        long systemTime = 0;
        NtQuerySystemTime(ref systemTime);
        Console.WriteLine("System Time: " + systemTime);

        // ntdll usage - Get OS version
        OSVERSIONINFOEX osInfo = new OSVERSIONINFOEX();
        osInfo.dwOSVersionInfoSize = (uint)Marshal.SizeOf(osInfo);
        RtlGetVersion(ref osInfo);
        Console.WriteLine($"OS Version: {osInfo.dwMajorVersion}.{osInfo.dwMinorVersion}, Build: {osInfo.dwBuildNumber}");

        // kernel32 usage
        Beep(750, 300);

        // Create directory
        CreateDirectory("C:\\TestDirectory", IntPtr.Zero);
        Console.WriteLine("Created Directory: C:\\TestDirectory");

        // Load library
        IntPtr moduleHandle = LoadLibrary("kernel32.dll");
        Console.WriteLine("Loaded kernel32.dll, handle: " + moduleHandle);

        // advapi32 usage - Open process token and lookup privilege
        IntPtr processToken;
        OpenProcessToken(GetModuleHandle("kernel32.dll"), 0x0008, out processToken);
        LUID privilegeLuid = new LUID();
        LookupPrivilegeValue(null, "SeShutdownPrivilege", ref privilegeLuid);
        Console.WriteLine("Privilege LUID: " + privilegeLuid.LowPart);

        // ole32 usage
        CoInitialize(IntPtr.Zero);
        Console.WriteLine("OLE Initialized.");
        CoUninitialize();

        // WS2_32 usage
        byte[] hostname = new byte[256];
        if (gethostname(hostname, hostname.Length) == 0)
        {
            string host = Encoding.ASCII.GetString(hostname).Trim('\0');
            Console.WriteLine("Hostname: " + host);
        }

        // BouncyCastle usage
        BouncyCastleRandom();
        BouncyCastleSHA1Digest();
        BouncyCastleRSAEncrypt();

        // Sorting operations
        SortingOperations();

        // String manipulation
        StringManipulationOperations();

        // Base64 operations
        Base64Operations();

        // Socket operations
        SocketOperations();

        // WebClient connection to example.com
        ConnectToExampleDotCom();
    }
}
