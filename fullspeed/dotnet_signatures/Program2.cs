// See https://aka.ms/new-console-template for more information
Console.WriteLine("Hello, World!");
PS D:\DOTNET AOT SYMBOLS\SYMBOLS FOR AOT DOTNET CHALL\TestApp> cd ..
PS D:\DOTNET AOT SYMBOLS\SYMBOLS FOR AOT DOTNET CHALL> cd .\TestApp2
PS D:\DOTNET AOT SYMBOLS\SYMBOLS FOR AOT DOTNET CHALL\TestApp2>
PS D:\DOTNET AOT SYMBOLS\SYMBOLS FOR AOT DOTNET CHALL\TestApp2> cat .\Program.cs
using System.Text;

// String manipulation
string exampleString = "Hello World";
string lowerString = exampleString.ToLower();
string upperString = exampleString.ToUpper();
string trimmedString = exampleString.Trim();
bool containsHello = exampleString.Contains("Hello");
string replacedString = exampleString.Replace("World", "Universe");

// Encoding
string encodedString = Convert.ToBase64String(Encoding.UTF8.GetBytes(exampleString));
byte[] decodedBytes = Convert.FromBase64String(encodedString);
string decodedString = Encoding.UTF8.GetString(decodedBytes);

// LINQ and Collections
List<int> numbers = new List<int> { 1, 2, 3, 4, 5 };
int maxNumber = numbers.Max();
int minNumber = numbers.Min();
IEnumerable<int> sortedNumbers = numbers.OrderBy(n => n);

// Math operations
double squareRoot = Math.Sqrt(25);
double power = Math.Pow(2, 3);
double absoluteValue = Math.Abs(-10.5);

// Output to verify operations
Console.WriteLine($"Lowercase: {lowerString}");
Console.WriteLine($"Uppercase: {upperString}");
Console.WriteLine($"Trimmed: {trimmedString}");
Console.WriteLine($"Contains 'Hello': {containsHello}");
Console.WriteLine($"Replaced String: {replacedString}");
Console.WriteLine($"Encoded string: {encodedString}");
Console.WriteLine($"Decoded string: {decodedString}");
Console.WriteLine($"Max number: {maxNumber}");
Console.WriteLine($"Min number: {minNumber}");
Console.WriteLine($"Sorted numbers: {string.Join(", ", sortedNumbers)}");
Console.WriteLine($"Square root of 25: {squareRoot}");
Console.WriteLine($"2 raised to the power of 3: {power}");
Console.WriteLine($"Absolute value of -10.5: {absoluteValue}");
