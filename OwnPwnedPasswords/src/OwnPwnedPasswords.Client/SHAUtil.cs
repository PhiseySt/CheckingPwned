using System.Security.Cryptography;
using System.Text;

namespace OwnPwnedPasswords.Client;

/// <summary>
/// Utilities for generating a SHA1 hash
/// </summary>
internal static class ShaUtil
{
    private static readonly SHA1 Sha1 = SHA1.Create();

    /// <summary>
    /// Compute hash for string
    /// </summary>
    /// <param name="s">String to be hashed</param>
    /// <returns>40-character hex string</returns>
    public static string Sha1HashStringForUtf8String(string? s)
    {
        var bytes = Encoding.Default.GetBytes(s);

        var hashBytes = Sha1.ComputeHash(bytes);

        return HexStringFromBytes(hashBytes);
    }

    /// <summary>
    /// Convert an array of bytes to a string of hex digits
    /// </summary>
    /// <param name="bytes">array of bytes</param>
    /// <returns>String of hex digits</returns>
    private static string HexStringFromBytes(IEnumerable<byte> bytes)
    {
        var sb = new StringBuilder();
        foreach (var b in bytes)
        {
            var hex = b.ToString("X2");
            sb.Append(hex);
        }
        return sb.ToString();
    }
}