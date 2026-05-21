using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace WindowsSentinel.Core.Security;

/// <summary>
/// Security validation utilities for input sanitization and security checks.
/// Centralizes security validation logic to prevent code duplication and ensure consistency.
/// </summary>
public static class SecurityValidation
{
    /// <summary>
    /// Validates if a filename is safe (no path traversal or dangerous characters).
    /// </summary>
    /// <param name="filename">The filename to validate.</param>
    /// <returns>True if the filename is safe, false otherwise.</returns>
    public static bool IsSafeFilename(string filename)
    {
        if (string.IsNullOrWhiteSpace(filename))
            return false;

        // Check for path traversal attempts
        if (filename.Contains("..") || filename.Contains("/") || filename.Contains("\\"))
            return false;

        // Check for Windows reserved names and dangerous characters
        if (filename.Contains(":") || filename.Contains("<") || filename.Contains(">") ||
            filename.Contains("|") || filename.Contains("*") || filename.Contains("?") ||
            filename.Contains("\"") || filename.Contains("\0"))
            return false;

        // Check for Windows reserved filenames (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
        var nameWithoutExt = System.IO.Path.GetFileNameWithoutExtension(filename).ToUpperInvariant();
        var reservedNames = new[] { "CON", "PRN", "AUX", "NUL", 
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };
        
        if (Array.Exists(reservedNames, reserved => nameWithoutExt == reserved))
            return false;

        return true;
    }

    /// <summary>
    /// Validates if a file path is within an expected directory (prevents path traversal).
    /// </summary>
    /// <param name="fullPath">The full path to validate.</param>
    /// <param name="expectedDirectory">The expected parent directory.</param>
    /// <returns>True if the path is within the expected directory, false otherwise.</returns>
    public static bool IsPathWithinDirectory(string fullPath, string expectedDirectory)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || string.IsNullOrWhiteSpace(expectedDirectory))
            return false;

        try
        {
            var fullPathResolved = System.IO.Path.GetFullPath(fullPath);
            var expectedDirResolved = System.IO.Path.GetFullPath(expectedDirectory);

            return fullPathResolved.StartsWith(expectedDirResolved, StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Validates if an IP address is private (RFC1918, link-local, loopback).
    /// </summary>
    /// <param name="ipAddress">The IP address to validate.</param>
    /// <returns>True if the IP address is private, false otherwise.</returns>
    public static bool IsPrivateIpAddress(string ipAddress)
    {
        if (string.IsNullOrWhiteSpace(ipAddress))
            return true;

        if (ipAddress == "127.0.0.1" || ipAddress == "::1" || ipAddress == "localhost")
            return true;

        // Check for RFC1918 addresses
        if (ipAddress.StartsWith("10.") || 
            ipAddress.StartsWith("172.16.") || ipAddress.StartsWith("172.17.") || 
            ipAddress.StartsWith("172.18.") || ipAddress.StartsWith("172.19.") ||
            ipAddress.StartsWith("172.20.") || ipAddress.StartsWith("172.21.") ||
            ipAddress.StartsWith("172.22.") || ipAddress.StartsWith("172.23.") ||
            ipAddress.StartsWith("172.24.") || ipAddress.StartsWith("172.25.") ||
            ipAddress.StartsWith("172.26.") || ipAddress.StartsWith("172.27.") ||
            ipAddress.StartsWith("172.28.") || ipAddress.StartsWith("172.29.") ||
            ipAddress.StartsWith("172.30.") || ipAddress.StartsWith("172.31.") ||
            ipAddress.StartsWith("192.168."))
            return true;

        // Check for link-local addresses
        if (ipAddress.StartsWith("169.254."))
            return true;

        return false;
    }

    /// <summary>
    /// Validates if a string contains only safe characters (alphanumeric, hyphen, underscore, dot).
    /// </summary>
    /// <param name="input">The string to validate.</param>
    /// <returns>True if the string contains only safe characters, false otherwise.</returns>
    public static bool IsSafeString(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            return true;

        // Allow alphanumeric, hyphen, underscore, dot, space
        return Regex.IsMatch(input, @"^[a-zA-Z0-9\-_\.\s]+$");
    }

    /// <summary>
    /// Validates if a process ID is within a reasonable range.
    /// </summary>
    /// <param name="pid">The process ID to validate.</param>
    /// <returns>True if the process ID is valid, false otherwise.</returns>
    public static bool IsValidProcessId(int pid)
    {
        return pid > 0 && pid <= 999999; // Reasonable upper bound
    }

    /// <summary>
    /// Validates if a port number is within the valid range.
    /// </summary>
    /// <param name="port">The port number to validate.</param>
    /// <returns>True if the port number is valid, false otherwise.</returns>
    public static bool IsValidPort(int port)
    {
        return port >= 1 && port <= 65535;
    }

    /// <summary>
    /// Validates if a timestamp is within a reasonable range (not too far in past/future).
    /// </summary>
    /// <param name="timestamp">The timestamp to validate.</param>
    /// <param name="maxAgeDays">Maximum age in days (default 365).</param>
    /// <returns>True if the timestamp is valid, false otherwise.</returns>
    public static bool IsValidTimestamp(DateTime timestamp, int maxAgeDays = 365)
    {
        var now = DateTime.UtcNow;
        var minDate = now.AddDays(-maxAgeDays);
        var maxDate = now.AddDays(1); // Allow slight future for clock skew

        return timestamp >= minDate && timestamp <= maxDate;
    }

    /// <summary>
    /// Computes a secure hash of a file for integrity verification.
    /// </summary>
    /// <param name="filePath">The path to the file.</param>
    /// <returns>The SHA256 hash of the file, or null if the file doesn't exist or an error occurs.</returns>
    public static byte[]? ComputeFileHash(string filePath)
    {
        if (!System.IO.File.Exists(filePath))
            return null;

        try
        {
            using var sha256 = SHA256.Create();
            using var stream = System.IO.File.OpenRead(filePath);
            return sha256.ComputeHash(stream);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Compares two byte arrays in constant time to prevent timing attacks.
    /// </summary>
    /// <param name="a">First byte array.</param>
    /// <param name="b">Second byte array.</param>
    /// <returns>True if the arrays are equal, false otherwise.</returns>
    public static bool SecureCompare(byte[]? a, byte[]? b)
    {
        if (a == null || b == null)
            return false;

        return CryptographicOperations.FixedTimeEquals(a, b);
    }
}