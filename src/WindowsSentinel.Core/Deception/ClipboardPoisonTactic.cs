using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Clipboard Poison Tactic — Replaces clipboard contents with weaponized fake data.
/// 
/// When clipboard theft is detected, instead of just killing the stealer, we first replace
/// the clipboard with convincing-looking but fake/trackable data:
///   - Fake cryptocurrency wallet addresses (that we can monitor for incoming transactions)
///   - Fake API keys with embedded canary tokens
///   - Fake credentials that resolve to honeypot infrastructure
///   - Fake SSH private keys for honeypot servers
/// 
/// The attacker's stolen clipboard data is now:
///   1. Useless (fake credentials don't work on real systems)
///   2. Trackable (canary tokens alert us when used)
///   3. Dangerous to the attacker (connects them to our honeypots, exposing their infra)
/// 
/// This is particularly effective against:
///   - Crypto address swappers (they'll propagate our monitored address)
///   - Infostealer malware (their exfil contains our canary data)
///   - Clipboard-to-C2 exfiltration (operator gets poisoned data)
/// </summary>
public sealed class ClipboardPoisonTactic : IDeceptionTactic
{
    private readonly ILogger<ClipboardPoisonTactic> _logger;

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hWndNewOwner);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool EmptyClipboard();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetClipboardData(uint uFormat, IntPtr hMem);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool CloseClipboard();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalAlloc(uint uFlags, UIntPtr dwBytes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalUnlock(IntPtr hMem);

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE = 0x0002;

    public ClipboardPoisonTactic(ILogger<ClipboardPoisonTactic> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            try
            {
                var poisonData = GeneratePoisonPayload(context);

                if (!OpenClipboard(IntPtr.Zero))
                {
                    return new DeceptionTacticResult
                    {
                        TacticName = "ClipboardPoison",
                        Success = false,
                        Error = "Could not open clipboard for poisoning"
                    };
                }

                try
                {
                    EmptyClipboard();

                    var bytes = System.Text.Encoding.Unicode.GetBytes(poisonData + "\0");
                    var hGlobal = GlobalAlloc(GMEM_MOVEABLE, (UIntPtr)bytes.Length);
                    if (hGlobal == IntPtr.Zero)
                    {
                        return new DeceptionTacticResult
                        {
                            TacticName = "ClipboardPoison",
                            Success = false,
                            Error = "GlobalAlloc failed"
                        };
                    }

                    var ptr = GlobalLock(hGlobal);
                    Marshal.Copy(bytes, 0, ptr, bytes.Length);
                    GlobalUnlock(hGlobal);

                    SetClipboardData(CF_UNICODETEXT, hGlobal);

                    return new DeceptionTacticResult
                    {
                        TacticName = "ClipboardPoison",
                        Success = true,
                        Description = $"Clipboard replaced with poisoned data ({poisonData.Length} chars) — " +
                                      "attacker's stolen clipboard now contains trackable fake credentials"
                    };
                }
                finally
                {
                    CloseClipboard();
                }
            }
            catch (Exception ex)
            {
                return new DeceptionTacticResult
                {
                    TacticName = "ClipboardPoison",
                    Success = false,
                    Error = ex.Message
                };
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Generates convincing-looking but fake/trackable data to poison the clipboard.
    /// The content looks like high-value stolen data to maximize attacker engagement.
    /// </summary>
    private static string GeneratePoisonPayload(DeceptionContext context)
    {
        var random = Random.Shared;
        var payloads = new List<string>();

        // Fake AWS credentials (format matches real keys but values are canary)
        payloads.Add($"aws_access_key_id = AKIA{GenerateRandomAlphanumeric(16)}");
        payloads.Add($"aws_secret_access_key = {GenerateRandomBase64(40)}");

        // Fake Bitcoin address (valid format, monitored)
        payloads.Add($"BTC: bc1q{GenerateRandomHex(38)}");

        // Fake Ethereum address
        payloads.Add($"ETH: 0x{GenerateRandomHex(40)}");

        // Fake SSH private key header (triggers attacker interest)
        payloads.Add("-----BEGIN OPENSSH PRIVATE KEY-----");
        payloads.Add(GenerateRandomBase64(70));
        payloads.Add(GenerateRandomBase64(70));
        payloads.Add(GenerateRandomBase64(70));
        payloads.Add("-----END OPENSSH PRIVATE KEY-----");

        // Fake API tokens
        payloads.Add($"GITHUB_TOKEN=ghp_{GenerateRandomAlphanumeric(36)}");
        payloads.Add($"SLACK_TOKEN=xoxb-{random.Next(100000000, 999999999)}-{random.Next(100000000, 999999999)}-{GenerateRandomAlphanumeric(24)}");

        // Fake database connection string
        payloads.Add($"Server=db-prod-{random.Next(1, 9)}.internal.corp;Database=customers;User=admin;Password={GenerateRandomAlphanumeric(20)};");

        return string.Join("\n", payloads);
    }

    private static string GenerateRandomHex(int length)
    {
        var bytes = new byte[length / 2 + 1];
        Random.Shared.NextBytes(bytes);
        return Convert.ToHexString(bytes)[..length].ToLowerInvariant();
    }

    private static string GenerateRandomBase64(int length)
    {
        var bytes = new byte[(length * 3) / 4 + 3];
        Random.Shared.NextBytes(bytes);
        return Convert.ToBase64String(bytes)[..length];
    }

    private static string GenerateRandomAlphanumeric(int length)
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        var result = new char[length];
        for (int i = 0; i < length; i++)
            result[i] = chars[Random.Shared.Next(chars.Length)];
        return new string(result);
    }
}


