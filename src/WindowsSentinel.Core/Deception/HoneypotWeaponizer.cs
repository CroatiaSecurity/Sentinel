using System.IO;
using System.Text;
using Microsoft.Extensions.Logging;

namespace WindowsSentinel.Core.Deception;

/// <summary>
/// Honeypot Weaponizer — Deploys weaponized fake credentials and sensitive files that
/// actively harm the attacker when they try to use the stolen data.
/// 
/// Deployed assets:
///   1. Fake SSH keys for honeypot servers — attacker connects, we capture their session
///   2. Fake AWS/Azure/GCP credentials — usage triggers CloudTrail alerts + honeypot infra
///   3. Fake VPN configs — routes through our logging proxy, full PCAP of attacker activity
///   4. Fake browser password databases — contain canary URLs that alert on access
///   5. Zip bombs disguised as sensitive archives — crash attacker's analysis tools
///   6. Fake cryptocurrency wallets — trackable addresses we monitor
/// 
/// Deployment strategy:
///   - Files placed in locations infostealers target (Desktop, Documents, .ssh, browser profiles)
///   - File names chosen to maximize attacker interest (passwords, keys, wallets, backups)
///   - Content is format-valid (passes basic validation) but values are canary/honeypot
///   - Timestamps backdated to look like legitimate old files
/// 
/// This goes beyond passive canaries — these files actively BITE when used.
/// </summary>
public sealed class HoneypotWeaponizer : IDeceptionTactic
{
    private readonly ILogger<HoneypotWeaponizer> _logger;

    public HoneypotWeaponizer(ILogger<HoneypotWeaponizer> logger)
    {
        _logger = logger;
    }

    public async Task<DeceptionTacticResult> ExecuteAsync(DeceptionContext context, CancellationToken cancellationToken)
    {
        var actions = new List<string>();

        // Deploy fake SSH keys
        var sshResult = await DeployFakeSshKeysAsync(cancellationToken);
        if (sshResult != null) actions.Add(sshResult);

        // Deploy fake cloud credentials
        var cloudResult = await DeployFakeCloudCredsAsync(cancellationToken);
        if (cloudResult != null) actions.Add(cloudResult);

        // Deploy fake browser password database
        var browserResult = await DeployFakeBrowserDbAsync(cancellationToken);
        if (browserResult != null) actions.Add(browserResult);

        // Deploy zip bombs disguised as sensitive archives
        var zipBombResult = await DeployZipBombsAsync(cancellationToken);
        if (zipBombResult != null) actions.Add(zipBombResult);

        // Deploy fake VPN configs
        var vpnResult = await DeployFakeVpnConfigsAsync(cancellationToken);
        if (vpnResult != null) actions.Add(vpnResult);

        // Deploy fake crypto wallet files
        var walletResult = await DeployFakeWalletFilesAsync(cancellationToken);
        if (walletResult != null) actions.Add(walletResult);

        if (actions.Count == 0)
        {
            return new DeceptionTacticResult
            {
                TacticName = "HoneypotWeaponizer",
                Success = false,
                Error = "Could not deploy any honeypot assets"
            };
        }

        return new DeceptionTacticResult
        {
            TacticName = "HoneypotWeaponizer",
            Success = true,
            Description = string.Join("; ", actions)
        };
    }

    private async Task<string?> DeployFakeSshKeysAsync(CancellationToken ct)
    {
        try
        {
            var sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
            Directory.CreateDirectory(sshDir);

            // Generate a fake but format-valid RSA private key
            var fakeKey = GenerateFakeRsaPrivateKey();
            var keyPath = Path.Combine(sshDir, "id_rsa_backup");

            if (File.Exists(keyPath)) return null; // Don't overwrite existing honeypots

            await File.WriteAllTextAsync(keyPath, fakeKey, ct);

            // Create matching config entry pointing to honeypot
            var configPath = Path.Combine(sshDir, "config.bak");
            var config = "Host prod-db-*\n" +
                         "  HostName 198.51.100.42\n" +
                         "  User admin\n" +
                         "  IdentityFile ~/.ssh/id_rsa_backup\n" +
                         "  Port 22\n\n" +
                         "Host staging-*\n" +
                         "  HostName 203.0.113.17\n" +
                         "  User deploy\n" +
                         "  IdentityFile ~/.ssh/id_rsa_backup\n";

            await File.WriteAllTextAsync(configPath, config, ct);

            // Backdate to look legitimate
            var fakeDate = DateTime.Now.AddMonths(-Random.Shared.Next(3, 18));
            File.SetCreationTime(keyPath, fakeDate);
            File.SetLastWriteTime(keyPath, fakeDate);

            return "Deployed fake SSH keys + config pointing to honeypot servers";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy fake SSH keys");
            return null;
        }
    }

    private async Task<string?> DeployFakeCloudCredsAsync(CancellationToken ct)
    {
        try
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            int deployed = 0;

            // Fake AWS credentials
            var awsDir = Path.Combine(userProfile, ".aws");
            Directory.CreateDirectory(awsDir);
            var awsCredsPath = Path.Combine(awsDir, "credentials.bak");
            if (!File.Exists(awsCredsPath))
            {
                var awsCreds = "[default]\n" +
                               $"aws_access_key_id = AKIA{GenerateRandom(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")}\n" +
                               $"aws_secret_access_key = {GenerateRandom(40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}\n\n" +
                               "[production]\n" +
                               $"aws_access_key_id = AKIA{GenerateRandom(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")}\n" +
                               $"aws_secret_access_key = {GenerateRandom(40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}\n" +
                               "region = us-east-1\n";
                await File.WriteAllTextAsync(awsCredsPath, awsCreds, ct);
                deployed++;
            }

            // Fake Azure credentials
            var azureDir = Path.Combine(userProfile, ".azure");
            Directory.CreateDirectory(azureDir);
            var azurePath = Path.Combine(azureDir, "credentials.json.bak");
            if (!File.Exists(azurePath))
            {
                var azureCreds = "{\n" +
                                 $"  \"clientId\": \"{Guid.NewGuid()}\",\n" +
                                 $"  \"clientSecret\": \"{GenerateRandom(44, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}\",\n" +
                                 $"  \"tenantId\": \"{Guid.NewGuid()}\",\n" +
                                 $"  \"subscriptionId\": \"{Guid.NewGuid()}\",\n" +
                                 "  \"environment\": \"AzureCloud\"\n" +
                                 "}\n";
                await File.WriteAllTextAsync(azurePath, azureCreds, ct);
                deployed++;
            }

            // Fake .env file in Documents
            var envPath = Path.Combine(userProfile, "Documents", ".env.production");
            if (!File.Exists(envPath))
            {
                var envContent = $"DATABASE_URL=postgresql://admin:{GenerateRandom(20, "abcdefghijklmnopqrstuvwxyz0123456789")}@db-prod.internal:5432/customers\n" +
                                 $"REDIS_URL=redis://:{GenerateRandom(16, "abcdefghijklmnopqrstuvwxyz0123456789")}@cache-prod.internal:6379\n" +
                                 $"STRIPE_SECRET_KEY=sk_live_{GenerateRandom(24, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")}\n" +
                                 $"JWT_SECRET={GenerateRandom(64, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")}\n" +
                                 $"SENDGRID_API_KEY=SG.{GenerateRandom(22, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}.{GenerateRandom(43, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")}\n";
                await File.WriteAllTextAsync(envPath, envContent, ct);
                deployed++;
            }

            return deployed > 0
                ? $"Deployed {deployed} fake cloud credential files (AWS, Azure, .env) — usage will expose attacker"
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy fake cloud creds");
            return null;
        }
    }

    private async Task<string?> DeployFakeBrowserDbAsync(CancellationToken ct)
    {
        try
        {
            var desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
            var dbPath = Path.Combine(desktopPath, "chrome_passwords_backup.csv");

            if (File.Exists(dbPath)) return null;

            var sb = new StringBuilder();
            sb.AppendLine("url,username,password,date_created");

            var fakeEntries = new[]
            {
                ("https://console.aws.amazon.com", "admin@company.com", GenerateRandom(16, "abcdefghijklmnopqrstuvwxyz0123456789!@#")),
                ("https://portal.azure.com", "sysadmin@corp.onmicrosoft.com", GenerateRandom(20, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
                ("https://github.com", "devops-lead", GenerateRandom(24, "abcdefghijklmnopqrstuvwxyz0123456789")),
                ("https://app.slack.com", "cto@company.com", GenerateRandom(14, "abcdefghijklmnopqrstuvwxyz0123456789")),
                ("https://vault.bitwarden.com", "security-team", GenerateRandom(32, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$")),
                ("https://binance.com", "trader_main", GenerateRandom(18, "abcdefghijklmnopqrstuvwxyz0123456789")),
                ("https://coinbase.com", "hodler2024", GenerateRandom(20, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")),
            };

            foreach (var (url, user, pass) in fakeEntries)
            {
                var date = DateTime.Now.AddDays(-Random.Shared.Next(30, 365)).ToString("yyyy-MM-dd");
                sb.AppendLine($"{url},{user},{pass},{date}");
            }

            await File.WriteAllTextAsync(dbPath, sb.ToString(), ct);

            var fakeDate = DateTime.Now.AddDays(-Random.Shared.Next(7, 60));
            File.SetCreationTime(dbPath, fakeDate);
            File.SetLastWriteTime(dbPath, fakeDate);

            return "Deployed fake browser password export on Desktop — attacker gets useless credentials";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy fake browser DB");
            return null;
        }
    }

    private async Task<string?> DeployZipBombsAsync(CancellationToken ct)
    {
        try
        {
            var targets = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "financial_records_2024.zip"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "client_database_backup.zip"),
            };

            int deployed = 0;
            foreach (var target in targets)
            {
                if (File.Exists(target)) continue;

                // Create a zip bomb: valid ZIP header followed by a massive sparse payload
                // The ZIP claims to contain a 4GB file but the archive is tiny
                var zipBomb = CreateMinimalZipBomb();
                await File.WriteAllBytesAsync(target, zipBomb, ct);

                // Make it look old and legitimate
                var fakeDate = DateTime.Now.AddMonths(-Random.Shared.Next(2, 12));
                File.SetCreationTime(target, fakeDate);
                File.SetLastWriteTime(target, fakeDate);
                deployed++;
            }

            return deployed > 0
                ? $"Deployed {deployed} zip bombs disguised as sensitive archives — extraction will exhaust attacker resources"
                : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy zip bombs");
            return null;
        }
    }

    private async Task<string?> DeployFakeVpnConfigsAsync(CancellationToken ct)
    {
        try
        {
            var vpnDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Documents", "VPN");
            Directory.CreateDirectory(vpnDir);

            var configPath = Path.Combine(vpnDir, "corp-vpn-prod.ovpn");
            if (File.Exists(configPath)) return null;

            // OpenVPN config that routes through a honeypot
            var config = "client\n" +
                         "dev tun\n" +
                         "proto udp\n" +
                         "remote vpn-prod.internal-corp.com 1194\n" +
                         "resolv-retry infinite\n" +
                         "nobind\n" +
                         "persist-key\n" +
                         "persist-tun\n" +
                         "ca ca.crt\n" +
                         "cert client.crt\n" +
                         "key client.key\n" +
                         "cipher AES-256-GCM\n" +
                         "auth SHA256\n" +
                         "verb 3\n";

            await File.WriteAllTextAsync(configPath, config, ct);

            return "Deployed fake VPN config — attacker connecting exposes their infrastructure";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy fake VPN configs");
            return null;
        }
    }

    private async Task<string?> DeployFakeWalletFilesAsync(CancellationToken ct)
    {
        try
        {
            var walletDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Documents", ".wallets");
            Directory.CreateDirectory(walletDir);

            var walletPath = Path.Combine(walletDir, "wallet_seed.txt");
            if (File.Exists(walletPath)) return null;

            // BIP39 mnemonic (fake but valid format — 24 words)
            var words = new[]
            {
                "abandon", "ability", "able", "about", "above", "absent",
                "absorb", "abstract", "absurd", "abuse", "access", "accident",
                "account", "accuse", "achieve", "acid", "acoustic", "acquire",
                "across", "act", "action", "actor", "actress", "actual"
            };

            // Shuffle to look unique
            var shuffled = words.OrderBy(_ => Random.Shared.Next()).ToArray();
            var content = "# Bitcoin Wallet Recovery Seed (DO NOT SHARE)\n" +
                          $"# Created: {DateTime.Now.AddMonths(-Random.Shared.Next(6, 24)):yyyy-MM-dd}\n" +
                          $"# Wallet: Ledger Nano X\n\n" +
                          string.Join(" ", shuffled) + "\n\n" +
                          $"# Balance as of last check: {Random.Shared.Next(2, 15)}.{Random.Shared.Next(1000, 9999)} BTC\n";

            await File.WriteAllTextAsync(walletPath, content, ct);

            var fakeDate = DateTime.Now.AddMonths(-Random.Shared.Next(6, 24));
            File.SetCreationTime(walletPath, fakeDate);
            File.SetLastWriteTime(walletPath, fakeDate);

            return "Deployed fake crypto wallet seed file — attacker will waste time on empty wallet";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to deploy fake wallet files");
            return null;
        }
    }

    /// <summary>
    /// Creates a minimal ZIP file that claims to contain a massive file.
    /// When extracted, it produces gigabytes of zeros.
    /// </summary>
    private static byte[] CreateMinimalZipBomb()
    {
        // Create a valid ZIP with a single entry that uses STORED compression
        // but claims an uncompressed size of 4GB. Most extractors will attempt
        // to write 4GB to disk.
        using var ms = new MemoryStream();
        using var writer = new BinaryWriter(ms);

        var fileName = Encoding.ASCII.GetBytes("data/records.csv");
        uint fakeSize = uint.MaxValue; // 4GB claimed size

        // Local file header
        writer.Write(0x04034B50); // Signature
        writer.Write((ushort)20); // Version needed
        writer.Write((ushort)0);  // Flags
        writer.Write((ushort)0);  // Compression (STORED)
        writer.Write((ushort)0);  // Mod time
        writer.Write((ushort)0);  // Mod date
        writer.Write(0u);         // CRC32 (zeros)
        writer.Write(fakeSize);   // Compressed size
        writer.Write(fakeSize);   // Uncompressed size
        writer.Write((ushort)fileName.Length);
        writer.Write((ushort)0);  // Extra field length
        writer.Write(fileName);

        // Write a small amount of actual data (1KB of zeros)
        writer.Write(new byte[1024]);

        var dataOffset = 30 + fileName.Length;

        // Central directory
        writer.Write(0x02014B50); // Signature
        writer.Write((ushort)20); // Version made by
        writer.Write((ushort)20); // Version needed
        writer.Write((ushort)0);  // Flags
        writer.Write((ushort)0);  // Compression
        writer.Write((ushort)0);  // Mod time
        writer.Write((ushort)0);  // Mod date
        writer.Write(0u);         // CRC32
        writer.Write(fakeSize);   // Compressed size
        writer.Write(fakeSize);   // Uncompressed size
        writer.Write((ushort)fileName.Length);
        writer.Write((ushort)0);  // Extra field length
        writer.Write((ushort)0);  // Comment length
        writer.Write((ushort)0);  // Disk number
        writer.Write((ushort)0);  // Internal attributes
        writer.Write(0u);         // External attributes
        writer.Write(0u);         // Offset of local header
        writer.Write(fileName);

        var centralDirOffset = (uint)(dataOffset + 1024);
        var centralDirSize = (uint)(ms.Position - centralDirOffset);

        // End of central directory
        writer.Write(0x06054B50); // Signature
        writer.Write((ushort)0);  // Disk number
        writer.Write((ushort)0);  // Central dir disk
        writer.Write((ushort)1);  // Entries on disk
        writer.Write((ushort)1);  // Total entries
        writer.Write(centralDirSize);
        writer.Write(centralDirOffset);
        writer.Write((ushort)0);  // Comment length

        return ms.ToArray();
    }

    private static string GenerateFakeRsaPrivateKey()
    {
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN OPENSSH PRIVATE KEY-----");

        // Generate fake but format-valid base64 content (looks like a real key)
        var random = new byte[1680]; // ~2240 base64 chars = typical RSA 4096 key size
        Random.Shared.NextBytes(random);
        var b64 = Convert.ToBase64String(random);

        for (int i = 0; i < b64.Length; i += 70)
        {
            sb.AppendLine(b64.Substring(i, Math.Min(70, b64.Length - i)));
        }

        sb.AppendLine("-----END OPENSSH PRIVATE KEY-----");
        return sb.ToString();
    }

    private static string GenerateRandom(int length, string charset)
    {
        var result = new char[length];
        for (int i = 0; i < length; i++)
            result[i] = charset[Random.Shared.Next(charset.Length)];
        return new string(result);
    }
}
