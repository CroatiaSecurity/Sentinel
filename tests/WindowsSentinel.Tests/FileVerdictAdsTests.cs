using System;
using System.IO;
using System.Text;
using Xunit;
using WindowsSentinel.Core;

namespace WindowsSentinel.Tests
{
    public class FileVerdictAdsTests
    {
        [Fact]
        public void FileVerdictAds_CreatesSecureDirAndHmacKey()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                var ads = new FileVerdictAds(tempDir);
                var keyFilePath = Path.Combine(tempDir, "ads_hmac.key");

                Assert.True(Directory.Exists(tempDir));
                Assert.True(File.Exists(keyFilePath));
                
                // Verify directory has restricted ACLs
                var dirInfo = new DirectoryInfo(tempDir);
                var security = dirInfo.GetAccessControl();
                Assert.True(security.AreAccessRulesProtected);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_PersistsAndLoadsSameKey()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            try
            {
                // First initialization creates the key
                var ads1 = new FileVerdictAds(tempDir);
                var keyFilePath = Path.Combine(tempDir, "ads_hmac.key");
                Assert.True(File.Exists(keyFilePath));
                var keyBytes1 = File.ReadAllBytes(keyFilePath);

                // Second initialization should read and use the exact same key
                var ads2 = new FileVerdictAds(tempDir);
                var keyBytes2 = File.ReadAllBytes(keyFilePath);

                Assert.Equal(keyBytes1, keyBytes2);
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_CanSetAndGetVerdict()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var testFile = Path.Combine(tempDir, "test_target.exe");

            try
            {
                File.WriteAllText(testFile, "dummy executable content");
                var sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // example sha256

                var ads = new FileVerdictAds(tempDir);
                
                // Verify initial verdict is Unknown
                Assert.Equal(HashVerdict.Unknown, ads.GetVerdict(testFile, sha256));

                // Set verdict to Safe
                ads.SetVerdict(testFile, sha256, HashVerdict.Safe);
                Assert.Equal(HashVerdict.Safe, ads.GetVerdict(testFile, sha256));

                // Set verdict to Unsafe
                ads.SetVerdict(testFile, sha256, HashVerdict.Unsafe);
                Assert.Equal(HashVerdict.Unsafe, ads.GetVerdict(testFile, sha256));
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }

        [Fact]
        public void FileVerdictAds_RejectsModifiedSignatureOrMismatchingHash()
        {
            var tempDir = Path.Combine(Path.GetTempPath(), "sentinel_ads_test_" + Guid.NewGuid().ToString("N")[..8]);
            Directory.CreateDirectory(tempDir);
            var testFile = Path.Combine(tempDir, "test_target2.exe");

            try
            {
                File.WriteAllText(testFile, "dummy content");
                var sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                var ads = new FileVerdictAds(tempDir);
                ads.SetVerdict(testFile, sha256, HashVerdict.Unsafe);

                // Mismatching SHA256 should return Unknown
                Assert.Equal(HashVerdict.Unknown, ads.GetVerdict(testFile, "different_sha256_hash_here_12345678"));

                // Corrupt signature in Alternate Data Stream
                var adsPath = $"{testFile}:sentinel_verdict";
                Assert.True(File.Exists(adsPath));
                var payload = File.ReadAllText(adsPath);
                
                // Tamper with the payload (e.g. corrupting the signature hex part)
                var parts = payload.Split('|');
                parts[3] = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"; // fake hmac signature
                var corruptedPayload = string.Join('|', parts);
                File.WriteAllText(adsPath, corruptedPayload);

                // Verdict should be rejected and return Unknown
                Assert.Equal(HashVerdict.Unknown, ads.GetVerdict(testFile, sha256));
            }
            finally
            {
                try { Directory.Delete(tempDir, true); } catch { }
            }
        }
    }
}
