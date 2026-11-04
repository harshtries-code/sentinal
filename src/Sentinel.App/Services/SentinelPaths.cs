using System.IO;
using Sentinel.Store;

namespace Sentinel.App.Services;

public static class SentinelPaths
{
    public static string DataDirectory
    {
        get
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var dir = Path.Combine(
                string.IsNullOrEmpty(local) ? Path.GetTempPath() : local,
                "Sentinel");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }

    // Legacy anchor: pre-split installs keep their single file here
    // until the first open split-migrates it (the file is renamed to
    // a backup, never deleted). New code opens the pair below.
    public static string DatabasePath => Path.Combine(DataDirectory, "sentinel.db");

    // P26: the path getters ensure the split, so EVERY entry point
    // (scans, pages, recovery) sees migrated files — no caller can
    // strand a legacy store by opening one half directly.
    public static string PassportDatabasePath
    {
        get
        {
            StoreLayout.EnsureSplit(DatabasePath);
            return StoreLayout.DerivePassportPath(DatabasePath);
        }
    }

    public static string FingerprintDatabasePath
    {
        get
        {
            StoreLayout.EnsureSplit(DatabasePath);
            return StoreLayout.DeriveFingerprintPath(DatabasePath);
        }
    }

    public static string AgentDatabasePath => Path.Combine(DataDirectory, "sentinel-agent.db");

    public static string VaultDatabasePath =>
        StoreLayout.DeriveVaultDbPath(DatabasePath);

    public static string AuditDatabasePath =>
        StoreLayout.DeriveAuditDbPath(DatabasePath);

    public static string VaultDirectory =>
        StoreLayout.DeriveVaultDir(DatabasePath);

    public static string SettingsPath => Path.Combine(DataDirectory, "settings.json");

    public static string ReportsDirectory
    {
        get
        {
            string dir = Path.Combine(DataDirectory, "Reports");
            Directory.CreateDirectory(dir);
            return dir;
        }
    }
}
