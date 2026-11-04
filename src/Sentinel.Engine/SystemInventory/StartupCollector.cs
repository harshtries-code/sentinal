using System.Security;
using System.ServiceProcess;
using Microsoft.Win32;

namespace Sentinel.Engine.SystemInventory;

// READ-ONLY: startup surface (Run keys, Startup folders, services).
// Every unreadable key, folder, or service is a reported gap.
// Scheduled tasks arrive in Phase 2 with the persistence map.
// D45: enable/disable state comes from Task Manager's
// StartupApproved values (read-only); approvalReader is injectable
// so tests own the bytes while production reads the registry.
public static class StartupCollector
{
    private static readonly (RegistryHive Hive, string SubKey, string Location)[] RunKeys =
    [
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
        (RegistryHive.LocalMachine, @"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
    ];

    public static CollectionResult<StartupRecord> CollectRunKeys(
        Func<RegistryHive, string, string, byte[]?>? approvalReader = null)
    {
        const string scope = "Run/RunOnce keys (5 hives/views)";
        var observed = DateTime.UtcNow;
        var result = new List<StartupRecord>();
        var gaps = new List<CollectionGap>();
        approvalReader ??= StartupApproval.ReadLive;
        foreach (var (hive, subKey, location) in RunKeys)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = baseKey.OpenSubKey(subKey, writable: false);
                if (key is null)
                {
                    gaps.Add(new CollectionGap(location, "KeyAbsent"));
                    continue;
                }

                foreach (var name in key.GetValueNames())
                {
                    object? value;
                    try
                    {
                        value = key.GetValue(name);
                    }
                    catch (Exception ex) when (ex is SecurityException or IOException or UnauthorizedAccessException)
                    {
                        gaps.Add(new CollectionGap(location, "ValueUnreadable", name));
                        continue;
                    }

                    result.Add(new StartupRecord(name, location,
                        value?.ToString() ?? string.Empty,
                        ReadApproval(approvalReader, location, name, gaps)));
                }
            }
            catch (Exception ex) when (ex is SecurityException or IOException or UnauthorizedAccessException)
            {
                gaps.Add(new CollectionGap(location, "KeyUnreadable", ex.GetType().Name));
            }
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<StartupRecord>(status, result, scope, observed, gaps, false);
    }

    // One approval lookup: missing shelf/value reads unknown (null);
    // only a FAILED read is a gap — and one gap per location, not
    // per value, so a locked shelf doesn't spam.
    private static bool? ReadApproval(
        Func<RegistryHive, string, string, byte[]?> reader,
        string location, string name, List<CollectionGap> gaps)
    {
        var shelf = StartupApproval.ShelfFor(location);
        if (shelf is null)
        {
            return null;
        }

        try
        {
            return StartupApproval.ParseState(reader(shelf.Value.Hive, shelf.Value.SubKey, name));
        }
        catch (Exception ex) when (ex is SecurityException or IOException or UnauthorizedAccessException)
        {
            if (!gaps.Any(g => g.Source == location && g.Reason == "ApprovalUnreadable"))
            {
                gaps.Add(new CollectionGap(location, "ApprovalUnreadable", ex.GetType().Name));
            }

            return null;
        }
    }

    public static CollectionResult<StartupRecord> CollectStartupFolders(
        Func<RegistryHive, string, string, byte[]?>? approvalReader = null)
    {
        const string scope = "Startup folders (user + all users)";
        var observed = DateTime.UtcNow;
        var result = new List<StartupRecord>();
        var gaps = new List<CollectionGap>();
        var folders = new[]
        {
            (Environment.SpecialFolder.Startup, "Startup folder (user)"),
            (Environment.SpecialFolder.CommonStartup, "Startup folder (all users)"),
        };
        foreach (var (folder, location) in folders)
        {
            string path;
            try
            {
                path = Environment.GetFolderPath(folder);
            }
            catch (Exception ex)
            {
                gaps.Add(new CollectionGap(location, "PathUnknown", ex.GetType().Name));
                continue;
            }

            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
                gaps.Add(new CollectionGap(location, "FolderAbsent"));
                continue;
            }

            string[] entries;
            try
            {
                entries = Directory.GetFileSystemEntries(path);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                gaps.Add(new CollectionGap(location, "FolderUnreadable", ex.GetType().Name));
                continue;
            }

            foreach (var entry in entries)
            {
                // D45: presence no longer means enabled — a shortcut
                // disabled in Task Manager is still listed. Missing
                // approval reads Unknown (null), never inferred.
                result.Add(new StartupRecord(Path.GetFileName(entry), location, entry,
                    ReadApproval(approvalReader ??= StartupApproval.ReadLive,
                        location, Path.GetFileName(entry), gaps)));
            }
        }

        var status = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<StartupRecord>(status, result, scope, observed, gaps, false);
    }

    public static CollectionResult<ServiceRecord> CollectServices()
    {
        const string scope = "Windows services (name, display, status, start type)";
        var observed = DateTime.UtcNow;
        var result = new List<ServiceRecord>();
        ServiceController[] services;
        try
        {
            services = ServiceController.GetServices();
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return CollectionResult<ServiceRecord>.Fail(scope, "ServiceControlUnavailable", ex.GetType().Name);
        }

        var gaps = new List<CollectionGap>();
        foreach (var svc in services)
        {
            string status;
            string startType;
            try
            {
                status = svc.Status.ToString();
                startType = svc.StartType.ToString();
            }
            catch (Exception ex)
            {
                gaps.Add(new CollectionGap(svc.ServiceName, "ServiceUnreadable", ex.GetType().Name));
                continue;
            }

            result.Add(new ServiceRecord(svc.ServiceName, svc.DisplayName, status, startType));
            svc.Dispose();
        }

        var final = gaps.Count == 0 ? CollectionStatus.Success : CollectionStatus.Partial;
        return new CollectionResult<ServiceRecord>(final, result, scope, observed, gaps, false);
    }
}
