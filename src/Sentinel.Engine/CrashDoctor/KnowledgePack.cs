namespace Sentinel.Engine.CrashDoctor;

// Windows knowledge pack v1 (01 §5.5): curated, versioned, LOCAL.
// Bug-check codes, common Event IDs, and driver/module vendors the
// explainer and the AI may cite. Anything NOT in the pack is
// reported as "no pack entry" — the product never invents a cause.
// Signed pack updates arrive via the update_knowledge_pack template
// (05 §4); v1 ships compiled in for reviewability.
public static class KnowledgePack
{
    public const string PackVersion = "1.0.0";

    public enum Confidence
    {
        Low,
        Medium,
        High,
    }

    public sealed record LikelyCause(
        string Text,
        Confidence BaseConfidence,
        string RaiseWhen);

    public sealed record PackEntry(
        string Key,
        string Title,
        IReadOnlyList<LikelyCause> Causes,
        IReadOnlyList<string> Prevention);

    public static PackEntry? FindBugCheck(uint code) =>
        BugChecks.TryGetValue(code, out var entry) ? entry : null;

    public static PackEntry? FindEvent(string provider, int id) =>
        Events.TryGetValue(provider.ToUpperInvariant() + "#" + id, out var entry) ? entry : null;

    public static string? FindVendor(string moduleName)
    {
        string key = moduleName.Trim().ToLowerInvariant();
        if (key.Length == 0)
        {
            return null;
        }

        return Vendors.TryGetValue(key, out var vendor) ? vendor : null;
    }

    private static readonly IReadOnlyDictionary<uint, PackEntry> BugChecks =
        new Dictionary<uint, PackEntry>
        {
            [0x124] = new PackEntry(
                "BC:0x124",
                "WHEA uncorrectable hardware error",
                [
                    new("A hardware component reported a fatal error (CPU, RAM, PCIe, or chipset).",
                        Confidence.High, "a WHEA event names the component"),
                    new("Overheating or an unstable overclock pushed hardware past its limits.",
                        Confidence.Medium, "crashes happen under load or heat"),
                ],
                [
                    "Check temperatures and fans; undo any overclock.",
                    "Run the PC maker's hardware diagnostics and a memory test.",
                    "Update BIOS/chipset firmware from the maker's official page.",
                ]),
            [0x133] = new PackEntry(
                "BC:0x133",
                "Driver watchdog timeout (DPC)",
                [
                    new("A driver took too long in a deferred procedure call — often storage, network, or audio.",
                        Confidence.High, "an implicated driver file is named"),
                    new("A failing SSD or hard disk stalled I/O until the watchdog fired.",
                        Confidence.Medium, "disk warnings (Event 153/55) appear nearby"),
                ],
                [
                    "Update storage controller, chipset, and network drivers from official sources.",
                    "Check disk health and cables; back up if warnings repeat.",
                    "Remove recently added external devices one at a time.",
                ]),
            [0xEF] = new PackEntry(
                "BC:0xEF",
                "Critical Windows process died",
                [
                    new("Corrupt system files stopped a process Windows cannot run without.",
                        Confidence.Medium, "SFC/DISM report corruption"),
                    new("A bad driver or update destabilized the system.",
                        Confidence.Medium, "crashes started right after an update"),
                    new("A failing disk corrupted data the system trusted.",
                        Confidence.Medium, "disk warnings appear nearby"),
                ],
                [
                    "Run System File Checker (sfc /scannow) and DISM restore-health.",
                    "Roll back the most recent driver or update if timing matches.",
                    "Back up, then check the disk for errors.",
                ]),
            [0x50] = new PackEntry(
                "BC:0x50",
                "Bad memory reference (page fault)",
                [
                    new("Faulty RAM returned bad data.",
                        Confidence.High, "crashes are random with different apps"),
                    new("A driver touched memory it had already freed.",
                        Confidence.Medium, "an implicated driver file is named"),
                    new("A corrupt pagefile or disk served a bad page.",
                        Confidence.Low, "disk warnings appear nearby"),
                ],
                [
                    "Run Windows Memory Diagnostic (extended, overnight if possible).",
                    "Update drivers, newest-first by install date.",
                    "Run chkdsk on the system drive at next restart.",
                ]),
            [0x7E] = new PackEntry(
                "BC:0x7E",
                "System thread threw an unhandled error",
                [
                    new("The named driver crashed inside a system thread.",
                        Confidence.High, "an implicated driver file is named"),
                    new("An outdated BIOS mishandled a system call.",
                        Confidence.Low, "no driver is named and BIOS is old"),
                ],
                [
                    "Update or roll back the named driver from an official source.",
                    "Update the BIOS from the PC maker's page if it is years old.",
                ]),
            [0x3B] = new PackEntry(
                "BC:0x3B",
                "System service threw an error",
                [
                    new("A driver or system service mishandled a request.",
                        Confidence.Medium, "an implicated driver file is named"),
                    new("Corrupt system files broke a service path.",
                        Confidence.Low, "SFC/DISM report corruption"),
                ],
                [
                    "Update the named driver; run SFC if none is named.",
                    "Remove recently installed system utilities one at a time.",
                ]),
            [0x1E] = new PackEntry(
                "BC:0x1E",
                "Kernel-mode program error",
                [
                    new("A driver hit a condition its code never handled.",
                        Confidence.Medium, "an implicated driver file is named"),
                    new("Faulty RAM flipped a kernel data structure.",
                        Confidence.Medium, "crashes are random with different codes"),
                ],
                [
                    "Update the named driver from an official source.",
                    "Run a memory test if codes vary crash to crash.",
                ]),
            [0x139] = new PackEntry(
                "BC:0x139",
                "Kernel safety check failed",
                [
                    new("A driver corrupted a kernel data structure.",
                        Confidence.Medium, "an implicated driver file is named"),
                    new("Faulty RAM or an unstable overclock corrupted kernel memory.",
                        Confidence.Medium, "memory is overclocked or crashes are random"),
                ],
                [
                    "Undo RAM/CPU overclocks first — this code loves them.",
                    "Update drivers; run a memory test next.",
                ]),
            [0x9F] = new PackEntry(
                "BC:0x9F",
                "Driver power failure (sleep/wake)",
                [
                    new("A driver mishandled sleep or wake — often Wi-Fi, GPU, or USB.",
                        Confidence.High, "crashes happen on sleep, wake, or lid-close"),
                ],
                [
                    "Update Wi-Fi, GPU, and chipset drivers from official sources.",
                    "In Device Manager, turn off 'allow this device to wake the computer' for suspects.",
                ]),
            [0xD1] = new PackEntry(
                "BC:0xD1",
                "Driver touched forbidden memory",
                [
                    new("The named driver read paged memory it must not touch.",
                        Confidence.High, "an implicated driver file is named"),
                ],
                [
                    "Update or roll back the named driver from an official source.",
                    "If it names the network stack, update network drivers too.",
                ]),
            [0xA] = new PackEntry(
                "BC:0xA",
                "Bad memory access at high priority",
                [
                    new("A driver or service read memory it should not have.",
                        Confidence.Medium, "an implicated driver file is named"),
                    new("Faulty RAM served a bad address.",
                        Confidence.Medium, "crashes are random with different apps"),
                ],
                [
                    "Update the named driver; test memory if none is named.",
                    "Remove recently added hardware drivers one at a time.",
                ]),
            [0x24] = new PackEntry(
                "BC:0x24",
                "NTFS filesystem driver fault",
                [
                    new("Filesystem corruption crashed the NTFS driver.",
                        Confidence.High, "Event 55 (NTFS) appears nearby"),
                    new("A failing disk or bad cable fed NTFS garbage.",
                        Confidence.Medium, "disk warnings appear nearby"),
                ],
                [
                    "Back up now, then run chkdsk on the affected drive.",
                    "Check SATA/NVMe seating and cables; check disk health.",
                ]),
            [0x7A] = new PackEntry(
                "BC:0x7A",
                "Could not read data from disk",
                [
                    new("A failing disk or loose cable broke a page-in.",
                        Confidence.High, "disk warnings appear nearby"),
                    new("Faulty RAM corrupted data in transit.",
                        Confidence.Medium, "memory test reports errors"),
                ],
                [
                    "Back up immediately — this code often precedes disk death.",
                    "Check cables and seating; test memory if the disk is healthy.",
                ]),
            [0x116] = new PackEntry(
                "BC:0x116",
                "Graphics driver recovery failed",
                [
                    new("The GPU driver crashed and Windows could not restart it.",
                        Confidence.High, "freezes/stutters precede the crash"),
                    new("An overheating or failing GPU stopped answering.",
                        Confidence.Medium, "crashes happen in games or heat"),
                ],
                [
                    "Clean-install the GPU driver from NVIDIA/AMD/Intel (not a mirror).",
                    "Check GPU temperatures and fans; test with games closed.",
                ]),
        };

    private static readonly IReadOnlyDictionary<string, PackEntry> Events =
        new Dictionary<string, PackEntry>(StringComparer.OrdinalIgnoreCase)
        {
            ["MICROSOFT-WINDOWS-KERNEL-POWER#41"] = new PackEntry(
                "EV:Kernel-Power#41",
                "Unexpected shutdown (Event 41)",
                [
                    new("Power was cut: outage, failing PSU/battery, or the power button held down.",
                        Confidence.Medium, "no bugcheck event follows"),
                    new("A crash rebooted the PC before Windows could write a bugcheck record.",
                        Confidence.Medium, "a BugCheck event (1001) exists nearby"),
                    new("Overheating forced an emergency shutdown.",
                        Confidence.Low, "shutdowns happen under load"),
                ],
                [
                    "Check power cable, outlet, and battery/PSU health.",
                    "Check temperatures; clean dust from vents and fans.",
                    "Look for a matching BugCheck 1001 event for the real cause.",
                ]),
            ["MICROSOFT-WINDOWS-WER-SYSTEMERRORREPORTING#1001"] = new PackEntry(
                "EV:BugCheck#1001",
                "Bugcheck record (Event 1001)",
                [
                    new("Windows captured the stop code and parameters — the pack entry for that code applies.",
                        Confidence.High, "always — this event carries the code"),
                ],
                [
                    "Read the stop code from this event, then follow that code's steps.",
                ]),
            ["EVENTLOG#6008"] = new PackEntry(
                "EV:EventLog#6008",
                "Previous shutdown was unexpected",
                [
                    new("Same family as Event 41: power, heat, or an unrecorded crash.",
                        Confidence.Medium, "an Event 41 exists at the same time"),
                ],
                [
                    "Follow the Event 41 steps for the same timestamp.",
                ]),
            ["APPLICATION ERROR#1000"] = new PackEntry(
                "EV:AppCrash#1000",
                "Application crashed (Event 1000)",
                [
                    new("The faulting module named in the event crashed the app.",
                        Confidence.High, "a faulting module is named"),
                    new("Corrupt app data or a bad update broke the app.",
                        Confidence.Medium, "only one app crashes"),
                ],
                [
                    "Update or repair the app; rename its data folder to test for corrupt state.",
                    "If a system DLL is named, run SFC and update drivers.",
                ]),
            ["APPLICATION HANG#1002"] = new PackEntry(
                "EV:AppHang#1002",
                "Application stopped responding (Event 1002)",
                [
                    new("The app deadlocked or waited forever on a resource.",
                        Confidence.Medium, "it hangs on the same action"),
                    new("A slow or failing disk starved the app of data.",
                        Confidence.Low, "disk warnings appear nearby"),
                ],
                [
                    "Update the app; test with add-ons disabled.",
                    "Check disk health if many apps hang together.",
                ]),
            ["NTFS#55"] = new PackEntry(
                "EV:NTFS#55",
                "Filesystem corruption (Event 55)",
                [
                    new("The filesystem structure is damaged — unsafe shutdowns, bad writes, or a failing disk.",
                        Confidence.High, "always — corruption is observed, not guessed"),
                ],
                [
                    "Back up, then run chkdsk on the named volume.",
                    "Check disk health; replace the drive if corruption returns.",
                ]),
            ["DISK#153"] = new PackEntry(
                "EV:disk#153",
                "Disk I/O warning (Event 153)",
                [
                    new("The disk retried a failed I/O — early failure sign, or a bad cable.",
                        Confidence.Medium, "warnings repeat on the same disk"),
                ],
                [
                    "Back up now; check cables and seating.",
                    "Watch disk health daily — repeated 153s mean replace soon.",
                ]),
            ["MICROSOFT-WINDOWS-WHEA-LOGGER#19"] = new PackEntry(
                "EV:WHEA#19",
                "Corrected hardware error (Event 19)",
                [
                    new("Hardware caught and fixed an error by itself — usually CPU or RAM.",
                        Confidence.Medium, "always — corrected, but counted"),
                ],
                [
                    "No panic for one; a rising count means run hardware diagnostics.",
                    "Check cooling — heat raises corrected-error rates.",
                ]),
        };

    private static readonly IReadOnlyDictionary<string, string> Vendors =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["ntoskrnl.exe"] = "Microsoft Windows kernel",
            ["hal.dll"] = "Microsoft hardware abstraction layer",
            ["nvlddmkm.sys"] = "NVIDIA graphics driver",
            ["amdkmdag.sys"] = "AMD graphics driver",
            ["igdkmd64.sys"] = "Intel graphics driver",
            ["dxgkrnl.sys"] = "Microsoft DirectX graphics",
            ["tcpip.sys"] = "Microsoft network stack",
            ["netio.sys"] = "Microsoft network I/O",
            ["ndis.sys"] = "Microsoft network driver interface",
            ["storport.sys"] = "Microsoft storage port driver",
            ["storahci.sys"] = "Microsoft SATA driver",
            ["ntfs.sys"] = "Microsoft NTFS filesystem",
            ["fltmgr.sys"] = "Microsoft filesystem filter manager",
            ["win32kfull.sys"] = "Microsoft windowing subsystem",
            ["usbhub3.sys"] = "Microsoft USB 3 driver",
            ["iastorac.sys"] = "Intel Rapid Storage driver",
            ["rtwlane.sys"] = "Realtek Wi-Fi driver",
            ["e1d65x64.sys"] = "Intel Ethernet driver",
        };
}
