namespace Sentinel.Engine.Actions;

// 05 §3: per-module permission levels. Stored in settings, enforced
// by the dispatcher. Drivers and Threats are capped at L2 inside
// the permission provider itself, so no settings edit, agent, or
// caller can raise them (the cap lives below every caller).
public enum PermissionLevel
{
    L0 = 0,
    L1 = 1,
    L2 = 2,
    L3 = 3,
}

// 05 §4 lifecycle. Only Active templates may execute; every other
// status is a distinct, audited refusal at the dispatcher.
public enum TemplateStatus
{
    // May execute via Confirm Sheet (or the L3 envelope where
    // lawful). Only clean_items_to_vault in v1.
    Active,

    // In the 05 §4 registry, but no executor is wired yet —
    // refused as NotImplemented, never silent.
    Registered,

    // Explicitly suspended (startup items: a Run/RunOnce write IS
    // a registry write, forbidden by 05 §10.1 in v1).
    Suspended,

    // Proposed, not lawful: cannot execute until owner-approved
    // here plus the four tests of 04.
    Proposed,
}

public sealed record ActionTemplate(
    string Id,
    TemplateStatus Status,
    string Module,
    string Title,
    PermissionLevel MinLevel,
    bool RequiresElevation,
    bool RequiresRestorePoint,
    string BackupKind,
    string VerifyStep,
    string RollbackStep);

// E30: the ONLY things the executor may ever do (05 §4, verbatim).
// Unknown IDs (anything not listed here, including the explicitly
// NOT-proposed orphan-registry cleanup) are refused as unknown.
// Adding a template requires an owner-approved edit HERE plus the
// four tests of 04 — there is no dynamic registration path.
public static class ActionRegistry
{
    private static readonly ActionTemplate[] Templates =
    [
        new("clean_items_to_vault", TemplateStatus.Active, "Cleaner",
            "Move selected items to the Sentinel Vault",
            PermissionLevel.L2, RequiresElevation: false, RequiresRestorePoint: false,
            BackupKind: "Sentinel Vault record (Sentinel-controlled store with retention review)",
            VerifyStep: "Vault record complete + retained bytes accounted; free-space delta reported separately",
            RollbackStep: "Restore from Vault"),
        new("disable_startup_item", TemplateStatus.Suspended, "Startup",
            "Disable a startup entry",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: false,
            BackupKind: "Registry/task state snapshot",
            VerifyStep: "Registry/task state (when lawful)",
            RollbackStep: "enable_startup_item"),
        new("enable_startup_item", TemplateStatus.Suspended, "Startup",
            "Re-enable a startup entry",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: false,
            BackupKind: "Registry/task state snapshot",
            VerifyStep: "Registry/task state (when lawful)",
            RollbackStep: "disable_startup_item"),
        // D42: ACTIVATED by GOAL D42 (owner-approved task): executors
        // registered in MainViewModel, elevated-process model (D41),
        // restore-point precondition, live runs in the VM battery.
        new("driver_update_from_ladder", TemplateStatus.Active, "Drivers",
            "Update a driver from Windows Update or the OEM catalogue",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: true,
            BackupKind: "System restore point + previous driver identity",
            VerifyStep: "Device status OK post-install",
            RollbackStep: "driver_rollback (automatic on verify failure)"),
        new("driver_rollback", TemplateStatus.Active, "Drivers",
            "Roll a driver back to its previous version",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: true,
            BackupKind: "System restore point",
            VerifyStep: "Device status OK post-rollback",
            RollbackStep: "driver_update_from_ladder"),
        new("defender_scan", TemplateStatus.Active, "Threats",
            "Run a Windows Defender scan and import results",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: false,
            BackupKind: "None (Sentinel modifies nothing; results imported)",
            VerifyStep: "Defender reports a completed scan",
            RollbackStep: "None needed (read-only for Sentinel)"),
        // T52: ACTIVATED by GOAL T52 (owner-approved task). The
        // registered copy promised a "re-quarantine offer" — no
        // supported MpCmdRun verb quarantines an arbitrary file
        // (DEC-REQUARANTINE), so BackupKind/RollbackStep now state
        // the supported reversibility: a Defender scan re-detects.
        new("quarantine_restore", TemplateStatus.Active, "Threats",
            "Restore a Defender-quarantined item (reversible)",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: false,
            BackupKind: "Audit entry (Sentinel cannot re-quarantine; a Defender scan re-detects restored threats)",
            VerifyStep: "Name gone from current quarantine list",
            RollbackStep: "Re-run a Defender scan (Defender-owned)"),
        new("create_restore_point", TemplateStatus.Registered, "System",
            "Create a system restore point",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: false,
            BackupKind: "None (this IS the backup)",
            VerifyStep: "Restore point listed by the OS",
            RollbackStep: "None (restore points expire by OS policy)"),
        new("export_report", TemplateStatus.Registered, "System",
            "Write a report file to a user-chosen path",
            PermissionLevel.L2, RequiresElevation: false, RequiresRestorePoint: false,
            BackupKind: "None (a new file is written; nothing is removed)",
            VerifyStep: "File exists with the exported bytes",
            RollbackStep: "Delete the exported file"),
        new("update_knowledge_pack", TemplateStatus.Registered, "System",
            "Install a signed knowledge pack",
            PermissionLevel.L2, RequiresElevation: false, RequiresRestorePoint: false,
            BackupKind: "Previous pack version retained",
            VerifyStep: "Pack signature valid + version recorded",
            RollbackStep: "Reinstall the previous pack"),
        new("quarantine_file_via_defender", TemplateStatus.Proposed, "Threats",
            "Quarantine one user-selected file via Defender (PROPOSED)",
            PermissionLevel.L2, RequiresElevation: true, RequiresRestorePoint: false,
            BackupKind: "Defender quarantine",
            VerifyStep: "Defender confirms quarantine",
            RollbackStep: "quarantine_restore"),
        new("second_opinion_file_check", TemplateStatus.Proposed, "Threats",
            "Hash/signer-first second-opinion check (PROPOSED)",
            PermissionLevel.L2, RequiresElevation: false, RequiresRestorePoint: false,
            BackupKind: "None (read-only check)",
            VerifyStep: "Verdict recorded with evidence",
            RollbackStep: "None needed"),
    ];

    public static IReadOnlyList<ActionTemplate> All => Templates;

    // Ordinal: template IDs are code constants, never user text.
    // Null, empty, or wrong-case IDs are unknown, never fuzzy.
    public static ActionTemplate? Find(string? id)
    {
        if (string.IsNullOrEmpty(id))
        {
            return null;
        }

        foreach (var template in Templates)
        {
            if (string.Equals(template.Id, id, StringComparison.Ordinal))
            {
                return template;
            }
        }

        return null;
    }

    public static bool IsKnown(string? id) => Find(id) is not null;
}
