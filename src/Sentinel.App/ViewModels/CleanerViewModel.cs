using System.Collections.ObjectModel;
using System.IO;
using Sentinel.Engine.Actions;
using Sentinel.Engine.Policy;
using Sentinel.Engine.Scan;
using Sentinel.Store;

namespace Sentinel.App.ViewModels;

public sealed record TierRow(string Tier, int Files, string Bytes, long BytesRaw);

public sealed record ClassifiedRow(
    string Path, string Size, string Tier, string Reasons, string? Regrowth,
    long SizeRaw, string Modified, string? Hash, string? DeadTarget = null);

public sealed record OrphanRow(string Directory, string Signals);

public sealed record AppRow(
    string AppName, string Directory, long Files, long Bytes, bool Known,
    IReadOnlyList<AppLocation> Locations);

public enum StorageRowKind
{
    File,
    Orphan,
    Duplicate,
    App,
}

public sealed record StorageDetail(
    string FullPath, string Size, string Modified, string HashDisplay,
    string TierLine, string KnowLine, string VerifyLine, string EvidenceLine,
    IReadOnlyList<string> ExtraPaths, string? Regrowth);

// One selectable table row. Never-tier rows are visible but refuse
// selection (02 §7 refinement #6: protected is not disposable).
public sealed class StorageRow : ViewModelBase
{
    private bool _isSelected;

    public StorageRow(
        StorageRowKind kind, string name, string location, string size,
        long sizeRaw, string classification, string tier,
        bool selectable, StorageDetail detail)
    {
        Kind = kind;
        Name = name;
        Location = location;
        Size = size;
        SizeRaw = sizeRaw;
        Classification = classification;
        Tier = tier;
        IsSelectable = selectable;
        Detail = detail;
    }

    public StorageRowKind Kind { get; }

    public string Name { get; }

    public string Location { get; }

    public string Size { get; }

    public long SizeRaw { get; }

    public string Classification { get; }

    public string Tier { get; }

    public bool IsSelectable { get; }

    public StorageDetail Detail { get; }

    public bool IsSelected
    {
        get => _isSelected;
        set
        {
            if (!IsSelectable && value)
            {
                return;
            }

            Set(ref _isSelected, value);
        }
    }
}

public sealed record TreemapFile(string Name, long Bytes, string Path);

public sealed record TreemapCategory(
    string Key, long Bytes, IReadOnlyList<TreemapFile> TopFiles,
    long RestBytes, int RestCount);

// U22: the same buckets as ranked rows — the table half of the
// map/table toggle. Identical numbers to the treemap boxes, in a
// keyboard- and screen-reader-reachable grid.
public sealed record MapRankRow(
    string Key, string Size, string Share, string Files, bool Scopable);

// Storage page (02 §7, board 02, read-only): tier breakdown,
// treemap, filterable/selectable inventory table, per-row
// detail drawer, hibernation/pagefile notes. Selection drives
// review + copy only — acting stays a later phase.
//
// P22: every chip/search/scope combination is one bounded DB page
// over the stated inventory — never a filter over a hidden
// top-20 sample. Collect (background) refreshes classification +
// aggregates; LoadPage (milliseconds, sync) serves the table.
public sealed class CleanerViewModel : ViewModelBase
{
    // A09: versions navigation collects; faults surface here
    // with the last table kept.
    public RefreshTracker RefreshState { get; } = new();

    public const int PageSize = 100;

    // Single source for the filter chips. Plain {Binding} cannot see
    // static members, so the XAML binds the instance passthrough
    // (A02 VM: chips rendered blank until this existed).
    public static readonly IReadOnlyList<string> ChipNames =
        ["All", "Safe", "Review", "Never", "Duplicates", "Orphans", "Large", "Regrowing", "Apps"];

    public IReadOnlyList<string> Chips => ChipNames;

    private readonly Func<SentinelDb> _dbFactory;
    private readonly Func<IReadOnlyList<string>> _neverProvider;
    private readonly CleanerActionServices? _actions;

    public CleanerViewModel(
        Func<SentinelDb> dbFactory, Func<IReadOnlyList<string>> neverProvider,
        CleanerActionServices? actions = null)
    {
        _dbFactory = dbFactory;
        _neverProvider = neverProvider;
        _actions = actions;
    }

    public ObservableCollection<TierRow> Tiers { get; } = [];

    public ObservableCollection<StorageRow> Rows { get; } = [];

    public ObservableCollection<StorageRow> VisibleRows { get; } = [];

    public ObservableCollection<TreemapCategory> Treemap { get; } = [];

    public ObservableCollection<MapRankRow> RankedRows { get; } = [];

    // U22: "Map" (treemap canvas) or "Table" (ranked grid). Any
    // other value falls back to Map — the toggle only writes these.
    private string _mapViewMode = "Map";

    public string MapViewMode
    {
        get => _mapViewMode;
        private set
        {
            if (Set(ref _mapViewMode, value == "Table" ? "Table" : "Map"))
            {
                Raise(nameof(ShowMap));
                Raise(nameof(ShowTable));
            }
        }
    }

    public bool ShowMap => MapViewMode != "Table";

    public bool ShowTable => MapViewMode == "Table";

    public void SetMapView(string mode) => MapViewMode = mode;

    private string _summary = "Not inspected yet.";

    public string Summary
    {
        get => _summary;
        private set => Set(ref _summary, value);
    }

    private string _coverage = string.Empty;

    public string Coverage
    {
        get => _coverage;
        private set => Set(ref _coverage, value);
    }

    private string _scopeLine = "No scan yet · Logical file sizes";

    public string ScopeLine
    {
        get => _scopeLine;
        private set => Set(ref _scopeLine, value);
    }

    private string _lastScanLine = "Last scan: never";

    public string LastScanLine
    {
        get => _lastScanLine;
        private set => Set(ref _lastScanLine, value);
    }

    private string _reviewLine = "Nothing flagged to review";

    public string ReviewLine
    {
        get => _reviewLine;
        private set => Set(ref _reviewLine, value);
    }

    private string _unavailableLine = "—";

    public string UnavailableLine
    {
        get => _unavailableLine;
        private set => Set(ref _unavailableLine, value);
    }

    private string _limitsLine = string.Empty;

    public string LimitsLine
    {
        get => _limitsLine;
        private set => Set(ref _limitsLine, value);
    }

    private string _pageLabel = string.Empty;

    public string PageLabel
    {
        get => _pageLabel;
        private set => Set(ref _pageLabel, value);
    }

    private bool _hasPrevPage;

    public bool HasPrevPage
    {
        get => _hasPrevPage;
        private set => Set(ref _hasPrevPage, value);
    }

    private bool _hasNextPage;

    public bool HasNextPage
    {
        get => _hasNextPage;
        private set => Set(ref _hasNextPage, value);
    }

    private string _folderScopeLabel = string.Empty;

    public string FolderScopeLabel
    {
        get => _folderScopeLabel;
        private set
        {
            if (Set(ref _folderScopeLabel, value))
            {
                Raise(nameof(HasFolderScope));
            }
        }
    }

    public bool HasFolderScope => FolderScope.Count > 0;

    private string _selectedChip = "All";

    public string SelectedChip
    {
        get => _selectedChip;
        set
        {
            if (Set(ref _selectedChip, value))
            {
                PageIndex = 0;
                LoadPageIfApplied();
            }
        }
    }

    private string _searchText = string.Empty;

    public string SearchText
    {
        get => _searchText;
        set
        {
            if (Set(ref _searchText, value ?? string.Empty))
            {
                PageIndex = 0;
                LoadPageIfApplied();
            }
        }
    }

    private StorageRow? _selectedRow;

    public StorageRow? SelectedRow
    {
        get => _selectedRow;
        set => Set(ref _selectedRow, value);
    }

    private string _checkedLine = "Nothing selected";

    public string CheckedLine
    {
        get => _checkedLine;
        private set => Set(ref _checkedLine, value);
    }

    private bool _hasChecked;

    public bool HasChecked
    {
        get => _hasChecked;
        private set => Set(ref _hasChecked, value);
    }

    private string? _hibernationNote;

    public string? HibernationNote
    {
        get => _hibernationNote;
        private set => Set(ref _hibernationNote, value);
    }

    private string? _pagefileNote;

    public string? PagefileNote
    {
        get => _pagefileNote;
        private set => Set(ref _pagefileNote, value);
    }

    public bool HasVisibleRows => VisibleRows.Count > 0;

    private string _emptyRowsText = "No inventory yet — run a scan first.";

    public string EmptyRowsText
    {
        get => _emptyRowsText;
        private set => Set(ref _emptyRowsText, value);
    }

    // Paging + scope state. Checked paths survive page turns (the
    // set, not row VMs, is the selection memory).
    public int PageIndex { get; private set; }

    public IReadOnlyList<string> FolderScope { get; private set; } = [];

    // U22: checked entries carry their mix key (tier or group
    // kind) so the selection summary shows the risk mix, not just
    // a count. Path -> (size, mix key).
    private readonly Dictionary<string, (long Size, string Mix)> _checked =
        new(StringComparer.OrdinalIgnoreCase);

    private List<string> _orphanDirs = [];

    private IReadOnlyList<AppGroup> _appGroups = [];

    private IReadOnlyList<AppOwnership> _appOwnerships = [];

    private IReadOnlyList<UninstallEntry> _uninstallEntries = [];

    private int _appliedGeneration;

    // E33: the scan roots the approval scope is built from — the
    // INVENTORY's scope, never derived from the selected targets
    // (deriving scope from targets would void scope protection).
    private IReadOnlyList<string> _appliedScopeRoots = [];

    private bool _applied;

    public void Refresh() => Apply(Collect(_dbFactory, _neverProvider()));

    public static CleanerSnapshot Collect(Func<SentinelDb> dbFactory, IReadOnlyList<string> neverList)
    {
        using var db = dbFactory();
        long totalFiles = db.CountFingerprints();
        long totalBytes = db.SumFingerprintBytes();
        var now = DateTime.UtcNow;

        // P22: classification + orphan verdicts are cached in the DB
        // (incremental: new/changed rows only, unless the Never list
        // changed). No cancellation here: PageRefresh drops stale
        // results on navigate-away, and classified rows persist, so
        // a dropped pass still did useful work.
        new InventoryClassifier(db, neverList)
            .EnsureClassified(now, CancellationToken.None);

        var tierGroups = db.CountGroupByTier();
        long pending = 0;
        var tiers = new List<TierRow>();
        foreach (var g in tierGroups.OrderBy(g => g.Tier, StringComparer.Ordinal))
        {
            if (g.Tier.Length == 0)
            {
                pending = g.Files;
                continue;
            }

            tiers.Add(new TierRow(g.Tier, (int)Math.Min(g.Files, int.MaxValue),
                FormatBytes(g.Bytes), g.Bytes));
        }

        if (pending > 0)
        {
            tiers.Add(new TierRow("Pending", (int)Math.Min(pending, int.MaxValue),
                FormatBytes(tierGroups.Where(g => g.Tier.Length == 0).Sum(g => g.Bytes)), 0));
        }

        long classified = totalFiles - pending;
        string coverage = totalFiles == 0
            ? "No inventory yet — run a scan first."
            : pending == 0
                ? $"Classified all {CountText.Of(totalFiles, "inventoried file")}."
                : $"Classified {CountText.Of(classified, "file")} of {CountText.Of(totalFiles, "inventoried file")} · {CountText.Of(pending, "file")} pending.";

        int inventoryGeneration = db.GetMaxGeneration();
        if (totalFiles > 0 && inventoryGeneration > 0)
        {
            coverage += $" Inventory generation {inventoryGeneration}.";
        }

        // A07: totals span retained inventory, so every label binds
        // to the last COMPLETED run — a newer cancelled/failed attempt
        // is named, never silently treated as current. Bounded: one
        // 50-row history read serves all three attributions.
        var runs = db.ListRuns(50);
        var lastRun = runs.FirstOrDefault();
        var lastCompleted = runs.FirstOrDefault(r =>
            r.Status.Equals("Completed", StringComparison.OrdinalIgnoreCase));
        var scopeRoots = ScanScopeLabels.DistinctRoots(runs);
        int scopeCount = scopeRoots.Count;
        // Single-scope branch shows the resolved root — never a raw
        // run label ("delta" rescans stamp rows, they are not a place).
        string? singleScopeRoot = scopeCount == 1 ? scopeRoots[0] : null;

        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string usersDir = Path.Combine(
            Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users");
        var treemap = BuildTreemapFromBuckets(db, windowsDir, programFiles, programFilesX86, usersDir);
        var attrs = db.QueryAttrStats();
        string limits = BuildLimitsLine(attrs);

        var orphans = new List<(string Dir, long YoungestTicks, string Signals)>();
        int orphanOffset = 0;
        while (true)
        {
            var page = db.QueryOrphanDirs(500, orphanOffset, out _);
            if (page.Count == 0)
            {
                break;
            }

            orphans.AddRange(page);
            orphanOffset += page.Count;
            if (page.Count < 500)
            {
                break;
            }
        }

        var (_, dupeSets, dupeWasted) = db.QueryDuplicateSets(1, 0);

        var uninstall = OrphanHunter.ReadUninstallEntries();
        var appRoots = GetAppRoots(programFiles, programFilesX86);

        var appGroups = AppGrouper.GroupApps(db, appRoots, uninstall, CancellationToken.None);

        // Overview's top findings: the two largest REVIEW rows with
        // fresh reasons (cheap: one 2-row page + two classifies).
        var reviewPage = db.QueryInventoryPage(new InventoryQuery(Tier: "REVIEW", Limit: 2));
        var classifier = new RiskClassifier(neverList.ToArray());
        var orphanSet = orphans.Select(o => o.Dir).ToList();
        bool IsOrphan(string normalizedPath) =>
            orphanSet.Any(d => normalizedPath.StartsWith(d, StringComparison.Ordinal));
        var topReview = new List<ClassifiedRow>();
        foreach (var fp in reviewPage.Rows)
        {
            var c = classifier.Classify(fp, now, IsOrphan);
            topReview.Add(new ClassifiedRow(
                fp.Path, FormatBytes(fp.Size), c.Tier.ToString().ToUpperInvariant(),
                string.Join(" ", c.RuleIds) + " — " + string.Join(" ", c.Reasons),
                c.ExpectedRegrowth, fp.Size,
                FormatModified(fp.MTimeUtcTicks), fp.Hash));
        }

        string? hibernation = DescribeSystemFile(
            Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "hiberfil.sys"));
        string? pagefile = DescribeSystemFile(
            Path.Combine(Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "pagefile.sys"));

        return new CleanerSnapshot(
            totalFiles, totalBytes, coverage, tiers, classified, pending,
            treemap, attrs, limits,
            orphans.Select(o => new OrphanRow(o.Dir, o.Signals)).ToList(),
            orphans.Select(o => o.Dir).ToList(),
            dupeSets, dupeWasted, appGroups,
            lastRun, lastCompleted, scopeCount, singleScopeRoot,
            inventoryGeneration, topReview, hibernation, pagefile,
            uninstall, scopeRoots);
    }

    internal static IReadOnlyList<string> GetAppRoots(string programFiles, string programFilesX86)
    {
        var roots = new List<string>();
        foreach (var root in new[]
        {
            programFiles, programFilesX86,
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        })
        {
            if (!string.IsNullOrWhiteSpace(root))
            {
                roots.Add(root);
            }
        }

        return roots;
    }

    internal static IReadOnlyList<(string Root, AppLocationKind Kind)> GetKindRoots()
    {
        var kinds = new List<(string, AppLocationKind)>();
        foreach (var (root, kind) in new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), AppLocationKind.Install),
            (Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), AppLocationKind.Install),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), AppLocationKind.SharedData),
            (Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), AppLocationKind.LocalData),
            (Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), AppLocationKind.RoamingData),
        })
        {
            if (!string.IsNullOrWhiteSpace(root))
            {
                kinds.Add((root, kind));
            }
        }

        return kinds;
    }

    // Keeper-order last resorts: downloads and temp rank below
    // unlisted user files, above only the bin (DuplicateFinder).
    internal static IReadOnlyList<string> GetLastRoots()
    {
        string profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var roots = new List<string>();
        foreach (var root in new[]
        {
            Path.Combine(profile, "Downloads"),
            Path.GetTempPath(),
        })
        {
            if (!string.IsNullOrWhiteSpace(root))
            {
                roots.Add(root);
            }
        }

        return roots;
    }

    // Treemap over the STATED inventory: one SUM-per-bucket query
    // partitions the total (design §7: no parent+child double
    // count), then one top-5 page per bucket subdivides. The two
    // Program Files roots merge into one Applications box.
    public static IReadOnlyList<TreemapCategory> BuildTreemapFromBuckets(
        SentinelDb db, string windowsDir, string programFiles,
        string programFilesX86, string usersDir)
    {
        var buckets = db.SumBuckets(
            [
                ("Windows", windowsDir),
                ("Applications", programFiles),
                ("Applications (x86)", programFilesX86),
                ("User files", usersDir),
            ], "Other");
        long GetBytes(string key) => buckets.TryGetValue(key, out var v) ? v.Bytes : 0;
        int GetFiles(string key) => buckets.TryGetValue(key, out var v) ? (int)Math.Min(v.Files, int.MaxValue) : 0;

        IReadOnlyList<TreemapFile> TopFor(IReadOnlyList<string> prefixes)
        {
            var page = db.QueryInventoryPage(new InventoryQuery(
                DirPrefixes: prefixes, Limit: 5));
            return page.Rows
                .Select(f => new TreemapFile(SafeFileName(f.Path), f.Size, f.Path))
                .ToList();
        }

        var appTop = TopFor([programFiles, programFilesX86])
            .OrderByDescending(f => f.Bytes).Take(5).ToList();
        long appBytes = GetBytes("Applications") + GetBytes("Applications (x86)");
        int appFiles = GetFiles("Applications") + GetFiles("Applications (x86)");

        var cats = new List<TreemapCategory>
        {
            new("Windows", GetBytes("Windows"),
                TopFor([windowsDir]),
                0, 0),
            new("Applications", appBytes, appTop, 0, 0),
            new("User files", GetBytes("User files"),
                TopFor([usersDir]),
                0, 0),
            new("Other", GetBytes("Other"),
                TopForOther(db, windowsDir, programFiles, programFilesX86, usersDir),
                0, 0),
        };

        // Rest = bucket minus shown top files (counts from the same
        // bucket sums, so shown + rest always reconcile).
        var counts = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["Windows"] = GetFiles("Windows"),
            ["Applications"] = appFiles,
            ["User files"] = GetFiles("User files"),
            ["Other"] = GetFiles("Other"),
        };
        return cats
            .Where(c => c.Bytes > 0)
            .Select(c =>
            {
                long topBytes = c.TopFiles.Sum(f => f.Bytes);
                return c with
                {
                    RestBytes = Math.Max(0, c.Bytes - topBytes),
                    RestCount = Math.Max(0, counts[c.Key] - c.TopFiles.Count),
                };
            })
            .OrderByDescending(c => c.Bytes)
            .ToList();
    }

    // U22: ranked-table rows from treemap categories. Same
    // bytes, same order (largest first), shares against the shown
    // total — the grid and the canvas can never disagree.
    public static IReadOnlyList<MapRankRow> BuildRankedRows(
        IReadOnlyList<TreemapCategory> categories)
    {
        long total = categories.Sum(c => c.Bytes);
        return categories
            .OrderByDescending(c => c.Bytes)
            .Select(c => new MapRankRow(
                c.Key,
                FormatBytes(c.Bytes),
                total <= 0 ? "—" : $"{100.0 * c.Bytes / total:0}%",
                CountText.Of(c.TopFiles.Count + c.RestCount, "file"),
                c.Key != "Other"))
            .ToList();
    }

    // The complement bucket has no prefix: top files come from the
    // global largest page minus bucketed paths (bounded: one page
    // read, honest rest). At most a handful of rows are skipped.
    private static IReadOnlyList<TreemapFile> TopForOther(
        SentinelDb db, params string[] bucketDirs)
    {
        var page = db.QueryInventoryPage(new InventoryQuery(Limit: 50));
        var result = new List<TreemapFile>();
        foreach (var f in page.Rows)
        {
            bool bucketed = false;
            foreach (var dir in bucketDirs)
            {
                string full;
                try
                {
                    full = Path.GetFullPath(dir).TrimEnd(Path.DirectorySeparatorChar)
                        + Path.DirectorySeparatorChar;
                }
                catch
                {
                    continue;
                }

                string upper;
                try
                {
                    upper = Path.GetFullPath(f.Path).ToUpperInvariant();
                }
                catch
                {
                    break;
                }

                if (upper.StartsWith(full.ToUpperInvariant(), StringComparison.Ordinal))
                {
                    bucketed = true;
                    break;
                }
            }

            if (!bucketed)
            {
                result.Add(new TreemapFile(SafeFileName(f.Path), f.Size, f.Path));
                if (result.Count >= 5)
                {
                    break;
                }
            }
        }

        return result;
    }

    public static string BuildLimitsLine(AttrStats attrs)
    {
        var parts = new List<string>();
        if (attrs.SparseFiles > 0)
        {
            parts.Add($"{CountText.Of(attrs.SparseFiles, "sparse file")} " +
                $"(logical size shown; on-disk is smaller)");
        }

        if (attrs.PlaceholderFiles > 0)
        {
            parts.Add($"{CountText.Of(attrs.PlaceholderFiles, "cloud placeholder")} " +
                "skipped, never opened");
        }

        long unreadable = Math.Max(0, attrs.HashMissingFiles - attrs.PlaceholderFiles);
        if (unreadable > 0)
        {
            parts.Add($"{CountText.Of(unreadable, "file")} unreadable (hash missing)");
        }

        // Always stated: the two sizing caveats that no scan can
        // remove without per-file handle work (P22 gap audit).
        parts.Add("each link path counted separately");
        return string.Join(" · ", parts);
    }

    private void LoadPageIfApplied()
    {
        if (_applied)
        {
            LoadPage();
        }
    }

    // One bounded page for the current chip/search/scope. Sync and
    // millisecond-scale (100-row pages); faults keep the last page
    // (A09) instead of blanking the table.
    public void LoadPage()
    {
        IReadOnlyList<StorageRow> rows;
        long total;
        int gen;
        string suffix;
        try
        {
            using var db = _dbFactory();
            (rows, total, gen, suffix) = QueryCurrentPage(db);
        }
        catch (Exception ex)
        {
            RefreshState.NoteFault("storage page", ex);
            return;
        }

        foreach (var row in Rows)
        {
            row.PropertyChanged -= OnRowChanged;
        }

        Rows.Clear();
        foreach (var row in rows)
        {
            if (_checked.TryGetValue(row.Detail.FullPath, out _))
            {
                row.IsSelected = true;
            }

            TrackRow(row);
            Rows.Add(row);
        }

        VisibleRows.Clear();
        foreach (var row in Rows)
        {
            VisibleRows.Add(row);
        }

        long first = total == 0 ? 0 : (long)PageIndex * PageSize + 1;
        long last = Math.Min(total, (long)PageIndex * PageSize + PageSize);
        PageLabel = total == 0
            ? $"No rows match this filter · gen {gen}{suffix}"
            : $"{first:N0}–{last:N0} of {total:N0} · gen {gen}{suffix}";
        HasPrevPage = PageIndex > 0;
        HasNextPage = last < total;
        EmptyRowsText = total == 0
            ? "No rows match this filter."
            : "No rows match this filter.";
        if (total == 0 && SelectedChip == "All"
            && string.IsNullOrWhiteSpace(SearchText) && FolderScope.Count == 0)
        {
            EmptyRowsText = _totalInventoried == 0
                ? "No inventory yet — run a scan first."
                : "Nothing to list — inventoried files are all protected (Never touch).";
        }

        Raise(nameof(HasVisibleRows));
        SelectedRow = null;
        UpdateCheckedLine();
    }

    private (IReadOnlyList<StorageRow> Rows, long Total, int Gen, string Suffix) QueryCurrentPage(
        SentinelDb db)
    {
        string search = SearchText.Trim();
        string? needle = string.IsNullOrWhiteSpace(search) ? null : search;
        int offset = PageIndex * PageSize;
        var classifier = new RiskClassifier(_neverProvider().ToArray());
        var orphanDirs = _orphanDirs;
        bool IsOrphan(string normalizedPath) =>
            orphanDirs.Any(d => normalizedPath.StartsWith(d, StringComparison.Ordinal));

        switch (SelectedChip)
        {
            case "Duplicates":
            {
                var (sets, totalSets, wasted) = db.QueryDuplicateSets(
                    PageSize, offset, needle,
                    FolderScope.Count == 0 ? null : FolderScope);
                string suffix = $" · {totalSets:N0} sets (exact-hash) · {FormatBytes(wasted)} spare · unhashed files excluded";
                // P23: one bounded member query per set on this page
                // (page-sized, hash-indexed) feeds keeper reasoning
                // from the inventory record — never a render-time stat.
                var preferred = GetAppRoots(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
                var lasts = GetLastRoots();
                var rows = new List<StorageRow>(sets.Count);
                foreach (var set in sets)
                {
                    var members = db.QueryDuplicateMembers(set.Hash);
                    var comparison = DuplicateComparer.Compare(
                        set.Hash, set.SizeBytes, members, preferred,
                        lasts, _uninstallEntries);
                    // P26: remember this set's keeper (idempotent
                    // upsert by set hash: re-rendering the same page
                    // overwrites the same row, never appends).
                    var keeper = comparison.CopiesOrdered.FirstOrDefault(c => c.IsKeeper)
                        ?? comparison.CopiesOrdered.FirstOrDefault();
                    if (keeper is not null)
                    {
                        db.Passport.RecordKeeperDecision(
                            set.Hash, keeper.Path, string.Join("; ", keeper.Reasons));
                    }

                    rows.Add(BuildDuplicateRow(set, comparison));
                }

                return (rows, totalSets, _appliedGeneration, suffix);
            }

            case "Orphans":
            {
                var dirs = db.QueryOrphanDirs(PageSize, offset, out long total, needle,
                    FolderScope.Count == 0 ? null : FolderScope);
                string suffix = " · possible leftovers · quiet 180+ days, no uninstall entry";
                return (dirs.Select(d => BuildOrphanRow(new OrphanRow(d.Dir, d.Signals))).ToList(),
                    total, _appliedGeneration, suffix);
            }

            case "Apps":
            {
                var owned = _appOwnerships;
                if (needle is not null)
                {
                    owned = owned.Where(o =>
                        o.AppName.Contains(needle, StringComparison.OrdinalIgnoreCase)
                        || o.Locations.Any(l => l.Directory.Contains(
                            needle, StringComparison.OrdinalIgnoreCase))).ToList();
                }

                if (FolderScope.Count > 0)
                {
                    owned = owned.Where(o =>
                        o.Locations.Any(l => UnderAnyScope(l.Directory))).ToList();
                }

                var page = owned.Skip(offset).Take(PageSize).ToList();
                string suffix = $" · {owned.Count:N0} apps · install + app-data locations";
                return (page.Select(o => BuildAppRow(new AppRow(
                    o.AppName, PrimaryDirectory(o), o.TotalFiles, o.TotalBytes,
                    o.Known, o.Locations))).ToList(),
                    owned.Count, _appliedGeneration, suffix);
            }

            default:
            {
                string? tier = SelectedChip switch
                {
                    "Safe" => "SAFE",
                    "Review" => "REVIEW",
                    "Never" => "NEVER",
                    _ => null,
                };
                var query = new InventoryQuery(
                    Tier: tier,
                    MinSize: SelectedChip == "Large" ? RiskClassifier.LargeFileBytes : null,
                    NameContains: needle,
                    DirPrefixes: FolderScope.Count == 0 ? null : FolderScope,
                    RegrowingOnly: SelectedChip == "Regrowing",
                    Limit: PageSize,
                    Offset: offset);
                var page = db.QueryInventoryPage(query);
                var rows = new List<StorageRow>(page.Rows.Count);
                foreach (var fp in page.Rows)
                {
                    var c = classifier.Classify(fp, DateTime.UtcNow, IsOrphan);
                    // P23: dead shortcuts name their missing target —
                    // one point lookup per shortcut row, page-bounded.
                    string? target = null;
                    if (c.Tier == RiskTier.Review
                        && fp.Path.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                    {
                        target = db.QueryDeadLink(fp.Path);
                    }

                    rows.Add(BuildFileRow(new ClassifiedRow(
                        fp.Path, FormatBytes(fp.Size), c.Tier.ToString().ToUpperInvariant(),
                        string.Join(" ", c.RuleIds) + " — " + string.Join(" ", c.Reasons),
                        c.ExpectedRegrowth, fp.Size,
                        FormatModified(fp.MTimeUtcTicks), fp.Hash, target)));
                }

                return (rows, page.TotalMatches, page.MaxGeneration, string.Empty);
            }
        }
    }

    private bool UnderAnyScope(string dir)
    {
        string upper;
        try
        {
            upper = Path.GetFullPath(dir).ToUpperInvariant();
        }
        catch
        {
            return false;
        }

        foreach (var scope in FolderScope)
        {
            string prefix;
            try
            {
                prefix = Path.GetFullPath(scope).TrimEnd(Path.DirectorySeparatorChar)
                    + Path.DirectorySeparatorChar;
            }
            catch
            {
                continue;
            }

            if (upper.StartsWith(prefix.ToUpperInvariant(), StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    public void PrevPage()
    {
        if (PageIndex > 0)
        {
            PageIndex--;
            LoadPageIfApplied();
        }
    }

    public void NextPage()
    {
        if (HasNextPage)
        {
            PageIndex++;
            LoadPageIfApplied();
        }
    }

    // Treemap drill-down: a category box scopes every chip to its
    // folders. "Other" is a complement bucket with no prefix and
    // does not scope (returns false; the box stays unclickable).
    public bool SetTreemapScope(string key)
    {
        string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string usersDir = Path.Combine(
            Path.GetPathRoot(Environment.SystemDirectory) ?? "C:\\", "Users");
        IReadOnlyList<string>? prefixes = key switch
        {
            "Windows" => [windowsDir],
            "Applications" => [programFiles, programFilesX86],
            "User files" => [usersDir],
            _ => null,
        };
        if (prefixes is null)
        {
            return false;
        }

        FolderScope = prefixes;
        FolderScopeLabel = $"Showing {key} · ";
        PageIndex = 0;
        LoadPageIfApplied();
        Raise(nameof(HasFolderScope));
        return true;
    }

    public void ClearFolderScope()
    {
        FolderScope = [];
        FolderScopeLabel = string.Empty;
        PageIndex = 0;
        LoadPageIfApplied();
        Raise(nameof(HasFolderScope));
    }

    private long _totalInventoried;

    public void Apply(CleanerSnapshot s)
    {
        _totalInventoried = s.TotalFiles;
        _orphanDirs = s.OrphanDirList.ToList();
        _appGroups = s.AppGroups;
        _appOwnerships = AppOwnershipMerger.Merge(s.AppGroups, GetKindRoots());
        _uninstallEntries = s.UninstallEntries;
        _appliedGeneration = s.InventoryGeneration;
        _appliedScopeRoots = s.ScopeRoots;
        Summary = s.TotalFiles == 0
            ? "Not inspected yet."
            : $"{CountText.Of(s.TotalFiles, "file")} · {FormatBytes(s.TotalBytes)} inventoried.";
        Coverage = s.Coverage;
        // A07: totals span retained inventory, so scope/time/gaps
        // bind to the last COMPLETED run. A newer aborted attempt
        // is named on the scan line — never silently current.
        ScopeLine = s.LastCompletedRun is null
            ? s.LastRun is null
                ? "No scan yet · Logical file sizes"
                : "No completed scan yet · Logical file sizes"
            : s.ScopeCount > 1
                ? $"{CountText.Of(s.ScopeCount, "location")} · Logical file sizes"
                : $"{s.SingleScopeRoot ?? s.LastCompletedRun.Root} · Logical file sizes";
        LastScanLine = s.LastCompletedRun is null
            ? "Last scan: never"
            : "Last scan: " + OverviewViewModel.ToLocalTime(s.LastCompletedRun.StartedUtc)
                + (s.LastRun is not null && s.LastRun.Id != s.LastCompletedRun.Id
                    ? $" · latest attempt {s.LastRun.Status.ToLowerInvariant()}"
                    : string.Empty);
        long review = 0;
        foreach (var tier in s.Tiers)
        {
            if (tier.Tier == "REVIEW")
            {
                review = tier.BytesRaw;
            }
        }

        ReviewLine = review > 0 ? $"{FormatBytes(review)} to review" : "Nothing flagged to review";
        UnavailableLine = s.LastCompletedRun is null
            ? "—"
            : s.LastCompletedRun.GapsCount == 0 ? "None" : $"{CountText.Of(s.LastCompletedRun.GapsCount, "location")} unavailable";
        LimitsLine = s.LimitsLine;

        Tiers.Clear();
        foreach (var row in s.Tiers)
        {
            Tiers.Add(row);
        }

        Treemap.Clear();
        foreach (var category in s.Treemap)
        {
            Treemap.Add(category);
        }

        RankedRows.Clear();
        foreach (var row in BuildRankedRows(s.Treemap))
        {
            RankedRows.Add(row);
        }

        HibernationNote = s.HibernationNote;
        PagefileNote = s.PagefileNote;
        _applied = true;
        PageIndex = 0;
        LoadPage();
        RefreshState.NoteSuccess();
    }

    public static StorageRow BuildFileRow(ClassifiedRow item)
    {
        string tier = item.Tier.ToUpperInvariant();
        string classification = tier switch
        {
            "SAFE" => "Safe",
            "REVIEW" => "Review",
            "NEVER" => "Never touch",
            _ => item.Tier,
        };
        string tierLine = tier switch
        {
            "SAFE" => "Safe — routine by rule",
            "REVIEW" => "Review — needs your judgment",
            "NEVER" => "Never touch — protected by policy",
            _ => "Unclassified",
        };
        string verifyLine = tier switch
        {
            "SAFE" => "Nothing further — the rules fired cleanly.",
            "REVIEW" => "Whether this file is still needed — only you know.",
            _ => "Protected paths are never listed for cleanup.",
        };
        string knowLine = item.DeadTarget is null
            ? item.Reasons
            : $"{item.Reasons} Points to {item.DeadTarget}, which is gone.";
        return new StorageRow(
            StorageRowKind.File, SafeFileName(item.Path), SafeDirectoryName(item.Path),
            item.Size, item.SizeRaw, classification, tier, tier != "NEVER",
            new StorageDetail(
                item.Path, item.Size, item.Modified,
                item.Hash ?? "Not requested", tierLine, knowLine, verifyLine,
                item.Hash is null
                    ? "Inventory record · hash not requested"
                    : "Inventory record · SHA-256 recorded",
                [], item.Regrowth));
    }

    public static StorageRow BuildDuplicateRow(DuplicateSet set, DuplicateComparison comparison)
    {
        var copies = comparison.CopiesOrdered;
        string primary = copies.Count == 0
            ? (set.Paths.Count == 0 ? "(missing)" : set.Paths[0])
            : copies[0].Path;
        long wasted = set.SizeBytes * Math.Max(0, set.Copies - 1);
        var lines = new List<string>(copies.Count);
        foreach (var copy in copies)
        {
            string tag = copy.IsKeeper ? "Suggested keeper" : "Spare copy";
            lines.Add($"{tag} — {copy.Path} — {string.Join(" ", copy.Reasons)}");
        }

        string keeperName = copies.Count == 0 ? "unknown" : SafeFileName(copies[0].Path);
        return new StorageRow(
            StorageRowKind.Duplicate,
            $"{SafeFileName(primary)} · {CountText.Of(set.Copies, "copy", "copies")}",
            SafeDirectoryName(primary),
            FormatBytes(wasted) + " spare", wasted,
            "Duplicate", string.Empty, true,
            new StorageDetail(
                primary, FormatBytes(set.SizeBytes) + " each",
                copies.Count == 0
                    ? DescribePrimaryModified(primary)
                    : FormatModified(copies[0].MTimeUtcTicks),
                "Matched by hash", $"Duplicate set — {set.Copies} identical copies",
                $"{set.Copies} identical copies × {FormatBytes(set.SizeBytes)} each. Suggested keeper: {keeperName} — review before removing any copy.",
                "Which copy the owning app actually uses — confirm before removing.",
                "Inventory record · hash match", lines, null));
    }

    public static StorageRow BuildOrphanRow(OrphanRow orphan)
    {
        string dir = orphan.Directory.TrimEnd(Path.DirectorySeparatorChar);
        return new StorageRow(
            StorageRowKind.Orphan, SafeFileName(dir), SafeDirectoryName(dir),
            "—", 0, "Orphan", string.Empty, true,
            new StorageDetail(
                orphan.Directory, "—", "Unknown", "Not applicable",
                "Possible leftover — no uninstall entry",
                orphan.Signals,
                "Whether the owning app is really gone — check installed programs.",
                "Inventory record · directory grouping", [], null));
    }

    internal static string PrimaryDirectory(AppOwnership owned)
    {
        var install = owned.Locations.FirstOrDefault(
            l => l.Kind == AppLocationKind.Install);
        if (install is not null)
        {
            return install.Directory;
        }

        return owned.Locations
            .OrderByDescending(l => l.Bytes)
            .FirstOrDefault()?.Directory ?? string.Empty;
    }

    public static StorageRow BuildAppRow(AppRow app)
    {
        var lines = new List<string>(app.Locations.Count);
        foreach (var location in app.Locations)
        {
            lines.Add($"{AppOwnershipMerger.LabelFor(location.Kind)} — {location.Directory} — " +
                $"{CountText.Of(location.Files, "file")}, {FormatBytes(location.Bytes)} — " +
                AppOwnershipMerger.GuidanceFor(location.Kind));
        }

        string kinds = app.Locations.Count == 0
            ? "no locations"
            : string.Join(" + ", app.Locations
                .Select(l => AppOwnershipMerger.LabelFor(l.Kind))
                .Distinct(StringComparer.Ordinal));
        return new StorageRow(
            StorageRowKind.App, app.AppName, app.Directory,
            FormatBytes(app.Bytes), app.Bytes,
            app.Known ? "App" : "Unknown app", string.Empty, true,
            new StorageDetail(
                app.Directory, FormatBytes(app.Bytes), "Unknown", "Not applicable",
                app.Known ? $"Installed app — {app.AppName}" : "Unknown owner — grouped by folder",
                $"{CountText.Of(app.Locations.Count, "location")} · {kinds} · {CountText.Of(app.Files, "file")} owned",
                app.Known
                    ? "Whether this app is still installed — check installed programs."
                    : "Which app owns this folder — unclaimed space.",
                app.Known
                    ? "Inventory record · folder rollups + uninstall match"
                    : "Inventory record · folder rollup, no uninstall match",
                lines, null));
    }

    // The real selection hookup, factored so tests drive the same
    // path the page load does (toggle → _checked → CheckedLine).
    internal void TrackRow(StorageRow row) => row.PropertyChanged += OnRowChanged;

    private void OnRowChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(StorageRow.IsSelected) && sender is StorageRow row)
        {
            if (row.IsSelected)
            {
                _checked[row.Detail.FullPath] = (row.SizeRaw, MixKeyFor(row));
            }
            else
            {
                _checked.Remove(row.Detail.FullPath);
            }

            UpdateCheckedLine();
        }
    }

    // Checked rows on the CURRENT page (row VMs exist only for the
    // loaded page — the cross-page memory is CheckedEntries).
    public IReadOnlyList<StorageRow> CheckedRows()
    {
        return Rows.Where(r => r.IsSelected && r.IsSelectable).ToList();
    }

    // Every checked path across page turns (path -> size).
    public IReadOnlyDictionary<string, long> CheckedEntries() =>
        _checked.ToDictionary(kv => kv.Key, kv => kv.Value.Size, StringComparer.OrdinalIgnoreCase);

    // E33: the full selection (path, size, mix key) for preview
    // building. The mix key tells files from group rows.
    public IReadOnlyList<(string Path, long Size, string Mix)> CheckedSelection() =>
        _checked.Select(kv => (kv.Key, kv.Value.Size, kv.Value.Mix)).ToList();

    public bool IsActionAvailable => _actions is not null;

    private string _actionStatusLine = string.Empty;

    public string ActionStatusLine
    {
        get => _actionStatusLine;
        private set => Set(ref _actionStatusLine, value);
    }

    // E33: opens the Confirm Sheet for the current selection. The
    // preview builder re-stats and re-classifies every entry — the
    // sheet lists exactly what Confirm would approve, plus the named
    // reasons for everything it would not.
    public void BeginVaultAction()
    {
        if (_actions is null)
        {
            ActionStatusLine = "Vault actions aren't wired in this build — the selection stays review-only.";
            return;
        }

        var selection = CheckedSelection();
        if (selection.Count == 0)
        {
            ActionStatusLine = "Nothing selected.";
            return;
        }

        var classifier = new RiskClassifier(_neverProvider().ToArray());
        var orphanDirs = _orphanDirs;
        bool IsOrphan(string normalizedPath) =>
            orphanDirs.Any(d => normalizedPath.StartsWith(d, StringComparison.Ordinal));
        // Classify normalizes the path before invoking IsOrphan,
        // so the predicate takes it as-is (same as QueryCurrentPage).
        // The flags lookup keeps the preview's tiers identical to the
        // table's (dead shortcuts and friends are scan evidence).
        using var db = _dbFactory();
        // D44: duplicate sets and orphan dirs expand to explicit
        // files (keepers + folders ride as notes, never targets).
        // Raw group mixes that somehow reach the builder are still
        // excluded there — expansion is the only way in.
        var expanded = ExpandGroups(selection, db);
        var preview = CleanPreviewBuilder.BuildPreview(
            expanded.Files,
            classifier, DateTime.UtcNow, _appliedGeneration, _appliedScopeRoots,
            IsOrphan,
            path => db.GetFingerprint(path)?.AttrFlags ?? 0);
        if (expanded.Notes.Count > 0)
        {
            preview = preview with
            {
                Excluded = preview.Excluded.Concat(expanded.Notes).ToList(),
            };
        }

        var template = ActionRegistry.Find("clean_items_to_vault");
        if (template is null)
        {
            ActionStatusLine = "The vault action is not registered — nothing was done.";
            return;
        }

        string expansion = expanded.Summary;
        ActionStatusLine = (preview.RefusedReason is null
            ? $"Confirm Sheet opened for {preview.Included.Count} file(s)."
            : "Confirm Sheet opened — review what can and cannot be vaulted.")
            + (string.IsNullOrEmpty(expansion) ? string.Empty : " " + expansion);
        var sheet = new ConfirmSheetViewModel(
            preview, template, _actions.Dispatcher, _actions.Undo, _actions.ScopeExcluded)
        {
            ViewHistory = _actions.ViewHistory,
        };
        _actions.Host.Show(sheet);
    }

    // D44: checked group rows become explicit file selections. Uses
    // the SAME keeper inputs as the Duplicates table (preferred/last
    // roots + uninstall entries), so the sheet's keeper always agrees
    // with the displayed suggestion. Test-visible via BeginVaultAction
    // with a capturing host.
    private ExpandedSelection ExpandGroups(
        IReadOnlyList<(string Path, long Size, string Mix)> selection,
        SentinelDb db)
    {
        var files = new List<(string Path, string Mix)>();
        var notes = new List<CleanExcludedItem>();
        int sets = 0;
        int dirs = 0;
        int keepers = 0;
        int groupFiles = 0;
        var inputs = new GroupExpansion.DuplicateInputs(
            GetAppRoots(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)),
            GetLastRoots(),
            _uninstallEntries);

        foreach (var entry in selection)
        {
            int budget = CleanPreviewBuilder.MaxPreviewItems - files.Count;
            if (entry.Mix == "duplicates")
            {
                var expanded = GroupExpansion.ExpandDuplicateSet(db, entry.Path, inputs, budget);
                files.AddRange(expanded.Files);
                notes.AddRange(expanded.Notes);
                keepers += expanded.KeeperPaths.Count;
                sets += expanded.SetsExpanded;
                groupFiles += expanded.Files.Count;
            }
            else if (entry.Mix == "orphans")
            {
                var expanded = GroupExpansion.ExpandOrphanDir(db, entry.Path, budget);
                files.AddRange(expanded.Files);
                notes.AddRange(expanded.Notes);
                dirs += expanded.SetsExpanded;
                groupFiles += expanded.Files.Count;
            }
            else
            {
                files.Add((entry.Path, entry.Mix));
            }
        }

        string summary = sets == 0 && dirs == 0
            ? string.Empty
            : $"Expanded {sets} duplicate set(s) and {dirs} leftover folder(s) → " +
              $"{groupFiles} file(s) listed, {keepers} keeper(s) stay.";
        return new ExpandedSelection(files, notes, summary);
    }

    private sealed record ExpandedSelection(
        IReadOnlyList<(string Path, string Mix)> Files,
        IReadOnlyList<CleanExcludedItem> Notes,
        string Summary);

    public void ClearSelection()
    {
        _checked.Clear();
        foreach (var row in Rows)
        {
            row.IsSelected = false;
        }

        UpdateCheckedLine();
    }

    private void UpdateCheckedLine()
    {
        HasChecked = _checked.Count > 0;
        if (_checked.Count == 0)
        {
            CheckedLine = "Nothing selected";
            return;
        }

        // U22 (02 §7): N items, total size, risk mix. Deliberately
        // review language — nothing here names cleanup, preview, or
        // deletion (those arrive with the action phase, E30+).
        string[] order = ["safe", "review", "never-touch", "duplicates", "orphans", "apps"];
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var entry in _checked.Values)
        {
            counts.TryGetValue(entry.Mix, out int n);
            counts[entry.Mix] = n + 1;
        }

        var mix = order
            .Where(counts.ContainsKey)
            .Select(key => $"{counts[key]} {key}");
        foreach (var key in counts.Keys.Where(k => !order.Contains(k)).OrderBy(k => k))
        {
            mix = mix.Append($"{counts[key]} {key}");
        }

        CheckedLine = $"{_checked.Count} items · {FormatBytes(_checked.Values.Sum(v => v.Size))} · " +
            string.Join(", ", mix);
    }

    // Risk-mix bucket for one checked row: file tiers by tier,
    // group rows by kind. Unknown tiers surface as-is (lowercased)
    // rather than collapsing into a wrong bucket.
    internal static string MixKeyFor(StorageRow row) =>
        row.Tier switch
        {
            "SAFE" => "safe",
            "REVIEW" => "review",
            "NEVER" => "never-touch",
            "" => row.Kind switch
            {
                StorageRowKind.Duplicate => "duplicates",
                StorageRowKind.Orphan => "orphans",
                StorageRowKind.App => "apps",
                _ => "items",
            },
            _ => row.Tier.ToLowerInvariant(),
        };

    internal static string SafeFileName(string path)
    {
        try
        {
            string name = Path.GetFileName(path);
            return string.IsNullOrEmpty(name) ? path : name;
        }
        catch
        {
            return path;
        }
    }

    internal static string SafeDirectoryName(string path)
    {
        try
        {
            return Path.GetDirectoryName(path) ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    internal static string FormatModified(long mtimeUtcTicks)
    {
        if (mtimeUtcTicks <= 0)
        {
            return "Unknown";
        }

        try
        {
            return new DateTime(mtimeUtcTicks, DateTimeKind.Utc)
                .ToLocalTime().ToString("d MMM yyyy, HH:mm");
        }
        catch
        {
            return "Unknown";
        }
    }

    // Public like the other Build*/Describe* row helpers: the P23
    // fixture pins the "managed by Windows, never deleted" note.
    public static string? DescribeSystemFile(string fullPath)
    {
        try
        {
            var info = new FileInfo(fullPath);
            if (!info.Exists)
            {
                return null;
            }

            string size;
            try
            {
                size = FormatBytes(info.Length);
            }
            catch
            {
                size = "size unavailable";
            }

            return $"{info.Name} · {size} · managed by Windows";
        }
        catch
        {
            return null;
        }
    }

    internal static string DescribePrimaryModified(string primary)
    {
        try
        {
            var info = new FileInfo(primary);
            return info.Exists ? FormatModified(info.LastWriteTimeUtc.Ticks) : "Missing now";
        }
        catch
        {
            return "Unknown";
        }
    }

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double value = bytes;
        int unit = 0;
        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.#} {units[unit]}";
    }

    public sealed record CleanerSnapshot(
        long TotalFiles,
        long TotalBytes,
        string Coverage,
        IReadOnlyList<TierRow> Tiers,
        long ClassifiedFiles,
        long PendingFiles,
        IReadOnlyList<TreemapCategory> Treemap,
        AttrStats Attrs,
        string LimitsLine,
        IReadOnlyList<OrphanRow> Orphans,
        IReadOnlyList<string> OrphanDirList,
        long DupeSetsTotal,
        long DupeWastedBytes,
        IReadOnlyList<AppGroup> AppGroups,
        ScanRunInfo? LastRun,
        ScanRunInfo? LastCompletedRun,
        int ScopeCount,
        string? SingleScopeRoot,
        int InventoryGeneration,
        IReadOnlyList<ClassifiedRow> TopReview,
        string? HibernationNote,
        string? PagefileNote,
        IReadOnlyList<UninstallEntry> UninstallEntries,
        IReadOnlyList<string> ScopeRoots);
}
