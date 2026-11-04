namespace Sentinel.App.ViewModels;

// Shared count formatting: "1 file", "2 files". Display strings must never
// show "(s)" hedges or "1 files" — counts are exact and cheap to pluralize.
public static class CountText
{
    public static string Of(long count, string singular, string? plural = null) =>
        $"{count:n0} {(count == 1 ? singular : (plural ?? singular + "s"))}";
}
