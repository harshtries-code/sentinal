using Sentinel.App.Views;

namespace Sentinel.Tests;

public sealed class TreemapTests
{
    [Fact]
    public void Layout_Empty_Or_Nonpositive_Is_Empty()
    {
        Assert.Empty(TreemapLayout.Layout([], 100, 100));
        Assert.Empty(TreemapLayout.Layout([("a", 0), ("b", -5)], 100, 100));
        Assert.Empty(TreemapLayout.Layout([("a", 10)], 0, 100));
    }

    [Fact]
    public void Layout_Single_Fills_Bounds()
    {
        var rects = TreemapLayout.Layout([("only", 42)], 200, 100);
        var r = Assert.Single(rects);
        Assert.Equal("only", r.Key);
        Assert.Equal(0, r.X);
        Assert.Equal(0, r.Y);
        Assert.Equal(200, r.Width);
        Assert.Equal(100, r.Height);
        Assert.Equal(1.0, r.Fraction);
    }

    [Fact]
    public void Layout_Splits_Proportionally_And_Covers()
    {
        var rects = TreemapLayout.Layout(
            [("a", 300), ("b", 100)], 200, 100).ToList();
        Assert.Equal(2, rects.Count);
        double total = rects.Sum(r => r.Width * r.Height);
        Assert.InRange(total, 19999.0, 20001.0);
        Assert.InRange(rects[0].Width * rects[0].Height / total, 0.74, 0.76);
        foreach (var r in rects)
        {
            Assert.InRange(r.X, 0, 200);
            Assert.InRange(r.Y, 0, 100);
            Assert.True(r.X + r.Width <= 200.001);
            Assert.True(r.Y + r.Height <= 100.001);
        }

        Assert.InRange(rects.Sum(r => r.Fraction), 0.999, 1.001);
    }

    [Fact]
    public void Layout_Skewed_Stays_Squarish()
    {
        var items = new List<(string Key, long Bytes)>
        {
            ("big", 1000), ("b", 60), ("c", 50), ("d", 40), ("e", 30), ("f", 10),
        };
        var rects = TreemapLayout.Layout(items, 400, 200).ToList();
        Assert.Equal(6, rects.Count);
        foreach (var r in rects)
        {
            double aspect = Math.Max(r.Width, r.Height) / Math.Max(1e-9, Math.Min(r.Width, r.Height));
            Assert.True(aspect < 8.0, $"box {r.Key} aspect {aspect}");
        }

        double total = rects.Sum(r => r.Width * r.Height);
        Assert.InRange(total, 79999.0, 80001.0);
    }
}
