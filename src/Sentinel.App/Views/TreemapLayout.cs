namespace Sentinel.App.Views;

// Squarified treemap, one level (Bruls–Huizing–van Wijk row
// rule). Pure geometry: the Storage page lays out prefix
// categories, then subdivides each box by its largest files.
// Zero/negative weights are dropped, never drawn.
public sealed record TreemapRect(
    string Key, double X, double Y, double Width, double Height, double Fraction);

public static class TreemapLayout
{
    public static IReadOnlyList<TreemapRect> Layout(
        IReadOnlyList<(string Key, long Bytes)> items, double width, double height)
    {
        var rects = new List<TreemapRect>();
        if (width <= 0 || height <= 0)
        {
            return rects;
        }

        var positive = items.Where(i => i.Bytes > 0).OrderByDescending(i => i.Bytes).ToList();
        long total = positive.Sum(i => i.Bytes);
        if (total <= 0)
        {
            return rects;
        }

        double scale = width * height / total;
        var row = new List<(string Key, long Bytes)>();
        double x = 0, y = 0, w = width, h = height;
        foreach (var item in positive)
        {
            var candidate = row.Append(item).ToList();
            if (row.Count > 0 && WorstAspect(candidate, w, h, scale) > WorstAspect(row, w, h, scale))
            {
                EmitRow(row, ref x, ref y, ref w, ref h, scale, total, rects);
                row.Clear();
            }

            row.Add(item);
        }

        if (row.Count > 0)
        {
            EmitRow(row, ref x, ref y, ref w, ref h, scale, total, rects);
        }

        return rects;
    }

    private static void EmitRow(
        List<(string Key, long Bytes)> row,
        ref double x, ref double y, ref double w, ref double h,
        double scale, long total, List<TreemapRect> rects)
    {
        long rowBytes = row.Sum(i => i.Bytes);
        double rowArea = rowBytes * scale;
        if (w >= h)
        {
            double rowW = rowArea / h;
            double oy = y;
            foreach (var item in row)
            {
                double boxH = item.Bytes * scale / rowW;
                rects.Add(new TreemapRect(item.Key, x, oy, rowW, boxH, (double)item.Bytes / total));
                oy += boxH;
            }

            x += rowW;
            w -= rowW;
        }
        else
        {
            double rowH = rowArea / w;
            double ox = x;
            foreach (var item in row)
            {
                double boxW = item.Bytes * scale / rowH;
                rects.Add(new TreemapRect(item.Key, ox, y, boxW, rowH, (double)item.Bytes / total));
                ox += boxW;
            }

            y += rowH;
            h -= rowH;
        }
    }

    private static double WorstAspect(
        List<(string Key, long Bytes)> row, double w, double h, double scale)
    {
        long rowBytes = row.Sum(i => i.Bytes);
        double rowArea = rowBytes * scale;
        double side = w >= h ? rowArea / h : rowArea / w;
        double worst = 1.0;
        foreach (var item in row)
        {
            double other = item.Bytes * scale / side;
            double ratio = Math.Max(side, other) / Math.Max(1e-9, Math.Min(side, other));
            worst = Math.Max(worst, ratio);
        }

        return worst;
    }
}
