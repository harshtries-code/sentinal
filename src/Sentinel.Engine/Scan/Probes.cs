using System.Runtime.InteropServices;

namespace Sentinel.Engine.Scan;

public interface IIdleProbe
{
    TimeSpan GetIdleTime();
}

public interface IFullscreenProbe
{
    bool IsForegroundFullscreen();
}

public sealed class WindowsIdleProbe : IIdleProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    public TimeSpan GetIdleTime()
    {
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info))
        {
            return TimeSpan.Zero; // Unknown: treat as active, never scan blind.
        }

        unchecked
        {
            return TimeSpan.FromMilliseconds((uint)Environment.TickCount - info.Time);
        }
    }
}

public sealed class WindowsFullscreenProbe : IFullscreenProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Rect
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool GetWindowRect(IntPtr hWnd, out Rect rect);

    [DllImport("user32.dll")]
    private static extern int GetSystemMetrics(int index);

    private const int SmCxScreen = 0;
    private const int SmCyScreen = 1;

    public bool IsForegroundFullscreen()
    {
        var fg = GetForegroundWindow();
        if (fg == IntPtr.Zero)
        {
            return false;
        }

        if (!GetWindowRect(fg, out var rect))
        {
            return false;
        }

        return rect.Left <= 0 && rect.Top <= 0
            && rect.Right >= GetSystemMetrics(SmCxScreen)
            && rect.Bottom >= GetSystemMetrics(SmCyScreen);
    }
}
