using System.Runtime.InteropServices;

namespace Sentinel.Engine.Scan;

// Battery / power probe (03 §5, 05 §6): Eco refuses to start on
// battery saver or low battery; a running Eco scan pauses until the
// stress clears; Balanced/Turbo pause on low battery only when the
// user leaves the PauseOnLowBattery setting on (default). Unknown
// power state fails CLOSED for Eco admission (never scan blind —
// same precedent as the idle probe) but never blocks an explicit
// user-started Balanced/Turbo scan.
public readonly record struct PowerState(
    bool Known,
    bool BatterySaverOn,
    bool OnBattery,
    int BatteryPercent)
{
    // Low battery means discharging AND under 20% (05 §6): a laptop
    // at 10% on the charger is charging, not stressed.
    public bool IsLowBattery =>
        Known && OnBattery && BatteryPercent >= 0 && BatteryPercent < 20;

    public static PowerState AcPower { get; } = new(true, false, false, 100);

    public static PowerState Unknown { get; } = new(false, false, false, -1);
}

public interface IBatteryProbe
{
    PowerState GetPowerState();
}

public sealed class WindowsBatteryProbe : IBatteryProbe
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SystemPowerStatus
    {
        public byte AcLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public uint BatteryLifeTime;
        public uint BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll")]
    private static extern bool GetSystemPowerStatus(out SystemPowerStatus status);

    private const byte AcOffline = 0;
    private const byte AcUnknown = 255;
    private const byte BatteryNoBattery = 128;
    private const byte BatteryUnknown = 255;

    public PowerState GetPowerState()
    {
        try
        {
            if (!GetSystemPowerStatus(out var status))
            {
                return PowerState.Unknown;
            }

            // A desktop reports no battery and AC online: that is a
            // KNOWN healthy state, not an unknown one.
            if (status.AcLineStatus == AcUnknown && status.BatteryFlag == BatteryUnknown)
            {
                return PowerState.Unknown;
            }

            bool onBattery = status.AcLineStatus == AcOffline
                && status.BatteryFlag != BatteryNoBattery;
            int percent = status.BatteryLifePercent is BatteryUnknown or > 100
                ? -1
                : status.BatteryLifePercent;
            return new PowerState(
                Known: true,
                BatterySaverOn: status.SystemStatusFlag != 0,
                OnBattery: onBattery,
                BatteryPercent: percent);
        }
        catch
        {
            return PowerState.Unknown;
        }
    }
}
