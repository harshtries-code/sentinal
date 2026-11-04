using System.Text;

namespace Sentinel.Engine.Policy;

// Minimal shell-link (.lnk) local-target reader (MS-SHLLINK subset,
// P23). Reads ONLY the LinkInfo local base path — enough to decide
// whether a shortcut's target still exists. Pure: bytes in, target
// path (or null) out. Anything unparseable, non-local-only (network
// paths, IDList-only links), or out of bounds yields null: an
// unknown target is never reported as dead.
public static class ShortcutResolver
{
    // Real shortcuts are ~1-4KB; 64KB covers adorned ones without
    // letting a renamed multi-GB file become a deep read.
    public const int MaxProbeBytes = 64 * 1024;

    private const uint HeaderSizeValue = 0x0000004C;
    private const int HeaderSize = 76;
    private const int LinkFlagsOffset = 20;
    private const uint HasLinkTargetIdList = 0x01;
    private const uint HasLinkInfo = 0x02;
    private const uint IsUnicode = 0x80;

    public static string? TryGetLocalTarget(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < HeaderSize)
        {
            return null;
        }

        // Offset 0 is the header-size field (0x4C); offset 4 opens
        // the LinkCLSID (00021401-0000-0000-C000-000000000046).
        if (ReadU32(bytes, 0) != HeaderSizeValue)
        {
            return null;
        }

        if (!HasLinkClsid(bytes))
        {
            return null;
        }

        uint linkFlags = ReadU32(bytes, LinkFlagsOffset);
        if ((linkFlags & HasLinkInfo) == 0)
        {
            return null;
        }

        int offset = HeaderSize;
        if ((linkFlags & HasLinkTargetIdList) != 0)
        {
            if (offset + 2 > bytes.Length)
            {
                return null;
            }

            int idListSize = ReadU16(bytes, offset);
            offset += 2 + idListSize;
        }

        if (offset + 28 > bytes.Length)
        {
            return null;
        }

        int infoStart = offset;
        int infoSize = (int)ReadU32(bytes, offset);
        int headerSize = (int)ReadU32(bytes, offset + 4);
        if (infoSize < 28 || headerSize < 28 || infoStart + infoSize > bytes.Length)
        {
            return null;
        }

        uint infoFlags = ReadU32(bytes, offset + 8);
        const uint VolumeIdAndLocalBasePath = 0x01;
        if ((infoFlags & VolumeIdAndLocalBasePath) == 0)
        {
            return null;
        }

        // Prefer the Unicode path when the link stores one; the ANSI
        // path is the fallback. Both are offsets from infoStart.
        // Slot 28 is LocalBasePathOffsetUnicode (slot 32 is the
        // common-suffix Unicode offset — not a target path).
        int unicodeOffset = headerSize >= 36 ? (int)ReadU32(bytes, offset + 28) : 0;
        int ansiOffset = (int)ReadU32(bytes, offset + 16);
        bool preferUnicode = (linkFlags & IsUnicode) != 0 && unicodeOffset > 0;

        string? target = preferUnicode
            ? ReadNullTerminated(bytes, infoStart + unicodeOffset, infoStart + infoSize, unicode: true)
            : null;
        target ??= ansiOffset > 0
            ? ReadNullTerminated(bytes, infoStart + ansiOffset, infoStart + infoSize, unicode: false)
            : null;

        if (string.IsNullOrWhiteSpace(target))
        {
            return null;
        }

        // Local targets only: a UNC/network target that is merely
        // offline must never read as "dead".
        if (target.StartsWith(@"\\", StringComparison.Ordinal))
        {
            return null;
        }

        return target;
    }

    private static string? ReadNullTerminated(
        ReadOnlySpan<byte> bytes, int start, int end, bool unicode)
    {
        if (start < 0 || start >= end || end > bytes.Length)
        {
            return null;
        }

        int limit = end - start;
        int length = 0;
        if (unicode)
        {
            while (length + 1 < limit)
            {
                if (bytes[start + length] == 0 && bytes[start + length + 1] == 0)
                {
                    break;
                }

                length += 2;
            }

            if (length + 1 >= limit)
            {
                return null;
            }

            return Encoding.Unicode.GetString(bytes.Slice(start, length));
        }

        while (length < limit && bytes[start + length] != 0)
        {
            length++;
        }

        if (length >= limit)
        {
            return null;
        }

        // Latin-1, not code page 1252: built in (no provider
        // registration), byte-identical for ASCII paths, and close
        // enough for the existence stat that consumes this.
        return Encoding.Latin1.GetString(bytes.Slice(start, length));
    }

    private static bool HasLinkClsid(ReadOnlySpan<byte> bytes)
    {
        // 00021401-0000-0000-C000-000000000046, mixed-endian fields.
        byte[] expected =
        [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        for (int i = 0; i < expected.Length; i++)
        {
            if (bytes[4 + i] != expected[i])
            {
                return false;
            }
        }

        return true;
    }

    private static uint ReadU32(ReadOnlySpan<byte> bytes, int offset) =>
        (uint)(bytes[offset]
            | (bytes[offset + 1] << 8)
            | (bytes[offset + 2] << 16)
            | (bytes[offset + 3] << 24));

    private static ushort ReadU16(ReadOnlySpan<byte> bytes, int offset) =>
        (ushort)(bytes[offset] | (bytes[offset + 1] << 8));
}
