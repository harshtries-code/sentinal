namespace Sentinel.Engine.Actions;

// Windows file-attribute bits the BCL does not name. Acting on a
// placeholder-only or offline file would trigger a silent cloud
// download (or fail); both are refused with an honest message.
public static class FileFlags
{
    // FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS (0x400000): opening the
    // file recalls its bytes from the cloud.
    public const FileAttributes RecallOnDataAccess = (FileAttributes)0x400000;

    public static bool IsCloudPlaceholder(FileAttributes attributes) =>
        (attributes & RecallOnDataAccess) != 0;

    // FILE_ATTRIBUTE_OFFLINE: data moved to offline storage.
    public static bool IsOffline(FileAttributes attributes) =>
        (attributes & FileAttributes.Offline) != 0;

    public static bool IsRecallable(FileAttributes attributes) =>
        IsCloudPlaceholder(attributes) || IsOffline(attributes);
}
