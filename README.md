# 🔍 Simple BAM Extractor - (SBE)

The Background Activity Moderator (BAM) is a Windows service that Controls activity of background applications. This service exists in Windows 10 only after Fall Creators update – version 1709.

It provides full path of the executable file that was run on the system and last execution date/time.

----------------------------------------

SBE extracts logs from **HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings** and translates *HarddiskVolume* to drive letters for easier access.  
Files are saved in the same directory where the program was executed, as:

- *sbe_all.csv* (contains all extracted information)
- *sbe_paths.txt* (contains paths only)

**SHA256**: 02887DB3D9551197CD77CFFC4CA8C75A73199F7AD3263B9D0B9DCEB0123C400B
