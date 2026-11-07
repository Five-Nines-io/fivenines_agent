# Diagnostic for issue #293 (throwaway branch, never merged), dot-sourced by
# the upgrade step. [LockProbe2] stays invisible to the installer's Restart
# Manager scan: it opens nothing until the old base_library.zip has been
# removed (InstallValidate is long over by then). From the moment the new file
# exists it samples, every millisecond, which processes have it open
# (NtQueryInformationFile FileProcessIdsUsingFileInformation, through a handle
# with FILE_READ_ATTRIBUTES only, which takes part in no sharing check), and,
# once the new agent holds it, opens it as Python does (GENERIC_READ,
# FILE_SHARE_READ | FILE_SHARE_WRITE), noting every failure with the holders
# of that instant.

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class LockProbe2 {
    [StructLayout(LayoutKind.Sequential)]
    struct IO_STATUS_BLOCK { public IntPtr Status; public IntPtr Information; }
    [DllImport("ntdll.dll")]
    static extern int NtQueryInformationFile(SafeFileHandle h, out IO_STATUS_BLOCK io, IntPtr info, int len, int cls);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);
    [DllImport("winmm.dll")]
    static extern uint timeBeginPeriod(uint ms);
    [DllImport("winmm.dll")]
    static extern uint timeEndPeriod(uint ms);

    static readonly List<string> lines = new List<string>();
    static readonly Dictionary<long, string> names = new Dictionary<long, string>();
    static volatile bool stop;
    static Thread worker;
    static long self = Process.GetCurrentProcess().Id;

    static void Note(string s) {
        lock (lines) { lines.Add(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); }
    }

    static string Name(long pid) {
        string n;
        if (names.TryGetValue(pid, out n)) return n;
        try { n = Process.GetProcessById((int)pid).ProcessName; } catch (Exception) { n = "?"; }
        names[pid] = n;
        return n;
    }

    // Null when the file cannot be queried; error then says why.
    static string Holders(string path, out string error) {
        error = null;
        using (SafeFileHandle h = CreateFile(path, 0x80, 0x7, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
            if (h.IsInvalid) { error = "open for attributes: " + Marshal.GetLastWin32Error(); return null; }
            int size = 8192;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try {
                IO_STATUS_BLOCK io;
                int st = NtQueryInformationFile(h, out io, buf, size, 47);
                if (st != 0) { error = "NtQueryInformationFile 0x" + st.ToString("X8"); return null; }
                int count = Marshal.ReadInt32(buf);
                List<string> parts = new List<string>();
                for (int i = 0; i < count && i < 1000; i++) {
                    long pid = Marshal.ReadIntPtr(buf, IntPtr.Size * (i + 1)).ToInt64();
                    if (pid == self) continue;
                    parts.Add(Name(pid) + "(" + pid + ")");
                }
                parts.Sort();
                return string.Join(", ", parts.ToArray());
            } finally {
                Marshal.FreeHGlobal(buf);
            }
        }
    }

    public static void Start(string path) {
        stop = false;
        lock (lines) { lines.Clear(); }
        worker = new Thread(delegate () { Run(path); });
        worker.IsBackground = true;
        worker.Start();
    }

    public static string[] Stop() {
        stop = true;
        if (worker != null) worker.Join(10000);
        lock (lines) { return lines.ToArray(); }
    }

    static void Run(string path) {
        timeBeginPeriod(1);
        long samples = 0;
        DateTime started = DateTime.UtcNow;
        try {
            bool removed = false, agentSeen = false;
            string lastHolders = null, lastFailure = null;
            int lastErr = -1;
            while (!stop) {
                bool exists = File.Exists(path);
                if (!removed) {
                    if (!exists) { removed = true; Note("old file removed"); }
                    Thread.Sleep(1);
                    continue;
                }
                if (!exists) { Thread.Sleep(1); continue; }
                samples++;
                try {
                    string error;
                    string holders = Holders(path, out error);
                    string shown = holders ?? ("unknown: " + error);
                    if (shown != lastHolders) { Note("holders: [" + shown + "]"); lastHolders = shown; }
                    if (holders != null && holders.Contains("fivenines-agent-windows-amd64")) agentSeen = true;
                    if (agentSeen) {
                        int err = 0;
                        using (SafeFileHandle fh = CreateFile(path, 0x80000000, 0x3, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                            if (fh.IsInvalid) err = Marshal.GetLastWin32Error();
                        }
                        if (err != lastErr) {
                            string now = Holders(path, out error) ?? ("unknown: " + error);
                            Note("python-like open: " + (err == 0 ? "ok" : "ERROR " + err + ", holders now: [" + now + "]"));
                            lastErr = err;
                        }
                    }
                } catch (Exception e) {
                    string what = e.GetType().Name + ": " + e.Message;
                    if (what != lastFailure) { Note("sample failed: " + what); lastFailure = what; }
                }
                Thread.Sleep(1);
            }
        } catch (Exception e) {
            Note("probe failed: " + e);
        } finally {
            timeEndPeriod(1);
            Note(string.Format("probe ended: {0} samples in {1:F1}s", samples, (DateTime.UtcNow - started).TotalSeconds));
        }
    }
}
"@

function Read-NewText([string]$Path, [long]$From) {
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    $fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        if ($fs.Length -lt $From) { $From = 0 }
        $fs.Seek($From, [IO.SeekOrigin]::Begin) | Out-Null
        return (New-Object IO.StreamReader($fs)).ReadToEnd()
    } finally {
        $fs.Dispose()
    }
}

function Get-LogSizes {
    $sizes = @{}
    Get-ChildItem "$env:ProgramData\fivenines_agent\logs" -File -ErrorAction SilentlyContinue | ForEach-Object { $sizes[$_.FullName] = $_.Length }
    return $sizes
}

# The hosted runner's own processes seen near the agent's files (provjobd):
# name, path, parent and file description only, never a command line.
function Show-RunnerHelpers {
    Get-CimInstance Win32_Process | Where-Object { $_.Name -like "provjobd*" -or $_.Name -like "provisioner*" } | ForEach-Object {
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.ParentProcessId)" -ErrorAction SilentlyContinue
        $desc = ""
        if ($_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath)) {
            $v = (Get-Item -LiteralPath $_.ExecutablePath).VersionInfo
            $desc = "$($v.CompanyName) / $($v.ProductName) / $($v.FileDescription) / $($v.FileVersion)"
        }
        Write-Host ("HELPER pid={0} name={1} path={2} started={3} parent={4}({5}) desc={6}" -f $_.ProcessId, $_.Name, $_.ExecutablePath, $_.CreationDate, $parent.Name, $_.ParentProcessId, $desc)
    }
}

function Show-Iteration([string]$Label, [datetime]$Since, [string[]]$ProbeLines, [hashtable]$LogSizes, [string]$MsiLog) {
    Write-Host "----- $Label"
    Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager"; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Message -match "Fivenines Monitoring Agent|fivenines-agent" } | Sort-Object TimeCreated |
        ForEach-Object { Write-Host ("SCM   {0:HH:mm:ss.fff} {1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace "\s+", " ")) }
    Get-WinEvent -FilterHashtable @{ LogName = "Application"; ProviderName = "Microsoft-Windows-RestartManager"; StartTime = $Since } -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -ne 10005 } | Sort-Object TimeCreated |
        ForEach-Object { Write-Host ("RMEVT {0:HH:mm:ss.fff} {1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace "\s+", " ")) }
    Get-Content -LiteralPath $MsiLog |
        Select-String -Pattern "RESTART MANAGER|ActionStart\(Name=(StartAgentService|StopServices|InstallFiles|RegisterProduct)|MainEngineThread is returning|Unlocking Server|Windows Installer installed" |
        ForEach-Object { Write-Host ("MSI   " + $_.Line) }
    foreach ($l in $ProbeLines) { Write-Host ("PROBE " + $l) }
    Get-ChildItem "$env:ProgramData\fivenines_agent\logs" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "wrapper|err" } | ForEach-Object {
        $from = 0
        if ($LogSizes.ContainsKey($_.FullName)) { $from = $LogSizes[$_.FullName] }
        $text = Read-NewText $_.FullName $from
        $keep = $text -split "`r?`n" | Where-Object { $_ -and $_ -notmatch "^\s+at |^The Zone|^MyComputer|^System.Security.SecurityException" }
        if ($keep) {
            Write-Host "LOG $($_.Name) (new lines):"
            $keep | Select-Object -Last 40 | ForEach-Object { Write-Host ("  " + $_) }
        }
    }
}
