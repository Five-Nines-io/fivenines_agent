# Diagnostic for issue #293 (throwaway branch, never merged): runs the
# v1.22.1 -> current MSI upgrade $Iterations times and, during each upgrade,
# samples _internal\base_library.zip: which processes hold it (RmGetList),
# its ACL (SDDL), and an open with the share mode Python uses (GENERIC_READ,
# FILE_SHARE_READ | FILE_SHARE_WRITE), once the new file is in place.
param(
    [Parameter(Mandatory = $true)] [string]$Variant,
    [int]$Iterations = 10,
    [string]$OldMsi = "old.msi",
    [string]$NewMsi = "fivenines-agent.msi",
    [string]$OutDir = "diag"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class LockProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct RM_UNIQUE_PROCESS { public int dwProcessId; public uint startLow; public uint startHigh; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmStartSession(out uint h, int flags, StringBuilder key);
    [DllImport("rstrtmgr.dll")]
    static extern int RmEndSession(uint h);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    static extern int RmRegisterResources(uint h, uint nFiles, string[] files, uint nApps, IntPtr apps, uint nSvcs, string[] svcs);
    [DllImport("rstrtmgr.dll")]
    static extern int RmGetList(uint h, out uint needed, ref uint n, [In, Out] RM_PROCESS_INFO[] info, ref uint reasons);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share, IntPtr sa, uint disposition, uint flags, IntPtr template);

    static readonly List<string> lines = new List<string>();
    static volatile bool stop;
    static Thread worker;

    static void Note(string s) {
        lock (lines) { lines.Add(DateTime.Now.ToString("HH:mm:ss.fff") + " " + s); }
    }

    static string Holders(uint h) {
        uint needed = 0, n = 0, reasons = 0;
        int rc = RmGetList(h, out needed, ref n, null, ref reasons);
        if (rc == 0 && needed == 0) return "";
        if (rc != 234 && rc != 0) return "RmGetList error " + rc;
        RM_PROCESS_INFO[] info = new RM_PROCESS_INFO[needed + 4];
        n = (uint)info.Length;
        rc = RmGetList(h, out needed, ref n, info, ref reasons);
        if (rc != 0) return "RmGetList error " + rc;
        List<string> parts = new List<string>();
        for (int i = 0; i < n; i++) {
            parts.Add(string.Format("pid={0} app='{1}' svc='{2}' type={3} session={4}",
                info[i].Process.dwProcessId, info[i].strAppName, info[i].strServiceShortName,
                info[i].ApplicationType, info[i].TSSessionId));
        }
        parts.Sort();
        return string.Join("; ", parts.ToArray());
    }

    static string Sddl(string path) {
        try {
            return File.GetAccessControl(path).GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
        } catch (Exception e) {
            return "unreadable: " + e.GetType().Name;
        }
    }

    public static void Start(string path, DateTime sinceUtc) {
        stop = false;
        lock (lines) { lines.Clear(); }
        worker = new Thread(delegate () { Run(path, sinceUtc); });
        worker.IsBackground = true;
        worker.Start();
    }

    public static string[] Stop() {
        stop = true;
        if (worker != null) worker.Join(10000);
        lock (lines) { return lines.ToArray(); }
    }

    static void Run(string path, DateTime sinceUtc) {
        uint h;
        int rc = RmStartSession(out h, 0, new StringBuilder(64));
        if (rc != 0) { Note("RmStartSession error " + rc); return; }
        rc = RmRegisterResources(h, 1, new string[] { path }, 0, IntPtr.Zero, 0, null);
        if (rc != 0) { Note("RmRegisterResources error " + rc); }
        string lastHolders = null, lastSddl = null, lastFile = null;
        int lastErr = -1;
        long loops = 0;
        DateTime? newSeen = null;
        DateTime started = DateTime.UtcNow;
        string lastFailure = null;
        try {
            while (!stop) {
                loops++;
                try {
                string holders = Holders(h);
                if (holders != lastHolders) { Note("holders: [" + holders + "]"); lastHolders = holders; }
                bool exists = File.Exists(path);
                string file = "absent";
                if (exists) {
                    DateTime ct = File.GetCreationTimeUtc(path);
                    FileInfo fi = new FileInfo(path);
                    file = string.Format("created {0:HH:mm:ss.fff}Z size {1} attrs {2}", ct, fi.Length, fi.Attributes);
                    if (ct > sinceUtc && newSeen == null) newSeen = DateTime.UtcNow;
                    string sddl = Sddl(path);
                    if (sddl != lastSddl) { Note("sddl: " + sddl); lastSddl = sddl; }
                }
                if (file != lastFile) { Note("file: " + file); lastFile = file; }
                // The open probe starts 1.5s after the new file appears, so it
                // never races the installer's own removal and copy of the file.
                if (newSeen != null && (DateTime.UtcNow - newSeen.Value).TotalMilliseconds > 1500) {
                    int err = 0;
                    using (SafeFileHandle fh = CreateFile(path, 0x80000000, 0x1 | 0x2, IntPtr.Zero, 3, 0, IntPtr.Zero)) {
                        if (fh.IsInvalid) err = Marshal.GetLastWin32Error();
                    }
                    if (err != lastErr) {
                        Note("open: " + (err == 0 ? "ok" : "error " + err + ", holders now: [" + Holders(h) + "], sddl now: " + Sddl(path)));
                        lastErr = err;
                    }
                }
                } catch (Exception e) {
                    // The file can vanish between two reads (the old
                    // product's removal): note it once, keep sampling.
                    string what = e.GetType().Name + ": " + e.Message;
                    if (what != lastFailure) { Note("sample failed: " + what); lastFailure = what; }
                }
                Thread.Sleep(1);
            }
        } catch (Exception e) {
            Note("probe failed: " + e);
        } finally {
            RmEndSession(h);
            Note(string.Format("probe ended: {0} samples in {1:F1}s", loops, (DateTime.UtcNow - started).TotalSeconds));
        }
    }
}
"@

$zip = "C:\Program Files\fivenines-agent\_internal\base_library.zip"
$errLog = "$env:ProgramData\fivenines_agent\logs\fivenines-agent-service.err.log"

function Install-Msi([string]$Msi, [string]$Log, [string]$Extra) {
    $argLine = "/i $Msi TOKEN=ci-diag-$(Get-Random) /qn /l*v $Log $Extra"
    return (Start-Process msiexec -ArgumentList $argLine -Wait -PassThru).ExitCode
}

function Wait-Running {
    for ($i = 0; $i -lt 30 -and (Get-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue).Status -ne "Running"; $i++) {
        Start-Sleep -Seconds 2
    }
    return [string](Get-Service -Name "fivenines-agent" -ErrorAction SilentlyContinue).Status
}

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

$results = @()
for ($i = 1; $i -le $Iterations; $i++) {
    Write-Host "::group::iteration $i ($Variant)"
    $code = Install-Msi $OldMsi "$OutDir\old-$i.log" ""
    if ($code -ne 0) { throw "iteration ${i}: installing v1.22.1 failed: $code" }
    $oldState = Wait-Running
    $errFrom = 0
    if (Test-Path -LiteralPath $errLog) { $errFrom = (Get-Item -LiteralPath $errLog).Length }

    $since = Get-Date
    $probe = $Variant -ne "default-noprobe"
    if ($probe) { [LockProbe]::Start($zip, $since.ToUniversalTime()) }
    $extra = ""
    if ($Variant -eq "rm-disabled") { $extra = "MSIRESTARTMANAGERCONTROL=Disable" }
    $code = Install-Msi $NewMsi "$OutDir\upgrade-$i.log" $extra
    $state = Wait-Running
    Start-Sleep -Seconds 15
    $probeLines = @()
    if ($probe) { $probeLines = [LockProbe]::Stop() }

    $scm = @(Get-WinEvent -FilterHashtable @{ LogName = "System"; ProviderName = "Service Control Manager"; StartTime = $since } -ErrorAction SilentlyContinue |
             Where-Object { $_.Message -match "Fivenines Monitoring Agent|fivenines-agent" } | Sort-Object TimeCreated)
    $crashes = @($scm | Where-Object { $_.Id -eq 7031 -or $_.Id -eq 7034 }).Count
    $rm = @(Get-WinEvent -FilterHashtable @{ LogName = "Application"; ProviderName = "Microsoft-Windows-RestartManager"; StartTime = $since } -ErrorAction SilentlyContinue |
            Sort-Object TimeCreated)
    $errNew = Read-NewText $errLog $errFrom
    $permError = $errNew -match "PermissionError"

    Write-Host ("old agent: {0}; upgrade msiexec: {1}; service: {2}; 7031/7034: {3}; PermissionError: {4}" -f $oldState, $code, $state, $crashes, $permError)
    foreach ($e in $scm) { Write-Host ("SCM   {0:HH:mm:ss.fff} {1} {2}" -f $e.TimeCreated, $e.Id, ($e.Message -replace "\s+", " ")) }
    foreach ($e in $rm) { Write-Host ("RMEVT {0:HH:mm:ss.fff} {1} {2}" -f $e.TimeCreated, $e.Id, ($e.Message -replace "\s+", " ")) }
    Get-Content -LiteralPath "$OutDir\upgrade-$i.log" |
        Select-String -Pattern "RESTART MANAGER|ActionStart\(Name=(StartAgentService|StopServices|InstallFiles|RegisterProduct)|ServiceControl\(|MainEngineThread is returning|Unlocking Server|Windows Installer installed" |
        ForEach-Object { Write-Host ("MSI   " + $_.Line) }
    foreach ($l in $probeLines) { Write-Host ("PROBE " + $l) }
    if ($errNew) {
        Write-Host "ERRLOG (new lines):"
        $errNew -split "`r?`n" | Select-Object -Last 30 | ForEach-Object { Write-Host ("  " + $_) }
    }
    $probeLines | Set-Content -LiteralPath "$OutDir\probe-$i.txt"
    $scm + $rm | ForEach-Object { "{0:HH:mm:ss.fff} {1} {2}" -f $_.TimeCreated, $_.Id, ($_.Message -replace "\s+", " ") } |
        Set-Content -LiteralPath "$OutDir\events-$i.txt"
    $errNew | Set-Content -LiteralPath "$OutDir\errlog-$i.txt"
    Write-Host "::endgroup::"

    $results += [pscustomobject]@{
        Iteration = $i; Variant = $Variant; Msiexec = $code; Service = $state
        Crashes = $crashes; PermissionError = $permError
        OpenErrors = @($probeLines | Where-Object { $_ -match " open: error" }).Count
    }
    Start-Process msiexec -ArgumentList "/x $NewMsi /qn /l*v $OutDir\uninstall-$i.log" -Wait | Out-Null
}

$table = $results | Format-Table -AutoSize | Out-String -Width 200
Write-Host $table
$fence = '```'
"## $Variant`n$fence`n$table$fence" | Out-File -Append -Encoding utf8 $env:GITHUB_STEP_SUMMARY
