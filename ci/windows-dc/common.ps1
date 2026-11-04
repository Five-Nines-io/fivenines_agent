# Shared by stage1.ps1 and stage2.ps1 of the domain-controller E2E: report a
# line on COM1, which run-vm.sh reads from QEMU's serial log, and keep a copy
# on the VM's disk.

function Log {
    param([string]$Message)

    $line = "{0} {1}" -f (Get-Date -Format "HH:mm:ss"), $Message
    Add-Content -Path "C:\fn\progress.log" -Value $line -ErrorAction SilentlyContinue
    try {
        $port = New-Object System.IO.Ports.SerialPort("COM1", 115200)
        $port.Encoding = [System.Text.Encoding]::UTF8
        $port.Open()
        try {
            $port.WriteLine($line)
        } finally {
            $port.Close()
        }
    } catch {
        Add-Content -Path "C:\fn\progress.log" -Value "(serial: $_)" -ErrorAction SilentlyContinue
    }
}
