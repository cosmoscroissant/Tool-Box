param(
    [Parameter(Mandatory=$true)]
    [string]$BinaryFile,
    [string]$ScriptFile = "ida_ir_extractor.py",
    [string]$OutputFile = "ir_with_idainfo.txt"
)

$IDAProcess = Start-Process -FilePath "C:\Program Files\IDA Professional 9.2\ida.exe" -ArgumentList "-L`"$OutputFile`"","-A","-S`"$ScriptFile`"","`"$BinaryFile`"" -PassThru -WindowStyle Hidden
$LastSize = 0
$FunctionCount = 0

while (!$IDAProcess.HasExited) {
    Start-Sleep -Seconds 3

    if (Test-Path $OutputFile) {
        $CurrentSize = (Get-Item $OutputFile).Length
        
        if ($CurrentSize -gt $LastSize) {
            $SizeIncrease = $CurrentSize - $LastSize
            $LastSize = $CurrentSize
            
            try {
                $Content = Get-Content $OutputFile 2>$null
                $MicrocodeLines = $Content | Where-Object { $_ -match "--- IR FOR" }
                $FunctionCount = $MicrocodeLines.Count
                Write-Host "Progress: $FunctionCount functions processed, $([math]::Round($CurrentSize/1024,2)) KB written"
            } catch {
                Write-Host "File Size: $([math]::Round($CurrentSize/1024,2)) KB"
            }
        }
    }
}