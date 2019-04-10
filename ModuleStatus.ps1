Get-Process | Select-Object -ExpandProperty Modules -ErrorAction SilentlyContinue | Sort-Object -Unique ModuleName | % {
    $StatusCheck = Get-AuthenticodeSignature -FilePath $_.FileName
    if ($StatusCheck.Status -notmatch "Valid") {
        Get-AuthenticodeSignature -FilePath $_.FileName | Select-Object Path, Status
    }
}
