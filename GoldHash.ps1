<#
    GoldHash v1.0
    Windows File Integrity Baseline & Comparison Tool
    Author: PawnShuffler

    Features:
    - Baseline mode (compute hashes)
    - Compare mode
    - JSON / CSV / HTML output
    - Metadata block
    - Progress bars
    - Verbose mode
    - HTML report 
    - Detect: CORRECT / SUSPICIOUS / MISSING / UNKNOWN
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Baseline","Compare")]
    [string]$Mode,

    [Parameter(Mandatory=$false)]
    [string]$Path,

    [Parameter(Mandatory=$false)]
    [string]$BaselineFile,

    [Parameter(Mandatory=$false)]
    [ValidateSet("json","csv","html")]
    [string]$OutputType = "json",

    [Parameter(Mandatory=$false)]
    [string]$Output,

    [switch]$VerboseMode
)

# -----------------------------------------------
# Utility Functions
# -----------------------------------------------
function Write-VerboseLog($msg) {
    if ($VerboseMode) {
        Write-Host "[INFO] $msg" -ForegroundColor DarkGray
    }
}

function Normalize-OutputPath {
    param (
        [string]$Output,
        [string]$Mode,
        [string]$OutputType
    )

    if ([string]::IsNullOrWhiteSpace($Output)) {
        $dir = Split-Path -Parent $MyInvocation.MyCommand.Path
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        return Join-Path $dir "$Mode`_$timestamp.$OutputType"
    }

    # If folder, generate name inside
    if (Test-Path $Output -PathType Container) {
        $timestamp = (Get-Date).ToString("yyyyMMdd_HHmmss")
        return Join-Path $Output "$Mode`_$timestamp.$OutputType"
    }

    # Else assume file path
    return $Output
}

function Get-Metadata {
    param([string]$Mode, [string]$Path)

    return [PSCustomObject]@{
        GeneratedOn   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Mode          = $Mode
        MachineName   = $env:COMPUTERNAME
        Username      = $env:USERNAME
        OSVersion     = (Get-CimInstance Win32_OperatingSystem).Caption + " (" +
                        (Get-CimInstance Win32_OperatingSystem).Version + ")"
        ScriptVersion = "1.3"
        ScannedPath   = $Path
        HashAlgorithm = "SHA256"
    }
}

function Get-AllFiles {
    param([string]$TargetPath)
    try {
        return Get-ChildItem -Recurse -Force -Path $TargetPath -File -ErrorAction SilentlyContinue
    }
    catch {
        Write-VerboseLog "Error reading files: $_"
        return @()
    }
}

function Get-FileHashSafe {
    param([string]$FilePath)
    try {
        return (Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        Write-VerboseLog "Unable to hash: $FilePath - $_"
        return $null
    }
}

# -----------------------------------------------
# Baseline Mode
# -----------------------------------------------
if ($Mode -eq "Baseline") {

    if (-not (Test-Path $Path)) {
        Write-Host "Path '$Path' does not exist." -ForegroundColor Red
        exit
    }

    Write-Host "Running baseline creation on: $Path" -ForegroundColor Cyan

    $BaselineList = New-Object System.Collections.Generic.List[Object]
    $Files = Get-AllFiles -TargetPath $Path
    $Total = $Files.Count
    $i = 0

    foreach ($file in $Files) {
        $i++
        $pct = [int](($i / $Total) * 100)

        Write-Progress -Activity "Hashing files" -Status "$i of $Total" -PercentComplete $pct

        $hash = Get-FileHashSafe -FilePath $file.FullName

        $BaselineList.Add([PSCustomObject]@{
            FileName = $file.Name
            Path     = $file.FullName
            Hash     = $hash
        })

        Write-VerboseLog "Hashed: $($file.FullName)"
    }

    $Metadata = Get-Metadata -Mode "Baseline" -Path $Path
    $OutputFile = Normalize-OutputPath -Output $Output -Mode "baseline" -OutputType $OutputType

    # Save
    switch ($OutputType) {

        "json" {
            $json = [PSCustomObject]@{
                Metadata = $Metadata
                Files    = $BaselineList
            } | ConvertTo-Json -Depth 5

            $json | Out-File -Encoding UTF8 $OutputFile
        }

        "csv" {
            "# Metadata" | Out-File $OutputFile
            $Metadata.PSObject.Properties | ForEach-Object {
                "# $($_.Name): $($_.Value)" | Out-File $OutputFile -Append
            }
            "" | Out-File $OutputFile -Append
            $BaselineList | Export-Csv -NoTypeInformation -Append $OutputFile
        }

        "html" {
            # Baseline HTML output is supported but simple
            $html = @"
<html>
<head><title>Baseline Report</title></head>
<body>
<h2>Baseline Created</h2>
<p>Path: $Path</p>
<p>Total Files: $Total</p>
</body>
</html>
"@
            $html | Out-File $OutputFile
        }
    }

    Write-Host "Baseline saved to: $OutputFile" -ForegroundColor Green
    exit
}

# -----------------------------------------------
# Compare Mode
# -----------------------------------------------
if ($Mode -eq "Compare") {

    if (-not (Test-Path $BaselineFile)) {
        Write-Host "Baseline file does not exist: $BaselineFile" -ForegroundColor Red
        exit
    }

    if (-not (Test-Path $Path)) {
        Write-Host "Path '$Path' does not exist." -ForegroundColor Red
        exit
    }

    Write-Host "Running comparison..." -ForegroundColor Cyan

    # Load baseline
    $BaselineJson = Get-Content $BaselineFile -Raw | ConvertFrom-Json
    $BaselineList = $BaselineJson.Files

    # Extract paths
    $BaselineMap = @{}
    foreach ($b in $BaselineList) {
        $BaselineMap[$b.Path] = $b
    }

    # Scan current files
    $CurrentFiles = Get-AllFiles -TargetPath $Path
    $TotalActual = $CurrentFiles.Count
    $j = 0

    $Results = New-Object System.Collections.Generic.List[Object]

    # Compare existing files
    foreach ($file in $CurrentFiles) {
        $j++
        $pct = [int](($j / $TotalActual) * 100)

        Write-Progress -Activity "Comparing files" -Status "$j of $TotalActual" -PercentComplete $pct

        $currentHash = Get-FileHashSafe $file.FullName

        if ($BaselineMap.ContainsKey($file.FullName)) {
            $baselineHash = $BaselineMap[$file.FullName].Hash

            if ($currentHash -eq $baselineHash) {
                $state = "CORRECT"
            }
            else {
                $state = "SUSPICIOUS"
            }

            $Results.Add([PSCustomObject]@{
                FileName       = $file.Name
                Path           = $file.FullName
                HashCurrent    = $currentHash
                HashBaseline   = $baselineHash
                Status         = $state
            })

            $BaselineMap.Remove($file.FullName)
        }
        else {
            # UNKNOWN
            $Results.Add([PSCustomObject]@{
                FileName       = $file.Name
                Path           = $file.FullName
                HashCurrent    = $currentHash
                HashBaseline   = $null
                Status         = "UNKNOWN"
            })
        }

        Write-VerboseLog "Compared: $($file.FullName)"
    }

    # Missing files
    foreach ($missing in $BaselineMap.Keys) {
        $Results.Add([PSCustomObject]@{
            FileName       = Split-Path $missing -Leaf
            Path           = $missing
            HashCurrent    = $null
            HashBaseline   = $BaselineMap[$missing].Hash
            Status         = "MISSING"
        })
    }

    $Metadata = Get-Metadata -Mode "Compare" -Path $Path
    $OutputFile = Normalize-OutputPath -Output $Output -Mode "compare" -OutputType $OutputType

    # Save results
    switch ($OutputType) {

        "json" {
            $json = [PSCustomObject]@{
                Metadata = $Metadata
                Results  = $Results
            } | ConvertTo-Json -Depth 5

            $json | Out-File -Encoding UTF8 $OutputFile
        }

        "csv" {
            "# Metadata" | Out-File $OutputFile
            $Metadata.PSObject.Properties | ForEach-Object {
                "# $($_.Name): $($_.Value)" | Out-File $OutputFile -Append
            }
            "" | Out-File $OutputFile -Append
            $Results | Export-Csv -NoTypeInformation -Append $OutputFile
        }

        "html" {
            # Simple HTML, can be expanded if needed
            $html = @"
<html>
<head>
<title>GoldHash Report</title>
<style>
    body { font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px; }
    h2 { text-align: center; font-weight: 600; margin-bottom: 30px; }
    table { width: 100%; border-collapse: collapse; background: #ffffff; font-family: 'Courier New', monospace; font-size: 14px; }
    th { background: #333333; color: #ffffff; padding: 10px; border-bottom: 2px solid #222222; text-align: left; }
    td { padding: 8px; border-bottom: 1px solid #dddddd; white-space: pre-wrap; word-break: break-word; }
    tr:nth-child(even) { background: #f0f0f0; }
</style>
<style>
th:hover { background-color: #555; color: #fff; }
</style>

</head>
<body>
<h2>GoldHash Compare Report</h2>
<p>Path: $Path</p>
<table id="goldhashTable">
<tr>
<th onclick="sortTable(0)" style="cursor:pointer">File &#x25B2;&#x25BC;</th>
<th onclick="sortTable(1)" style="cursor:pointer">Path &#x25B2;&#x25BC;</th>
<th onclick="sortTable(2)" style="cursor:pointer">Status &#x25B2;&#x25BC;</th>
<th onclick="sortTable(3)" style="cursor:pointer">Baseline &#x25B2;&#x25BC;</th>
<th onclick="sortTable(4)" style="cursor:pointer">Current &#x25B2;&#x25BC;</th>
</tr>

"@

    foreach ($r in $Results) {
        $color = switch ($r.Status) {
            "CORRECT"    { "lightgreen" }
            "SUSPICIOUS" { "lightcoral" }
            "UNKNOWN"    { "lightblue" }
            "MISSING"    { "khaki" }
        }

        $html += "<tr style='background:$color'><td>$($r.FileName)</td><td>$($r.Path)</td><td>$($r.Status)</td><td>$($r.HashBaseline)</td><td>$($r.HashCurrent)</td></tr>"
    }

    $html += @"
</table>
<script>
function sortTable(n) {
  var table, rows, switching, i, x, y, shouldSwitch, dir, switchcount = 0;
  table = document.getElementById("goldhashTable");
  switching = true;
  dir = "asc"; 
  while (switching) {
    switching = false;
    rows = table.rows;
    for (i = 1; i < (rows.length - 1); i++) {
      shouldSwitch = false;
      x = rows[i].getElementsByTagName("TD")[n];
      y = rows[i + 1].getElementsByTagName("TD")[n];
      if (dir == "asc") {
        if (x.innerHTML.toLowerCase() > y.innerHTML.toLowerCase()) {
          shouldSwitch = true;
          break;
        }
      } else if (dir == "desc") {
        if (x.innerHTML.toLowerCase() < y.innerHTML.toLowerCase()) {
          shouldSwitch = true;
          break;
        }
      }
    }
    if (shouldSwitch) {
      rows[i].parentNode.insertBefore(rows[i + 1], rows[i]);
      switching = true;
      switchcount ++;      
    } else {
      if (switchcount == 0 && dir == "asc") {
        dir = "desc";
        switching = true;
      }
    }
  }
}
</script>

</body>
</html>
"@

    $html | Out-File $OutputFile -Encoding UTF8
}

    }

    Write-Host "Compare report saved to: $OutputFile" -ForegroundColor Green
    exit
}
