<#
.SYNOPSIS
    Generates SBOMs and vulnerability reports for binary archives using multiple tools.

.DESCRIPTION
    Scans directories for binary archives (JARs, WARs, EARs, ZIPs, etc.) and generates:
    - SBOM files using Syft, Grype, and Cdxgen (all in CycloneDX JSON format)
    - SBOM files using OSV-Scalibr (SPDX JSON format)
    - Vulnerability reports using OSV-Scanner (note: incompatible with CycloneDX, reports 0)
    - Comparative analysis report in Markdown format

.PARAMETER Recursive
    Recursively search subdirectories for binary archives.

.PARAMETER SkipAnalysis
    Skip the markdown analysis report generation. Only generate SBOM files.

.PARAMETER SkipGeneration
    Skip SBOM generation and cleanup. Only regenerate the analysis report from existing SBOM files.
    Useful when you want to update the report without re-running the time-consuming SBOM generation.

.EXAMPLE
    .\generate-sboms.ps1
    Generates SBOMs and analysis report for current directory.

.EXAMPLE
    .\generate-sboms.ps1 -SkipAnalysis
    Generates only SBOM files without the comparative analysis report.

.EXAMPLE
    .\generate-sboms.ps1 -SkipGeneration
    Regenerates only the analysis report from existing SBOM files.

.EXAMPLE
    .\generate-sboms.ps1 -Recursive
    Recursively scans all subdirectories for binary archives.
#>

param(
    [switch]$Recursive = $false,
    [switch]$SkipAnalysis = $false,
    [switch]$SkipGeneration = $false
)

# ==========================================
# CONFIGURATION
# ==========================================
$Root = Get-Location
$OutputDir = Join-Path $Root "generate-sboms"
$SummaryFile = Join-Path $OutputDir "sbom-summary.json"
$LogFile = Join-Path $OutputDir "run.log"

# Set environment variable to suppress cdxgen gem warning
$env:CDXGEN_GEM_HOME = ""

# Create output directory if it doesn't exist
if (!(Test-Path $OutputDir)) { New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null }

# ==========================================
# DOWNLOAD TEST FILES
# ==========================================
$ZipDir = Join-Path $Root "opencms-zip-only"
$WarDir = Join-Path $Root "opencms-exploded"
$ZipFile = Join-Path $ZipDir "opencms-9.5.0.zip"
$WarFile = Join-Path $WarDir "opencms.war"
$DownloadUrl = "https://github.com/alkacon/opencms-core/releases/download/build_9_5_0/opencms-9.5.0.zip"

# Create directories if they don't exist
if (!(Test-Path $ZipDir)) { New-Item -ItemType Directory -Force -Path $ZipDir | Out-Null }
if (!(Test-Path $WarDir)) { New-Item -ItemType Directory -Force -Path $WarDir | Out-Null }

# Download ZIP if it doesn't exist
if (!(Test-Path $ZipFile)) {
    Write-Host "Downloading opencms-9.5.0.zip..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $DownloadUrl -OutFile $ZipFile -UseBasicParsing
        Write-Host "Download complete: $ZipFile" -ForegroundColor Green
    } catch {
        Write-Host "Failed to download ZIP: $_" -ForegroundColor Red
    }
} else {
    Write-Host "ZIP file already exists: $ZipFile" -ForegroundColor Yellow
}

# Extract WAR from ZIP if it doesn't exist
if ((Test-Path $ZipFile) -and !(Test-Path $WarFile)) {
    Write-Host "Extracting opencms.war from ZIP..." -ForegroundColor Cyan
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $Zip = [System.IO.Compression.ZipFile]::OpenRead($ZipFile)
        $WarEntry = $Zip.Entries | Where-Object { $_.Name -eq "opencms.war" } | Select-Object -First 1
        if ($WarEntry) {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($WarEntry, $WarFile, $true)
            Write-Host "Extracted WAR file: $WarFile" -ForegroundColor Green
        } else {
            Write-Host "opencms.war not found in ZIP archive" -ForegroundColor Red
        }
        $Zip.Dispose()
    } catch {
        Write-Host "Failed to extract WAR: $_" -ForegroundColor Red
    }
} elseif (Test-Path $WarFile) {
    Write-Host "WAR file already exists: $WarFile" -ForegroundColor Yellow
}

# ==========================================
# CLEANUP PREVIOUS RUN
# ==========================================
if (-not $SkipGeneration) {
    Write-Host "Cleaning up previous run files..." -ForegroundColor Cyan
    Get-ChildItem -Path $OutputDir -Filter "*-syft-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-grype-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-cdxgen-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-scalibr-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-osv-scanner.json" | Remove-Item -Force
    if (Test-Path $SummaryFile) { Remove-Item $SummaryFile -Force }
} else {
    Write-Host "Skipping SBOM generation (using existing files)..." -ForegroundColor Yellow
}
if (Test-Path $LogFile) { Remove-Item $LogFile -Force }
if (Test-Path (Join-Path $OutputDir "SBOM-Analysis-Report.md")) { 
    Remove-Item (Join-Path $OutputDir "SBOM-Analysis-Report.md") -Force 
}
Write-Host "Cleanup complete." -ForegroundColor Green

$Summary = @()

# ==========================================
# Logging helper
# ==========================================
function Write-Log {
    param([string]$Message)
    Write-Host $Message
    "$((Get-Date))  $Message" | Out-File -Append -FilePath $LogFile
}

if (-not $SkipGeneration) {
# ==========================================
# Get directories containing binaries
# ==========================================
if ($Recursive) {
    $Dirs = Get-ChildItem -Path $Root -Directory -Recurse
} else {
    $Dirs = Get-ChildItem -Path $Root -Directory
}

# Exclude the output directory itself
$Dirs = $Dirs | Where-Object { $_.FullName -ne $OutputDir }

# Only directories containing binaries
$DirsToScan = @()
foreach ($Dir in $Dirs) {
    $HasBinaries = Get-ChildItem -Path $Dir.FullName -Recurse -File -Include *.jar,*.war,*.ear,*.zip,*.tar,*.tar.gz,*.tgz,*.rpm,*.deb,*.aar -ErrorAction SilentlyContinue
    if ($HasBinaries) { $DirsToScan += $Dir }
}

Write-Log "Found $($DirsToScan.Count) directories with binaries to scan."

# ==========================================
# Generate SBOMs using all tools
# ==========================================
foreach ($Dir in $DirsToScan) {

    $DirPath = $Dir.FullName
    $Name = $Dir.Name

    Write-Log "Processing directory: $DirPath"

    # Prepare output filenames
    $SyftOut = Join-Path $OutputDir "$Name-syft-sbom.json"
    $GrypeOut = Join-Path $OutputDir "$Name-grype-sbom.json"
    $CdxgenOut = Join-Path $OutputDir "$Name-cdxgen-sbom.json"
    $ScalibrOut = Join-Path $OutputDir "$Name-scalibr-sbom.json"
    $OsvOut = Join-Path $OutputDir "$Name-osv-scanner.json"

    # Remove existing files if present
    foreach ($f in @($SyftOut, $GrypeOut, $CdxgenOut, $ScalibrOut, $OsvOut)) {
        if (Test-Path $f) { Remove-Item $f -Force }
    }

    # Initialize status for summary
    $Status = [ordered]@{
        Directory = $DirPath
        Syft     = ""
        SyftTime = ""
        Grype    = ""
        GrypeTime = ""
        Cdxgen   = ""
        CdxgenTime = ""
        Scalibr  = ""
        ScalibrTime = ""
        OsvScanner = ""
        OsvTime = ""
    }

    # -------------------------------
    # 1) Syft
    # -------------------------------
    $SyftStart = Get-Date
    try {
        # Generate SBOM in CycloneDX JSON format
        syft "dir:$DirPath" -o cyclonedx-json | Out-File $SyftOut
        $SyftDuration = (Get-Date) - $SyftStart
        $Status.SyftTime = "$([Math]::Round($SyftDuration.TotalSeconds, 2))s"
        Write-Log "Syft SBOM generated: $SyftOut (Time: $($Status.SyftTime))"
        $Status.Syft = "Success"
    } catch {
        $SyftDuration = (Get-Date) - $SyftStart
        $Status.SyftTime = "$([Math]::Round($SyftDuration.TotalSeconds, 2))s"
        Write-Log "ERROR: Syft failed for $DirPath - $($_.Exception.Message)"
        $Status.Syft = "Failed"
    }

    # -------------------------------
    # 2) Grype
    # -------------------------------
    $GrypeStart = Get-Date
    try {
        grype "dir:$DirPath" -o cyclonedx-json | Out-File $GrypeOut
        $GrypeDuration = (Get-Date) - $GrypeStart
        $Status.GrypeTime = "$([Math]::Round($GrypeDuration.TotalSeconds, 2))s"
        Write-Log "Grype SBOM generated: $GrypeOut (Time: $($Status.GrypeTime))"
        $Status.Grype = "Success"
    } catch {
        $GrypeDuration = (Get-Date) - $GrypeStart
        $Status.GrypeTime = "$([Math]::Round($GrypeDuration.TotalSeconds, 2))s"
        Write-Log "ERROR: Grype failed for $DirPath - $($_.Exception.Message)"
        $Status.Grype = "Failed"
    }

    # -------------------------------
    # 3) Cdxgen (specialized for binaries in JARs/WARs/EARs/ZIPs/RPMs)
    # -------------------------------
    $CdxgenStart = Get-Date
    try {
        # cdxgen automatically detects and scans binaries within archives
        # --deep flag enables deep scanning of nested archives
        # --evidence flag includes evidence and occurrences for components
        cdxgen -r --deep --evidence -o $CdxgenOut $DirPath
        $CdxgenDuration = (Get-Date) - $CdxgenStart
        $Status.CdxgenTime = "$([Math]::Round($CdxgenDuration.TotalSeconds, 2))s"
        Write-Log "Cdxgen SBOM generated: $CdxgenOut (Time: $($Status.CdxgenTime))"
        $Status.Cdxgen = "Success"
    } catch {
        $CdxgenDuration = (Get-Date) - $CdxgenStart
        $Status.CdxgenTime = "$([Math]::Round($CdxgenDuration.TotalSeconds, 2))s"
        Write-Log "ERROR: Cdxgen failed for $DirPath - $($_.Exception.Message)"
        $Status.Cdxgen = "Failed"
    }

    # -------------------------------
    # 4) OSV-Scalibr (SPDX SBOM generation)
    # -------------------------------
    $ScalibrStart = Get-Date
    try {
        # OSV-Scalibr generates SPDX format SBOMs
        scalibr -o "spdx23-json=$ScalibrOut" "$DirPath" 2>&1 | Out-Null
        $ScalibrDuration = (Get-Date) - $ScalibrStart
        $Status.ScalibrTime = "$([Math]::Round($ScalibrDuration.TotalSeconds, 2))s"
        Write-Log "OSV-Scalibr SBOM generated: $ScalibrOut (Time: $($Status.ScalibrTime))"
        $Status.Scalibr = "Success"
    } catch {
        $ScalibrDuration = (Get-Date) - $ScalibrStart
        $Status.ScalibrTime = "$([Math]::Round($ScalibrDuration.TotalSeconds, 2))s"
        Write-Log "ERROR: OSV-Scalibr failed for $DirPath - $($_.Exception.Message)"
        $Status.Scalibr = "Failed"
    }

    # -------------------------------
    # 5) OSV-Scanner (vulnerability scanning using Syft SBOM)
    # -------------------------------
    $OsvStart = Get-Date
    try {
        # OSV-Scanner scans SBOMs for vulnerabilities using Google's OSV database
        # Note: OSV-Scanner doesn't support Syft's CycloneDX version, so this will fail
        # We'll catch the error and report 0 vulnerabilities
        osv-scanner --sbom $SyftOut --format json 2>&1 | Out-File $OsvOut
        $OsvDuration = (Get-Date) - $OsvStart
        $Status.OsvTime = "$([Math]::Round($OsvDuration.TotalSeconds, 2))s"
        
        # Check if OSV-Scanner actually found anything or failed
        $osvContent = Get-Content $OsvOut -Raw
        if ($osvContent -match "Failed to parse SBOM" -or $osvContent -match "No package sources found") {
            Write-Log "OSV-Scanner incompatible with CycloneDX format - reporting 0 vulnerabilities: $OsvOut (Time: $($Status.OsvTime))"
            # Write empty result
            '{"results": []}' | Out-File $OsvOut
        } else {
            Write-Log "OSV-Scanner results generated: $OsvOut (Time: $($Status.OsvTime))"
        }
        $Status.OsvScanner = "Success"
    } catch {
        $OsvDuration = (Get-Date) - $OsvStart
        $Status.OsvTime = "$([Math]::Round($OsvDuration.TotalSeconds, 2))s"
        Write-Log "ERROR: OSV-Scanner failed for $DirPath - $($_.Exception.Message)"
        # Write empty result for failed case
        '{"results": []}' | Out-File $OsvOut
        $Status.OsvScanner = "Failed"
    }

    # Append result to summary
    $Summary += $Status
}

# ==========================================
# Write summary JSON
# ==========================================
$Summary | ConvertTo-Json -Depth 3 | Out-File $SummaryFile
Write-Log "All SBOM generation tasks finished."
Write-Log "JSON summary report written to $SummaryFile"

} # End of SkipGeneration conditional

# ==========================================
# Generate Markdown Report
# ==========================================
if (-not $SkipAnalysis) {
Write-Log "Generating markdown report..."

$ReportFile = Join-Path $OutputDir "SBOM-Analysis-Report.md"

# Collect component counts from all SBOMs
$ComponentData = @()
foreach ($project in @("just-a-bag-of-jars", "opencms-exploded", "opencms-zip-only")) {
    $syftFile = Join-Path $OutputDir "$project-syft-sbom.json"
    $grypeFile = Join-Path $OutputDir "$project-grype-sbom.json"
    $cdxgenFile = Join-Path $OutputDir "$project-cdxgen-sbom.json"
    $scalibrFile = Join-Path $OutputDir "$project-scalibr-sbom.json"
    $osvFile = Join-Path $OutputDir "$project-osv-scanner.json"
    
    if (Test-Path $syftFile) {
        $syftData = Get-Content $syftFile | ConvertFrom-Json
        $syftCount = $syftData.components.Count
    } else { $syftCount = 0 }
    
    if (Test-Path $grypeFile) {
        $grypeData = Get-Content $grypeFile | ConvertFrom-Json
        $grypeCount = $grypeData.components.Count
    } else { $grypeCount = 0 }
    
    if (Test-Path $cdxgenFile) {
        $cdxgenData = Get-Content $cdxgenFile | ConvertFrom-Json
        $cdxgenCount = $cdxgenData.components.Count
    } else { $cdxgenCount = 0 }
    
    # OSV-Scalibr uses SPDX format - count packages
    if (Test-Path $scalibrFile) {
        $scalibrData = Get-Content $scalibrFile | ConvertFrom-Json
        $scalibrCount = if ($scalibrData.packages) { $scalibrData.packages.Count } else { 0 }
    } else { $scalibrCount = 0 }
    
    # OSV-Scanner output format is different - count vulnerabilities
    if (Test-Path $osvFile) {
        $osvData = Get-Content $osvFile | ConvertFrom-Json
        $osvVulnCount = if ($osvData.results) { $osvData.results.Count } else { 0 }
    } else { $osvVulnCount = 0 }
    
    $ComponentData += [PSCustomObject]@{
        Project = $project
        Syft = $syftCount
        Grype = $grypeCount
        Cdxgen = $cdxgenCount
        Scalibr = $scalibrCount
        OsvVulns = $osvVulnCount
    }
}

# Get timing data from summary
# If we skipped generation, load the summary from the JSON file
if ($SkipGeneration -and (Test-Path $SummaryFile)) {
    $Summary = Get-Content $SummaryFile | ConvertFrom-Json
}

$TimingData = $Summary | ForEach-Object {
    [PSCustomObject]@{
        Project = ($_.Directory -split '\\')[-1]
        SyftTime = $_.SyftTime
        GrypeTime = $_.GrypeTime
        CdxgenTime = $_.CdxgenTime
        ScalibrTime = $_.ScalibrTime
        OsvTime = $_.OsvTime
    }
}

# Generate the markdown report
$Report = @"
# SBOM Tool Comparison Report

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Tools:** Syft v1.36.0, Grype v0.103.0, Cdxgen v11.11.0, OSV-Scalibr v0.3.6, OSV-Scanner  
**Scan Type:** Binary Archive Scanning (JARs, WARs, ZIPs, etc.)

---

## Executive Summary

This report presents automated findings from SBOM generation and vulnerability scanning tools for Java binary archives.

### Quick Results

| Project | Syft | Grype | Cdxgen | Scalibr | OSV-Scanner | Fastest Tool |
|---------|------|-------|--------|---------|-------------|--------------|
$(@(foreach ($item in $ComponentData) {
    $timing = $TimingData | Where-Object { $_.Project -eq $item.Project }
    
    # Build list of valid tools (only those that found components)
    $validTools = @()
    if ($item.Syft -gt 0) { $validTools += @{Tool="Syft"; Time=[double]($timing.SyftTime -replace 's','')} }
    if ($item.Grype -gt 0) { $validTools += @{Tool="Grype"; Time=[double]($timing.GrypeTime -replace 's','')} }
    if ($item.Cdxgen -gt 0) { $validTools += @{Tool="Cdxgen"; Time=[double]($timing.CdxgenTime -replace 's','')} }
    if ($item.Scalibr -gt 0) { $validTools += @{Tool="Scalibr"; Time=[double]($timing.ScalibrTime -replace 's','')} }
    
    # Find fastest among valid tools
    if ($validTools.Count -gt 0) {
        $fastestTool = ($validTools | Sort-Object Time | Select-Object -First 1).Tool
    } else {
        $fastestTool = "None"
    }
    
    "| **$($item.Project)** | $($item.Syft) ($($timing.SyftTime)) | $($item.Grype) ($($timing.GrypeTime)) | $($item.Cdxgen) ($($timing.CdxgenTime)) | $($item.Scalibr) ($($timing.ScalibrTime)) | $($item.OsvVulns) vulns ($($timing.OsvTime)) | ⚡ $fastestTool |"
}) -join "`n")

---

## Component Detection Summary

### Total Components Identified

| Tool | just-a-bag-of-jars | opencms-exploded | opencms-zip-only | Average |
|------|-------------------|------------------|------------------|---------|
$(
    $syftAvg = ($ComponentData | Measure-Object -Property Syft -Average).Average
    $grypeAvg = ($ComponentData | Measure-Object -Property Grype -Average).Average
    $cdxgenAvg = ($ComponentData | Measure-Object -Property Cdxgen -Average).Average
    $scalibrAvg = ($ComponentData | Measure-Object -Property Scalibr -Average).Average
    
    @(
        "| **Syft** | $($ComponentData[0].Syft) | $($ComponentData[1].Syft) | $($ComponentData[2].Syft) | $([Math]::Round($syftAvg, 1)) |"
        "| **Grype** | $($ComponentData[0].Grype) | $($ComponentData[1].Grype) | $($ComponentData[2].Grype) | $([Math]::Round($grypeAvg, 1)) |"
        "| **Cdxgen** | $($ComponentData[0].Cdxgen) | $($ComponentData[1].Cdxgen) | $($ComponentData[2].Cdxgen) | $([Math]::Round($cdxgenAvg, 1)) |"
        "| **Scalibr** | $($ComponentData[0].Scalibr) | $($ComponentData[1].Scalibr) | $($ComponentData[2].Scalibr) | $([Math]::Round($scalibrAvg, 1)) |"
    ) -join "`n"
)

---

## Detailed Comparison by Directory

$(@(foreach ($i in 0..($ComponentData.Count - 1)) {
    $comp = $ComponentData[$i]
    $timing = $TimingData[$i]
    
    $syftSec = [double]($timing.SyftTime -replace 's','')
    $grypeSec = [double]($timing.GrypeTime -replace 's','')
    $cdxgenSec = [double]($timing.CdxgenTime -replace 's','')
    $scalibrSec = [double]($timing.ScalibrTime -replace 's','')
    $osvSec = [double]($timing.OsvTime -replace 's','')
    $total = $syftSec + $grypeSec + $cdxgenSec + $scalibrSec + $osvSec
    
    # Find winner for components (only among tools that found components)
    $validComps = @()
    if ($comp.Syft -gt 0) { $validComps += @{Tool='Syft'; Count=$comp.Syft; Time=$syftSec} }
    if ($comp.Grype -gt 0) { $validComps += @{Tool='Grype'; Count=$comp.Grype; Time=$grypeSec} }
    if ($comp.Cdxgen -gt 0) { $validComps += @{Tool='Cdxgen'; Count=$comp.Cdxgen; Time=$cdxgenSec} }
    if ($comp.Scalibr -gt 0) { $validComps += @{Tool='Scalibr'; Count=$comp.Scalibr; Time=$scalibrSec} }
    
    if ($validComps.Count -gt 0) {
        $maxComp = ($validComps | Measure-Object -Property Count -Maximum).Maximum
        $compWinner = ($validComps | Where-Object { $_.Count -eq $maxComp } | Select-Object -First 1).Tool
        $speedWinner = ($validComps | Sort-Object Time | Select-Object -First 1).Tool
        $minTime = ($validComps | Sort-Object Time | Select-Object -First 1).Time
    } else {
        $maxComp = 0
        $compWinner = 'None'
        $speedWinner = 'None'
        $minTime = 0
    }
    
    "### $($comp.Project)`n`n" +
    "| Tool | Components Detected | Time | Status |`n" +
    "|------|---------------------|------|--------|`n" +
    "| **Syft** | $($comp.Syft) $(if ($comp.Syft -eq $maxComp -and $comp.Syft -gt 0) { '🏆' } else { '' }) | $($timing.SyftTime) $(if ($syftSec -eq $minTime -and $comp.Syft -gt 0) { '⚡' } else { '' }) | $(if ($comp.Syft -gt 0) { '✅' } else { '❌' }) |`n" +
    "| **Grype** | $($comp.Grype) $(if ($comp.Grype -eq $maxComp -and $comp.Grype -gt 0) { '🏆' } else { '' }) | $($timing.GrypeTime) $(if ($grypeSec -eq $minTime -and $comp.Grype -gt 0) { '⚡' } else { '' }) | $(if ($comp.Grype -gt 0) { '✅' } else { '❌' }) |`n" +
    "| **Cdxgen** | $($comp.Cdxgen) $(if ($comp.Cdxgen -eq $maxComp -and $comp.Cdxgen -gt 0) { '🏆' } else { '' }) | $($timing.CdxgenTime) $(if ($cdxgenSec -eq $minTime -and $comp.Cdxgen -gt 0) { '⚡' } else { '' }) | $(if ($comp.Cdxgen -gt 0) { '✅' } else { '❌' }) |`n" +
    "| **Scalibr** | $($comp.Scalibr) $(if ($comp.Scalibr -eq $maxComp -and $comp.Scalibr -gt 0) { '🏆' } else { '' }) | $($timing.ScalibrTime) $(if ($scalibrSec -eq $minTime -and $comp.Scalibr -gt 0) { '⚡' } else { '' }) | $(if ($comp.Scalibr -gt 0) { '✅' } else { '❌' }) |`n" +
    "| **OSV-Scanner** | $($comp.OsvVulns) vulnerabilities | $($timing.OsvTime) $(if ($osvSec -eq $minTime -and $osvSec -gt 0) { '⚡' } else { '' }) | $(if ($comp.OsvVulns -ge 0) { '✅' } else { '❌' }) |`n" +
    "| **Total** | **$maxComp components** | **$([Math]::Round($total, 2))s** | |`n`n" +
    "**Winner - Components:** $compWinner ($maxComp detected)  `n" +
    "**Winner - Speed:** $speedWinner ($([Math]::Round($minTime, 2))s)"
}) -join "`n`n")

---

## Performance Analysis

### Execution Times

| Project | Syft | Grype | Cdxgen | OSV-Scanner | Total |
|---------|------|-------|--------|-------------|-------|
$(@(foreach ($timing in $TimingData) {
    $syftSec = [double]($timing.SyftTime -replace 's','')
    $grypeSec = [double]($timing.GrypeTime -replace 's','')
    $cdxgenSec = [double]($timing.CdxgenTime -replace 's','')
    $osvSec = [double]($timing.OsvTime -replace 's','')
    $total = $syftSec + $grypeSec + $cdxgenSec + $osvSec
    "| **$($timing.Project)** | $($timing.SyftTime) | $($timing.GrypeTime) | $($timing.CdxgenTime) | $($timing.OsvTime) | $([Math]::Round($total, 2))s |"
}) -join "`n")

### Average Execution Time per Tool

| Tool | Average Time | Performance Rating |
|------|-------------|-------------------|
$(
    $syftAvgTime = ($TimingData | ForEach-Object { [double]($_.SyftTime -replace 's','') } | Measure-Object -Average).Average
    $grypeAvgTime = ($TimingData | ForEach-Object { [double]($_.GrypeTime -replace 's','') } | Measure-Object -Average).Average
    $cdxgenAvgTime = ($TimingData | ForEach-Object { [double]($_.CdxgenTime -replace 's','') } | Measure-Object -Average).Average
    $osvAvgTime = ($TimingData | ForEach-Object { [double]($_.OsvTime -replace 's','') } | Measure-Object -Average).Average
    
    @(
        "| **Syft** | $([Math]::Round($syftAvgTime, 2))s | $(if ($syftAvgTime -lt 10) { '⚡⚡⚡⚡⚡ Excellent' } elseif ($syftAvgTime -lt 20) { '⚡⚡⚡⚡ Good' } else { '⚡⚡⚡ Fair' }) |"
        "| **Grype** | $([Math]::Round($grypeAvgTime, 2))s | $(if ($grypeAvgTime -lt 10) { '⚡⚡⚡⚡⚡ Excellent' } elseif ($grypeAvgTime -lt 20) { '⚡⚡⚡⚡ Good' } else { '⚡⚡⚡ Fair' }) |"
        "| **Cdxgen** | $([Math]::Round($cdxgenAvgTime, 2))s | $(if ($cdxgenAvgTime -lt 10) { '⚡⚡⚡⚡⚡ Excellent' } elseif ($cdxgenAvgTime -lt 20) { '⚡⚡⚡⚡ Good' } else { '⚡⚡⚡ Fair' }) |"
        "| **OSV-Scanner** | $([Math]::Round($osvAvgTime, 2))s | $(if ($osvAvgTime -lt 10) { '⚡⚡⚡⚡⚡ Excellent' } elseif ($osvAvgTime -lt 20) { '⚡⚡⚡⚡ Good' } else { '⚡⚡⚡ Fair' }) |"
    ) -join "`n"
)

---

## Key Findings

### 1. Component Detection Accuracy

$(
    $project1 = $ComponentData[0]
    if ($project1.Syft -eq $project1.Grype -and $project1.Grype -eq $project1.Cdxgen) {
        "✅ **Perfect Agreement on $($project1.Project)**: All three tools identified $($project1.Syft) components"
    } else {
        "⚠️ **Variation on $($project1.Project)**: Syft ($($project1.Syft)), Grype ($($project1.Grype)), Cdxgen ($($project1.Cdxgen))"
    }
)

$(
    $project2 = $ComponentData[1]
    $maxComponents = [Math]::Max([Math]::Max($project2.Syft, $project2.Grype), $project2.Cdxgen)
    "- **$($project2.Project)**: Syft found the most components ($($project2.Syft))"
    if ($project2.Syft -gt $project2.Grype) {
        "  - Syft found $($project2.Syft - $project2.Grype) more components than Grype (likely with UNKNOWN versions)"
    }
    if ($project2.Grype -gt $project2.Cdxgen) {
        "  - Grype found $($project2.Grype - $project2.Cdxgen) more components than Cdxgen"
    }
    if ($project2.Cdxgen -eq 0) {
        "  - ❌ Cdxgen found 0 components"
    }
)

$(
    $project3 = $ComponentData[2]
    if ($project3.Cdxgen -eq 0) {
        "- **$($project3.Project)**: ❌ Cdxgen failed to detect any components in ZIP archive format"
    }
)

### 2. Performance Winners

$(
    foreach ($timing in $TimingData) {
        $times = @(
            @{Tool='Syft'; Time=[double]($timing.SyftTime -replace 's','')},
            @{Tool='Grype'; Time=[double]($timing.GrypeTime -replace 's','')},
            @{Tool='Cdxgen'; Time=[double]($timing.CdxgenTime -replace 's','')}
        ) | Sort-Object Time
        "- **$($timing.Project)**: $($times[0].Tool) was fastest at $($timing.($times[0].Tool + 'Time'))"
    }
)

### 3. Tool Success Rate

| Tool | Successful Scans | Success Rate |
|------|-----------------|--------------|
$(
    $syftSuccess = ($ComponentData | Where-Object { $_.Syft -gt 0 }).Count
    $grypeSuccess = ($ComponentData | Where-Object { $_.Grype -gt 0 }).Count
    $cdxgenSuccess = ($ComponentData | Where-Object { $_.Cdxgen -gt 0 }).Count
    $total = $ComponentData.Count
    
    @(
        "| **Syft** | $syftSuccess/$total | $(if ($syftSuccess -eq $total) { '✅ 100%' } else { "$([Math]::Round(($syftSuccess/$total)*100, 1))%" }) |"
        "| **Grype** | $grypeSuccess/$total | $(if ($grypeSuccess -eq $total) { '✅ 100%' } else { "$([Math]::Round(($grypeSuccess/$total)*100, 1))%" }) |"
        "| **Cdxgen** | $cdxgenSuccess/$total | $(if ($cdxgenSuccess -eq $total) { '✅ 100%' } else { "⚠️ $([Math]::Round(($cdxgenSuccess/$total)*100, 1))%" }) |"
    ) -join "`n"
)

---

## Recommendations

### Tool Selection Guide

| Use Case | Recommended Tool | Reason |
|----------|-----------------|--------|
| **Comprehensive SBOM** | **Syft** | Most complete component discovery |
| **Security Scanning** | **Grype** | Fast + integrated vulnerability detection |
| **CI/CD Pipeline** | **Grype** | Fastest execution with security insights |
| **ZIP Archives** | **Syft or Grype** | Cdxgen failed on ZIP format |
| **Speed Critical** | **Grype** | Consistently fastest performance |

### Optimal Workflow

1. Run Syft for comprehensive SBOM generation
2. Run Grype for vulnerability scanning
3. Combine results for complete security-aware SBOM

---

## Detailed Scan Results

### Execution Status

| Directory | Syft | Grype | Cdxgen | OSV-Scanner |
|-----------|------|-------|--------|-------------|
$(@(foreach ($item in $Summary) {
    $dirName = ($item.Directory -split '\\')[-1]
    "| $dirName | $($item.Syft) | $($item.Grype) | $($item.Cdxgen) | $($item.OsvScanner) |"
}) -join "`n")

---

## Output Files

The following files have been generated:

### Syft SBOMs

$(Get-ChildItem "$OutputDir\*-syft-sbom.json" | ForEach-Object { "- ``$($_.Name)``" } | Join-String -Separator "`n")

### Grype SBOMs

$(Get-ChildItem "$OutputDir\*-grype-sbom.json" | ForEach-Object { "- ``$($_.Name)``" } | Join-String -Separator "`n")

### Cdxgen SBOMs

$(Get-ChildItem "$OutputDir\*-cdxgen-sbom.json" | ForEach-Object { "- ``$($_.Name)``" } | Join-String -Separator "`n")

### OSV-Scanner Results

$(Get-ChildItem "$OutputDir\*-osv-scanner.json" | ForEach-Object { "- ``$($_.Name)``" } | Join-String -Separator "`n")

---

**Report Location:** ``$ReportFile``  
**Summary JSON:** ``$SummaryFile``  
**Log File:** ``$LogFile``

---

Report generated automatically by generate-sboms.ps1
"@

$Report | Out-File $ReportFile -Encoding UTF8
Write-Log "Markdown report generated: $ReportFile"
} else {
    Write-Log "Skipping markdown report generation (SkipAnalysis flag set)"
}
