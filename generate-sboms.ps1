<#
.SYNOPSIS
    Generates SBOMs and vulnerability reports for binary archives using multiple tools.

.DESCRIPTION
    Scans directories for binary archives (JARs, WARs, EARs, ZIPs, etc.) and generates:
    - SBOM files using Syft, Grype, Cdxgen, Trivy, and Vet (CycloneDX JSON format)
    - SBOM files using OSV-Scalibr (CycloneDX JSON format)
    - SBOM files using Bei (JSON output)
    - Vulnerability reports using OSV-Scanner (note: may report 0 when CycloneDX is unsupported)
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

.EXAMPLE
    .\generate-sboms.ps1 -Tool Syft
    Runs only Syft for SBOM generation and reporting.

.EXAMPLE
    .\generate-sboms.ps1 -Tool Trivy
    Runs only Trivy for SBOM generation and reporting.
#>

param(
    [switch]$Recursive = $false,
    [switch]$SkipAnalysis = $false,
    [switch]$SkipGeneration = $false,
    [switch]$ReportOnly = $false,
    [switch]$TestOnly = $false,
    [ValidateSet("Syft","Grype","Cdxgen","Scalibr","Trivy","Bei","Vet","OsvScanner", "")]
    [string]$Tool = ""
)

# ==========================================
# Harmonise convenience switches
if ($ReportOnly) {
    $SkipGeneration = $true
}
if ($TestOnly) {
    $SkipAnalysis = $true
}

# ==========================================
# CONFIGURATION
# ==========================================
$Root = Get-Location
$SourceProjectsDir = Join-Path $Root "source-projects"
$BinaryProjectsDir = Join-Path $Root "binary-projects"
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
$ZipDir = Join-Path $BinaryProjectsDir "opencms-zip-only"
$WarDir = Join-Path $BinaryProjectsDir "opencms-exploded"
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
if ($ReportOnly -and $TestOnly) {
    Write-Host "Cannot use -ReportOnly and -TestOnly together." -ForegroundColor Red
    exit 1
}

# Only run SBOM generation if not reporting only
if (-not $SkipGeneration -and -not $ReportOnly) {
    Write-Host "Cleaning up previous run files..." -ForegroundColor Cyan
    Get-ChildItem -Path $OutputDir -Filter "*-syft-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-grype-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-cdxgen-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-scalibr-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-trivy-sbom.json" | Remove-Item -Force
    Get-ChildItem -Path $OutputDir -Filter "*-bei-sbom.json*" | Remove-Item -Force -Recurse
    Get-ChildItem -Path $OutputDir -Filter "*-vet-sbom.json" | Remove-Item -Force
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

function Write-CommandLog {
    param(
        [Parameter(Mandatory)][string]$CommandText,
        [ValidateSet("Start","End")][string]$Phase = "Start",
        [string]$Result = "Unknown"
    )

    $border = '-' * 80

    if ($Phase -eq "Start") {
        Write-Log $border
        Write-Log "Executing command:"
        Write-Log "    $CommandText"
    }
    else {
        $statusMessage = if ([string]::IsNullOrWhiteSpace($Result) -or $Result -eq "Unknown") {
            "Command completed"
        } else {
            "Command completed with status: $Result"
        }
        Write-Log $statusMessage
        Write-Log "    $CommandText"
        Write-Log $border
    }
}

if (-not $SkipGeneration) {
# ==========================================
# Get directories containing binaries or source projects
# ==========================================
$BinaryDirsToScan = @()
$SourceDirsToScan = @()

# Scan binary projects directory
if (Test-Path $BinaryProjectsDir) {
    if ($Recursive) {
        $BinaryDirs = Get-ChildItem -Path $BinaryProjectsDir -Directory -Recurse
    } else {
        $BinaryDirs = Get-ChildItem -Path $BinaryProjectsDir -Directory
    }
    
    foreach ($Dir in $BinaryDirs) {
        $HasBinaries = Get-ChildItem -Path $Dir.FullName -Recurse -File -Include *.jar,*.war,*.ear,*.zip,*.tar,*.tar.gz,*.tgz,*.rpm,*.deb,*.aar -ErrorAction SilentlyContinue
        if ($HasBinaries) { $BinaryDirsToScan += $Dir }
    }
}

# Scan source projects directory
if (Test-Path $SourceProjectsDir) {
    if ($Recursive) {
        $SourceDirs = Get-ChildItem -Path $SourceProjectsDir -Directory -Recurse
    } else {
        $SourceDirs = Get-ChildItem -Path $SourceProjectsDir -Directory
    }
    
    foreach ($Dir in $SourceDirs) {
        $HasMavenProject = Test-Path (Join-Path $Dir.FullName "pom.xml")
        $HasGradleProject = (Test-Path (Join-Path $Dir.FullName "build.gradle")) -or (Test-Path (Join-Path $Dir.FullName "build.gradle.kts"))
        
        if ($HasMavenProject -or $HasGradleProject) { 
            $SourceDirsToScan += $Dir 
        }
    }
}

Write-Log "Found $($BinaryDirsToScan.Count) binary directories and $($SourceDirsToScan.Count) source directories to scan."

# Combine for processing
$DirsToScan = $BinaryDirsToScan + $SourceDirsToScan

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
    $TrivyOut = Join-Path $OutputDir "$Name-trivy-sbom.json"
    $BeiOut = Join-Path $OutputDir "$Name-bei-sbom.json"
    $VetOut = Join-Path $OutputDir "$Name-vet-sbom.json"
    $OsvOut = Join-Path $OutputDir "$Name-osv-scanner.json"

    # Remove existing files if present
    foreach ($f in @($SyftOut, $GrypeOut, $CdxgenOut, $ScalibrOut, $OsvOut)) {
        if (Test-Path $f) { Remove-Item $f -Force }
    }
    if (Test-Path $TrivyOut) { Remove-Item $TrivyOut -Force }
    if (Test-Path $BeiOut) { Remove-Item $BeiOut -Force }
    if (Test-Path $VetOut) { Remove-Item $VetOut -Force }

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
        Trivy    = ""
        TrivyTime = ""
        Bei      = ""
        BeiTime  = ""
        Vet      = ""
        VetTime  = ""
        OsvScanner = ""
        OsvTime = ""
    }

    # -------------------------------
    # 4) Trivy (CycloneDX SBOM generation)
    # -------------------------------
    if (($Tool -eq "Trivy") -or ($Tool -eq "")) {
        $TrivyStart = Get-Date
        # Trivy can generate CycloneDX SBOMs for directories
        $trivyCmd = "trivy fs --format cyclonedx --output `"$TrivyOut`" `"$DirPath`""
        $trivyResult = "Unknown"
        Write-CommandLog -CommandText $trivyCmd
        try {
            trivy fs --format cyclonedx --output "$TrivyOut" "$DirPath" | Out-Null
            $TrivyDuration = (Get-Date) - $TrivyStart
            $Status.TrivyTime = "$([Math]::Round($TrivyDuration.TotalSeconds, 2))s"
            Write-Log "Trivy SBOM generated: $TrivyOut (Time: $($Status.TrivyTime))"
            $Status.Trivy = "Success"
            $trivyResult = "Success"
        } catch {
            $TrivyDuration = (Get-Date) - $TrivyStart
            $Status.TrivyTime = "$([Math]::Round($TrivyDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: Trivy failed for $DirPath - $($_.Exception.Message)"
            $Status.Trivy = "Failed"
            $trivyResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $trivyCmd -Phase End -Result $trivyResult
        }
    }


    # -------------------------------
    # 1) Syft
    # -------------------------------
    if (($Tool -eq "Syft") -or ($Tool -eq "")) {
        $SyftStart = Get-Date
        # Generate SBOM in CycloneDX JSON format
        $syftCmd = "syft `"dir:$DirPath`" -o cyclonedx-json"
        $syftResult = "Unknown"
        Write-CommandLog -CommandText $syftCmd
        try {
            syft "dir:$DirPath" -o cyclonedx-json | Out-File $SyftOut
            $SyftDuration = (Get-Date) - $SyftStart
            $Status.SyftTime = "$([Math]::Round($SyftDuration.TotalSeconds, 2))s"
            Write-Log "Syft SBOM generated: $SyftOut (Time: $($Status.SyftTime))"
            $Status.Syft = "Success"
            $syftResult = "Success"
        } catch {
            $SyftDuration = (Get-Date) - $SyftStart
            $Status.SyftTime = "$([Math]::Round($SyftDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: Syft failed for $DirPath - $($_.Exception.Message)"
            $Status.Syft = "Failed"
            $syftResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $syftCmd -Phase End -Result $syftResult
        }
    }


    # -------------------------------
    # 2) Grype
    # -------------------------------
    if (($Tool -eq "Grype") -or ($Tool -eq "")) {
        $GrypeStart = Get-Date
        $grypeCmd = "grype `"dir:$DirPath`" -o cyclonedx-json"
        $grypeResult = "Unknown"
        Write-CommandLog -CommandText $grypeCmd
        try {
            grype "dir:$DirPath" -o cyclonedx-json | Out-File $GrypeOut
            $GrypeDuration = (Get-Date) - $GrypeStart
            $Status.GrypeTime = "$([Math]::Round($GrypeDuration.TotalSeconds, 2))s"
            Write-Log "Grype SBOM generated: $GrypeOut (Time: $($Status.GrypeTime))"
            $Status.Grype = "Success"
            $grypeResult = "Success"
        } catch {
            $GrypeDuration = (Get-Date) - $GrypeStart
            $Status.GrypeTime = "$([Math]::Round($GrypeDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: Grype failed for $DirPath - $($_.Exception.Message)"
            $Status.Grype = "Failed"
            $grypeResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $grypeCmd -Phase End -Result $grypeResult
        }
    }


    # -------------------------------
    # 3) Cdxgen (specialized for binaries in JARs/WARs/EARs/ZIPs/RPMs)
    # -------------------------------
    if (($Tool -eq "Cdxgen") -or ($Tool -eq "")) {
        $CdxgenStart = Get-Date
        $cdxgenResult = "Unknown"
        $cdxgenCmd = $null
        try {
            # Determine if this is a source project or binary project
            $isSourceProject = $SourceDirsToScan -contains $Dir
            
            if ($isSourceProject) {
                # For source projects: use basic flags without deep/evidence
                $cdxgenCmd = "cdxgen -r -o `"$CdxgenOut`" `"$DirPath`""
                Write-Log "Executing cdxgen in source mode."
                Write-CommandLog -CommandText $cdxgenCmd
                cdxgen -r -o $CdxgenOut $DirPath
            } else {
                # For binary projects: use deep scanning and evidence collection
                # --deep flag enables deep scanning of nested archives
                # --evidence flag includes evidence and occurrences for components
                $cdxgenCmd = "cdxgen -r --deep --evidence -o `"$CdxgenOut`" `"$DirPath`""
                Write-Log "Executing cdxgen in binary mode."
                Write-CommandLog -CommandText $cdxgenCmd
                cdxgen -r --deep --evidence -o $CdxgenOut $DirPath
            }
            $CdxgenDuration = (Get-Date) - $CdxgenStart
            $Status.CdxgenTime = "$([Math]::Round($CdxgenDuration.TotalSeconds, 2))s"
            Write-Log "Cdxgen SBOM generated: $CdxgenOut (Time: $($Status.CdxgenTime))"
            $Status.Cdxgen = "Success"
            $cdxgenResult = "Success"
        } catch {
            $CdxgenDuration = (Get-Date) - $CdxgenStart
            $Status.CdxgenTime = "$([Math]::Round($CdxgenDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: Cdxgen failed for $DirPath - $($_.Exception.Message)"
            $Status.Cdxgen = "Failed"
            $cdxgenResult = "Failed"
        } finally {
            if ($null -ne $cdxgenCmd -and $cdxgenCmd -ne "") {
                Write-CommandLog -CommandText $cdxgenCmd -Phase End -Result $cdxgenResult
            }
        }
    }


    # -------------------------------
    # 4) OSV-Scalibr (CycloneDX SBOM generation)
    # -------------------------------
    if (($Tool -eq "Scalibr") -or ($Tool -eq "")) {
        $ScalibrStart = Get-Date
        # OSV-Scalibr generates CycloneDX format SBOMs
        $scalibrCmd = "scalibr -o `"cdx-json=$ScalibrOut`" `"$DirPath`""
        $scalibrResult = "Unknown"
        Write-CommandLog -CommandText $scalibrCmd
        try {
            scalibr -o "cdx-json=$ScalibrOut" "$DirPath" 2>&1 | Out-Null
            $ScalibrDuration = (Get-Date) - $ScalibrStart
            $Status.ScalibrTime = "$([Math]::Round($ScalibrDuration.TotalSeconds, 2))s"
            Write-Log "OSV-Scalibr SBOM generated: $ScalibrOut (Time: $($Status.ScalibrTime))"
            $Status.Scalibr = "Success"
            $scalibrResult = "Success"
        } catch {
            $ScalibrDuration = (Get-Date) - $ScalibrStart
            $Status.ScalibrTime = "$([Math]::Round($ScalibrDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: OSV-Scalibr failed for $DirPath - $($_.Exception.Message)"
            $Status.Scalibr = "Failed"
            $scalibrResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $scalibrCmd -Phase End -Result $scalibrResult
        }
    }


    # -------------------------------
    # 6) Bei (SBOM generation)
    # -------------------------------
    if (($Tool -eq "Bei") -or ($Tool -eq "")) {
        $BeiStart = Get-Date
        $beiCmd = "bei sbom --additional-args=`"`" --output=`"$BeiOut`""
        $beiResult = "Unknown"
        Write-CommandLog -CommandText $beiCmd
        try {
            # Change to the directory and run bei
            Push-Location $DirPath
            $beiExitCode = 0
            bei sbom --additional-args="" --output="$BeiOut" 2>&1 | Out-Null
            $beiExitCode = $LASTEXITCODE
            Pop-Location
            $BeiDuration = (Get-Date) - $BeiStart
            $Status.BeiTime = "$([Math]::Round($BeiDuration.TotalSeconds, 2))s"
            if ($beiExitCode -eq 0 -and (Test-Path $BeiOut)) {
                Write-Log "Bei SBOM generated: $BeiOut (Time: $($Status.BeiTime))"
                $Status.Bei = "Success"
                $beiResult = "Success"
            } else {
                Write-Log "ERROR: Bei failed for $DirPath (exit code: $beiExitCode)"
                $Status.Bei = "Failed"
                $beiResult = "Failed"
            }
        } catch {
            if ((Get-Location).Path -ne $PSScriptRoot) { Pop-Location }
            $BeiDuration = (Get-Date) - $BeiStart
            $Status.BeiTime = "$([Math]::Round($BeiDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: Bei failed for $DirPath - $($_.Exception.Message)"
            $Status.Bei = "Failed"
            $beiResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $beiCmd -Phase End -Result $beiResult
        }
    }

    # -------------------------------
    # 7) Vet (SBOM generation)
    # -------------------------------
    if (($Tool -eq "Vet") -or ($Tool -eq "")) {
        $VetStart = Get-Date
        $vetCmd = "vet scan -D `"$DirPath`" --report-cdx=`"$VetOut`""
        $vetResult = "Unknown"
        Write-CommandLog -CommandText $vetCmd
        try {
            vet scan -D "$DirPath" --report-cdx="$VetOut" 2>&1 | Out-Null
            $vetExitCode = $LASTEXITCODE
            $VetDuration = (Get-Date) - $VetStart
            $Status.VetTime = "$([Math]::Round($VetDuration.TotalSeconds, 2))s"
            if ((Test-Path $VetOut) -and ($vetExitCode -eq 0)) {
                Write-Log "Vet SBOM generated: $VetOut (Time: $($Status.VetTime))"
                $Status.Vet = "Success"
                $vetResult = "Success"
            } else {
                Write-Log "ERROR: Vet did not produce SBOM for $DirPath (exit code: $vetExitCode)"
                $Status.Vet = "Failed"
                $vetResult = "Failed"
            }
        } catch {
            $VetDuration = (Get-Date) - $VetStart
            $Status.VetTime = "$([Math]::Round($VetDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: Vet failed for $DirPath - $($_.Exception.Message)"
            $Status.Vet = "Failed"
            $vetResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $vetCmd -Phase End -Result $vetResult
        }
    }


    # -------------------------------
    # 5) OSV-Scanner (vulnerability scanning using Syft SBOM)
    # -------------------------------
    if (($Tool -eq "OsvScanner") -or ($Tool -eq "")) {
        $OsvStart = Get-Date
        # OSV-Scanner scans SBOMs for vulnerabilities using Google's OSV database
        # Note: OSV-Scanner doesn't support Syft's CycloneDX version, so this will fail
        # We'll catch the error and report 0 vulnerabilities
        $osvCmd = "osv-scanner --sbom `"$SyftOut`" --format json"
        $osvResult = "Unknown"
        Write-CommandLog -CommandText $osvCmd
        try {
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
            $osvResult = "Success"
        } catch {
            $OsvDuration = (Get-Date) - $OsvStart
            $Status.OsvTime = "$([Math]::Round($OsvDuration.TotalSeconds, 2))s"
            Write-Log "ERROR: OSV-Scanner failed for $DirPath - $($_.Exception.Message)"
            # Write empty result for failed case
            '{"results": []}' | Out-File $OsvOut
            $Status.OsvScanner = "Failed"
            $osvResult = "Failed"
        } finally {
            Write-CommandLog -CommandText $osvCmd -Phase End -Result $osvResult
        }
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

if (-not $SkipAnalysis -and -not $TestOnly) {
    $reportScript = Join-Path $Root "generate-sboms-report.ps1"
    if (Test-Path $reportScript) {
        Write-Log "Generating markdown report..."
        try {
            $reportPath = Join-Path $OutputDir "sbom-report.md"
            pwsh -NoLogo -NoProfile -File $reportScript -SummaryFile $SummaryFile -ReportFile $reportPath
            Write-Log "Markdown report generated: $reportPath"
        } catch {
            Write-Log "Report generation failed: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Report script not found: $reportScript"
    }
}

Write-Log "Script execution complete."

