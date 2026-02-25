# SBOM Tool Comparison Report Generator
# Usage: .\generate-sboms-report.ps1 -SummaryFile <summary.json> -ReportFile <output.md>
param(
    [string]$SummaryFile = "generate-sboms/sbom-summary.json",
    [string]$ReportFile = "generate-sboms/sbom-report.md"
)

if (!(Test-Path $SummaryFile)) {
    Write-Error "Summary file not found: $SummaryFile"
    exit 1
}

try {
    $summaryContent = Get-Content -Path $SummaryFile -Raw | ConvertFrom-Json
} catch {
    Write-Error "Failed to parse summary JSON: $($_.Exception.Message)"
    exit 1
}

if ($null -eq $summaryContent) {
    Write-Error "Summary file is empty: $SummaryFile"
    exit 1
}

if ($summaryContent -isnot [System.Collections.IEnumerable]) {
    $Summary = @($summaryContent)
} else {
    $Summary = @($summaryContent)
}

if ($Summary.Count -eq 0) {
    Write-Error "Summary file does not contain any scan results."
    exit 1
}

$outputDir = Split-Path -Path $SummaryFile -Parent
if (-not $outputDir) { $outputDir = "." }

$knownTools = @('Syft','Grype','Cdxgen','Scalibr','Trivy','Bei','Vet')
$availableProps = $Summary[0].PSObject.Properties.Name
$toolHeaders = @()
foreach ($tool in $knownTools) {
    if ($availableProps -contains $tool) {
        $toolHeaders += $tool
    }
}
if ($toolHeaders.Count -eq 0) {
    Write-Error "No tool results found in summary file."
    exit 1
}

function Get-ComponentCount {
    param([string]$Path)
    if (!(Test-Path $Path)) { return 0 }
    try {
        $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
    } catch {
        return 0
    }
    if ($null -eq $json) { return 0 }
    if ($json.components) { return ($json.components).Count }
    if ($json.bom -and $json.bom.components) { return ($json.bom.components).Count }
    if ($json.packages) { return ($json.packages).Count }
    if ($json.Packages) { return ($json.Packages).Count }
    return 0
}

function Get-OsvVulnerabilityCount {
    param([string]$Path)
    if (!(Test-Path $Path)) { return 0 }
    try {
        $json = Get-Content -Path $Path -Raw | ConvertFrom-Json
    } catch {
        return 0
    }
    if ($null -eq $json) { return 0 }
    $count = 0
    if ($json.results) {
        foreach ($result in $json.results) {
            if ($result.vulns) { $count += $result.vulns.Count }
            elseif ($result.vulnerabilities) { $count += $result.vulnerabilities.Count }
        }
    } elseif ($json.vulns) {
        $count += $json.vulns.Count
    }
    return $count
}

function Normalize-Status {
    param([string]$Status)
    if ([string]::IsNullOrWhiteSpace($Status)) { return "Not Run" }
    return $Status
}

function Format-StatusCell {
    param([string]$Status)
    $normalized = Normalize-Status $Status
    switch ($normalized.ToLower()) {
        'success' { return '✅ Success' }
        'failed' { return '❌ Failed' }
        default { return $normalized }
    }
}

function Parse-Seconds {
    param([string]$Duration)
    if ([string]::IsNullOrWhiteSpace($Duration)) { return 0.0 }
    $trimmed = $Duration.Trim()
    if ($trimmed.EndsWith('s')) { $trimmed = $trimmed.Substring(0, $trimmed.Length - 1) }
    [double]$value = 0
    [double]::TryParse($trimmed, [ref]$value) | Out-Null
    return [Math]::Round($value, 4)
}

$reportRecords = @()
foreach ($entry in $Summary) {
    $projectName = Split-Path -Path $entry.Directory -Leaf
    $record = [ordered]@{
        Project = $projectName
        Directory = $entry.Directory
        OsvScanner = Normalize-Status $entry.OsvScanner
        OsvTime = $entry.OsvTime
    }
    foreach ($tool in $toolHeaders) {
        $statusField = Normalize-Status $entry.$tool
        $timeField = $entry."${tool}Time"
        $sbomPath = Join-Path $outputDir ("{0}-{1}-sbom.json" -f $projectName, $tool.ToLower())
        $componentCount = Get-ComponentCount -Path $sbomPath
        $record[$tool] = $componentCount
        $record["${tool}Status"] = $statusField
        $record["${tool}Time"] = $timeField
    }
    $osvPath = Join-Path $outputDir ("{0}-osv-scanner.json" -f $projectName)
    $record['OsvVulns'] = Get-OsvVulnerabilityCount -Path $osvPath
    $reportRecords += [PSCustomObject]$record
}

# Separate records into binary and source projects
$binaryRecords = $reportRecords | Where-Object { $_.Directory -like '*binary-projects*' }
$sourceRecords = $reportRecords | Where-Object { $_.Directory -like '*source-projects*' }

$projectNames = $reportRecords | ForEach-Object { $_.Project }
$reportType = 'Mixed'
if (($reportRecords.Directory | Where-Object { $_ -like '*binary-projects*' }).Count -eq $reportRecords.Count) {
    $reportType = 'Binary'
} elseif (($reportRecords.Directory | Where-Object { $_ -like '*source-projects*' }).Count -eq $reportRecords.Count) {
    $reportType = 'Source'
}
$reportTitle = if ($reportRecords.Count -gt 1) { 'Multi-project comparison' } else { 'Single-project comparison' }

$headerLine = '| Directory'
foreach ($tool in $toolHeaders) { $headerLine += " | $tool" }
$headerLine += ' | OSV-Scanner |'

$dividerLine = '|-----------'
foreach ($tool in $toolHeaders) { $dividerLine += ' |-------------' }
$dividerLine += ' |-------------|'

$quickRows = @()
foreach ($record in $reportRecords) {
    $row = "| $($record.Project)"
    foreach ($tool in $toolHeaders) {
        $row += " | $(Format-StatusCell $record."${tool}Status")"
    }
    $row += " | $(Format-StatusCell $record.OsvScanner) |"
    $quickRows += $row
}
$quickResults = $quickRows -join "`n"

$toolHeaderLine = '| Tool'
foreach ($name in $projectNames) { $toolHeaderLine += " | $name" }
$toolHeaderLine += ' | Average |'

$toolDividerLine = '|------'
foreach ($name in $projectNames) { $toolDividerLine += ' |------' }
$toolDividerLine += ' |---------|'

$componentTable = ""
foreach ($tool in $toolHeaders) {
    $counts = @()
    foreach ($record in $reportRecords) { $counts += $record.$tool }
    $average = if ($counts.Count -gt 0) { [Math]::Round(($counts | Measure-Object -Average).Average, 2) } else { 0 }
    $componentTable += "| **$tool** | $($counts -join ' | ') | $average |`n"
}

function Format-TimeCell {
    param([string]$Time)
    if ([string]::IsNullOrWhiteSpace($Time)) { return '—' }
    return $Time
}

$perfRows = ""
foreach ($record in $reportRecords) {
    $timeCells = @()
    $totalSeconds = 0.0
    foreach ($tool in $toolHeaders) {
        $timeValue = $record."${tool}Time"
        $timeCells += (Format-TimeCell $timeValue)
        $totalSeconds += Parse-Seconds $timeValue
    }
    $osvTime = Format-TimeCell $record.OsvTime
    $totalSeconds += Parse-Seconds $record.OsvTime
    $perfRows += "| **$($record.Project)** | $($timeCells -join ' | ') | $osvTime | $([Math]::Round($totalSeconds, 2))s |`n"
}

$avgPerfRows = ""
foreach ($tool in $toolHeaders) {
    $seconds = @()
    foreach ($record in $reportRecords) {
        $seconds += Parse-Seconds $record."${tool}Time"
    }
    $positiveSeconds = $seconds | Where-Object { $_ -gt 0 }
    $avgValue = 0.0
    if ($positiveSeconds.Count -gt 0) {
        $avgValue = [Math]::Round(($positiveSeconds | Measure-Object -Average).Average, 2)
    }
    $rating = if ($avgValue -eq 0) { '—' } elseif ($avgValue -lt 10) { '⚡⚡⚡⚡⚡ Excellent' } elseif ($avgValue -lt 20) { '⚡⚡⚡⚡ Good' } else { '⚡⚡⚡ Fair' }
    $avgPerfRows += "| **$tool** | $avgValue s | $rating |`n"
}

$osvSeconds = @($reportRecords | ForEach-Object { Parse-Seconds $_.OsvTime } | Where-Object { $_ -gt 0 })
if ($osvSeconds.Count -gt 0) {
    $osvAvg = [Math]::Round(($osvSeconds | Measure-Object -Average).Average, 2)
    $osvRating = if ($osvAvg -lt 10) { '⚡⚡⚡⚡⚡ Excellent' } elseif ($osvAvg -lt 20) { '⚡⚡⚡⚡ Good' } else { '⚡⚡⚡ Fair' }
    $avgPerfRows += "| **OSV-Scanner** | $osvAvg s | $osvRating |`n"
}

$successRows = ""
foreach ($tool in $toolHeaders) {
    $successCount = ($reportRecords | Where-Object { $_."${tool}Status" -eq 'Success' }).Count
    $total = $reportRecords.Count
    $rate = if ($total -eq 0) { '0%' } elseif ($successCount -eq $total) { '✅ 100%' } else { "{0:P1}" -f ($successCount / $total) }
    $successRows += "| **$tool** | $successCount/$total | $rate |`n"
}

$detailedSections = ""
foreach ($record in $reportRecords) {
    $detailedSections += "### $($record.Project)`n`n"
    $detailedSections += "| Tool | Components Detected | Time | Status |`n"
    $detailedSections += "|------|---------------------|------|--------|`n"
    $maxComponents = 0
    $fastestTime = $null
    foreach ($tool in $toolHeaders) {
        $components = $record.$tool
        if ($components -gt $maxComponents) { $maxComponents = $components }
        $rawSec = Parse-Seconds $record."${tool}Time"
        if ($null -eq $fastestTime -or ($rawSec -gt 0 -and $rawSec -lt $fastestTime)) { $fastestTime = $rawSec }
    }
    foreach ($tool in $toolHeaders) {
        $components = $record.$tool
        $timeVal = Format-TimeCell $record."${tool}Time"
        $status = Format-StatusCell $record."${tool}Status"
        $trophy = if ($components -eq $maxComponents -and $components -gt 0) { ' 🏆' } else { '' }
        $rawSec = Parse-Seconds $record."${tool}Time"
        $bolt = if ($fastestTime -and $rawSec -gt 0 -and [Math]::Abs($rawSec - $fastestTime) -lt 0.0001) { ' ⚡' } else { '' }
        $detailedSections += "| **$tool** | $components$trophy | $timeVal$bolt | $status |`n"
    }
    $detailedSections += "| **OSV-Scanner** | $($record.OsvVulns) vulnerabilities | $(Format-TimeCell $record.OsvTime) | $(Format-StatusCell $record.OsvScanner) |`n`n"
}

$keyFindings = ""
$firstRecord = $reportRecords | Select-Object -First 1
if ($firstRecord) {
    $counts = @()
    foreach ($tool in $toolHeaders) { $counts += "$tool ($($firstRecord.$tool))" }
    if (($toolHeaders.Count -gt 1) -and (($toolHeaders | ForEach-Object { $firstRecord.$_ }) | Select-Object -Unique).Count -eq 1) {
        $keyFindings += "✅ **$($firstRecord.Project):** All tools detected $($firstRecord.$($toolHeaders[0])) components.`n"
    } else {
        $keyFindings += "⚠️ **$($firstRecord.Project):** Component counts vary – $($counts -join ', ').`n"
    }
}

$perfWinners = ""
foreach ($record in $reportRecords) {
    $timings = @()
    foreach ($tool in $toolHeaders) {
        $seconds = Parse-Seconds $record."${tool}Time"
        if ($seconds -gt 0) { $timings += [PSCustomObject]@{ Tool = $tool; Seconds = $seconds; Display = $record."${tool}Time" } }
    }
    if ($timings.Count -gt 0) {
        $fastest = $timings | Sort-Object Seconds | Select-Object -First 1
        $perfWinners += "- **$($record.Project):** $($fastest.Tool) fastest at $($fastest.Display)`n"
    }
}

$execHeaderLine = '| Directory'
foreach ($tool in $toolHeaders) { $execHeaderLine += " | $tool" }
$execHeaderLine += ' | OSV-Scanner |'

$execDividerLine = '|-----------'
foreach ($tool in $toolHeaders) { $execDividerLine += ' |------' }
$execDividerLine += ' |-------------|'

$execRows = ""
foreach ($record in $reportRecords) {
    $statuses = @()
    foreach ($tool in $toolHeaders) { $statuses += Format-StatusCell $record."${tool}Status" }
    $execRows += "| $($record.Project) | $($statuses -join ' | ') | $(Format-StatusCell $record.OsvScanner) |`n"
}

$outputFilesSection = ""
foreach ($tool in $toolHeaders) {
    $pattern = "*-{0}-sbom.json" -f $tool.ToLower()
    $files = Get-ChildItem -Path $outputDir -Filter $pattern -ErrorAction SilentlyContinue
    if ($files) {
        $outputFilesSection += "### $tool SBOMs`n"
        foreach ($file in $files) { $outputFilesSection += "- ``$($file.Name)```n" }
        $outputFilesSection += "`n"
    }
}
$osvFiles = Get-ChildItem -Path $outputDir -Filter "*-osv-scanner.json" -ErrorAction SilentlyContinue
if ($osvFiles) {
    $outputFilesSection += "### OSV-Scanner Results`n"
    foreach ($file in $osvFiles) { $outputFilesSection += "- ``$($file.Name)```n" }
    $outputFilesSection += "`n"
}

# Build simplified table with tools as rows and directories as columns
# Create header with category labels
$tableHeader = ""
if ($binaryRecords.Count -gt 0 -and $sourceRecords.Count -gt 0) {
    # Show both categories
    $tableHeader = "### Binary Projects`n`n"
    $tableHeader += "| Tool"
    foreach ($record in $binaryRecords) {
        $tableHeader += " | $($record.Project)"
    }
    $tableHeader += " |`n"
    
    $tableDivider = "|------"
    foreach ($record in $binaryRecords) {
        $tableDivider += "|------"
    }
    $tableDivider += "|`n"
    
    $tableHeader += $tableDivider
    
    # Binary rows
    $binaryRows = ""
    foreach ($tool in $toolHeaders) {
        $binaryRows += "| **$tool**"
        foreach ($record in $binaryRecords) {
            $components = $record.$tool
            $timeVal = $record."${tool}Time"
            $maxForDir = 0
            foreach ($t in $toolHeaders) {
                if ($record.$t -gt $maxForDir) { $maxForDir = $record.$t }
            }
            $champion = if ($components -eq $maxForDir -and $components -gt 0) { " 🏆" } else { "" }
            $binaryRows += " | $components ($timeVal)$champion"
        }
        $binaryRows += " |`n"
    }
    
    # Source projects section
    $sourceHeader = "`n### Source Projects`n`n"
    $sourceHeader += "| Tool"
    foreach ($record in $sourceRecords) {
        $sourceHeader += " | $($record.Project)"
    }
    $sourceHeader += " |`n"
    
    $sourceDivider = "|------"
    foreach ($record in $sourceRecords) {
        $sourceDivider += "|------"
    }
    $sourceDivider += "|`n"
    
    $sourceHeader += $sourceDivider
    
    # Source rows
    $sourceRows = ""
    foreach ($tool in $toolHeaders) {
        $sourceRows += "| **$tool**"
        foreach ($record in $sourceRecords) {
            $components = $record.$tool
            $timeVal = $record."${tool}Time"
            $maxForDir = 0
            foreach ($t in $toolHeaders) {
                if ($record.$t -gt $maxForDir) { $maxForDir = $record.$t }
            }
            $champion = if ($components -eq $maxForDir -and $components -gt 0) { " 🏆" } else { "" }
            $sourceRows += " | $components ($timeVal)$champion"
        }
        $sourceRows += " |`n"
    }
    
    $tableRows = $binaryRows + $sourceHeader + $sourceRows
    $tableDivider = ""
} else {
    # Single category
    $tableHeader = "| Tool"
    $allRecords = if ($binaryRecords.Count -gt 0) { $binaryRecords } else { $sourceRecords }
    foreach ($record in $allRecords) {
        $tableHeader += " | $($record.Project)"
    }
    $tableHeader += " |`n"
    
    $tableDivider = "|------"
    foreach ($record in $allRecords) {
        $tableDivider += "|------"
    }
    $tableDivider += "|`n"
    $tableDivider += "|`n"

    $tableRows = ""
    foreach ($tool in $toolHeaders) {
        $tableRows += "| **$tool**"
        foreach ($record in $allRecords) {
            $components = $record.$tool
            $timeVal = $record."${tool}Time"
            $maxForDir = 0
            foreach ($t in $toolHeaders) {
                if ($record.$t -gt $maxForDir) { $maxForDir = $record.$t }
            }
            $champion = if ($components -eq $maxForDir -and $components -gt 0) { " 🏆" } else { "" }
            $tableRows += " | $components ($timeVal)$champion"
        }
        $tableRows += " |`n"
    }
}

$Report = "# SBOM Tool Comparison Report`n`n"
$Report += "**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  `n"
$Report += "**Tools:** $($toolHeaders -join ', ')  `n`n"
$Report += "## Components Detected (Time)`n`n"
$Report += $tableHeader
$Report += $tableDivider
$Report += $tableRows
$Report += "`n---`n`n"
$Report += "**Report Location:** ``$ReportFile``  `n"
$Report += "**Summary JSON:** ``$SummaryFile``"

Set-Content -Path $ReportFile -Value $Report
Write-Host "Markdown report generated: $ReportFile"
