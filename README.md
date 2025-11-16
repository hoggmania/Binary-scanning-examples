# Binary Scanning Examples

SBOM generation and comparison tools for binary archives using multiple scanning tools.

## Overview

This project provides scripts to automatically generate Software Bill of Materials (SBOMs) and vulnerability reports for binary archives (JARs, WARs, EARs, ZIPs, RPMs, DEBs, etc.) using multiple industry-standard tools:

- **Syft** - SBOM generation (CycloneDX JSON format)
- **Grype** - Vulnerability scanning with SBOM generation (CycloneDX JSON format)
- **Cdxgen** - Deep binary scanning with evidence collection (CycloneDX JSON format)
- **OSV-Scalibr** - Comprehensive SBOM generation (SPDX JSON format)
- **OSV-Scanner** - Vulnerability scanning (Note: incompatible with CycloneDX v1.6, reports 0)

The scripts compare the results from each tool, measuring both accuracy (components detected) and performance (execution time), then generate a comprehensive Markdown analysis report.

## Features

- ✅ **Multi-tool comparison** - Compare Syft, Grype, Cdxgen, OSV-Scalibr, and OSV-Scanner results side-by-side
- ✅ **Automated downloads** - Scripts automatically download test files (OpenCMS) if needed
- ✅ **Performance metrics** - Track execution time for each tool on each project
- ✅ **Component counting** - Count and compare detected components across tools
- ✅ **Fastest tool detection** - Identify which tool performs best (excluding tools with 0 components)
- ✅ **Markdown reporting** - Generate detailed comparison reports in Markdown format
- ✅ **Flexible options** - Skip analysis, skip generation, or run full pipeline
- ✅ **Cross-platform** - PowerShell script for Windows, Bash script for Linux/Unix

## Prerequisites

### Required Tools

Install all five scanning tools:

```bash
# Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Cdxgen
npm install -g @cyclonedx/cdxgen

# OSV-Scalibr
go install github.com/google/osv-scalibr/binary/scalibr@latest

# OSV-Scanner
go install github.com/google/osv-scanner/cmd/osv-scanner@latest
```

### Additional Requirements

**For Bash script (Linux/Unix):**
- `jq` - JSON processor
- `bc` - Floating-point calculator
- `curl` - Download tool
- `unzip` - Archive extraction

```bash
# Ubuntu/Debian
sudo apt-get install jq bc curl unzip

# macOS
brew install jq bc
```

**For PowerShell script (Windows):**
- PowerShell 7+ recommended
- .NET Framework (for ZIP extraction)

## Test Projects

The repository includes three test projects:

1. **just-a-bag-of-jars/** - 18 JAR files for basic testing
2. **opencms-zip-only/** - OpenCMS 9.5.0 ZIP archive (downloaded by script)
3. **opencms-exploded/** - OpenCMS WAR file extracted from ZIP (downloaded/extracted by script)

The scripts will automatically download `opencms-9.5.0.zip` (142MB) from the [OpenCMS releases](https://github.com/alkacon/opencms-core/releases/download/build_9_5_0/opencms-9.5.0.zip) and extract the `opencms.war` file if they don't exist locally.

## Usage

### PowerShell (Windows)

```powershell
# Full scan - Generate SBOMs and analysis report
.\generate-sboms.ps1

# Generate only SBOMs (skip analysis report)
.\generate-sboms.ps1 -SkipAnalysis

# Regenerate report from existing SBOMs (skip generation)
.\generate-sboms.ps1 -SkipGeneration

# Recursive scan of subdirectories
.\generate-sboms.ps1 -Recursive
```

### Bash (Linux/Unix)

```bash
# Make script executable
chmod +x generate-sboms.sh

# Full scan - Generate SBOMs and analysis report
./generate-sboms.sh

# Generate only SBOMs (skip analysis report)
./generate-sboms.sh --skip-analysis

# Regenerate report from existing SBOMs (skip generation)
./generate-sboms.sh --skip-generation

# Recursive scan of subdirectories
./generate-sboms.sh --recursive

# Display help
./generate-sboms.sh --help
```

## Output

All generated files are saved to the `generate-sboms/` directory:

- `*-syft-sbom.json` - Syft SBOM files (CycloneDX)
- `*-grype-sbom.json` - Grype SBOM files (CycloneDX)
- `*-cdxgen-sbom.json` - Cdxgen SBOM files (CycloneDX)
- `*-osv-scanner.json` - OSV-Scanner vulnerability reports
- `sbom-summary.json` - Summary data for all projects and tools
- `SBOM-Analysis-Report.md` - Comprehensive comparison report

### Sample Report Sections

The analysis report includes:

1. **Quick Results** - Summary table with fastest tool per project
2. **Detailed Comparison** - Component counts and timing for each tool
3. **Individual Project Details** - Breakdown by project with component counts
4. **Overall Winners** - Most accurate and fastest tools across all projects

## Supported Archive Formats

The scripts scan for the following binary archive formats:

- `.jar` - Java Archives
- `.war` - Web Application Archives
- `.ear` - Enterprise Application Archives
- `.zip` - ZIP archives
- `.tar`, `.tar.gz`, `.tgz` - TAR archives
- `.rpm` - Red Hat Package Manager
- `.deb` - Debian packages
- `.aar` - Android Archives

## Notes

- **OSV-Scalibr**: Uses SPDX 2.3 JSON format for SBOMs, providing comprehensive package detection with built-in extractors for multiple ecosystems.
- **OSV-Scanner Incompatibility**: OSV-Scanner v1.6.2 doesn't support CycloneDX v1.6 format from Syft. The scripts detect this and gracefully report 0 vulnerabilities.
- **Fastest Tool Logic**: Tools that find 0 components are excluded from "fastest tool" calculations.
- **Large Files**: The OpenCMS files are automatically downloaded and excluded from git via `.gitignore` to avoid repository size issues.

## License

This project is provided as-is for educational and testing purposes. The test binaries (OpenCMS) are subject to their own licenses.

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.
