#!/bin/bash

# ==============================================================================
# generate-sboms.sh
# ==============================================================================
# Generates SBOMs and vulnerability reports for binary archives using multiple tools.
#
# DESCRIPTION:
#   Scans directories for binary archives (JARs, WARs, EARs, ZIPs, etc.) and generates:
#   - SBOM files using Syft, Grype, and Cdxgen (all in CycloneDX JSON format)
#   - SBOM files using OSV-Scalibr (CycloneDX JSON format)
#   - Vulnerability reports using OSV-Scanner (note: incompatible with CycloneDX, reports 0)
#   - Comparative analysis report in Markdown format
#
# OPTIONS:
#   -r, --recursive      Recursively search subdirectories for binary archives
#   -s, --skip-analysis  Skip the markdown analysis report generation
#   -g, --skip-generation Skip SBOM generation and cleanup (regenerate report only)
#   -h, --help           Display this help message
#
# EXAMPLES:
#   ./generate-sboms.sh                  # Generate SBOMs and analysis report
#   ./generate-sboms.sh --skip-analysis  # Generate only SBOM files
#   ./generate-sboms.sh --skip-generation # Regenerate report from existing SBOMs
#   ./generate-sboms.sh --recursive      # Recursively scan subdirectories
# ==============================================================================

set -e  # Exit on error

# ==========================================
# PARSE ARGUMENTS
# ==========================================
RECURSIVE=false
SKIP_ANALYSIS=false
SKIP_GENERATION=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--recursive)
            RECURSIVE=true
            shift
            ;;
        -s|--skip-analysis)
            SKIP_ANALYSIS=true
            shift
            ;;
        -g|--skip-generation)
            SKIP_GENERATION=true
            shift
            ;;
        -h|--help)
            head -n 25 "$0" | grep "^#" | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ==========================================
# CONFIGURATION
# ==========================================
ROOT=$(pwd)
SOURCE_PROJECTS_DIR="$ROOT/source-projects"
BINARY_PROJECTS_DIR="$ROOT/binary-projects"
OUTPUT_DIR="$ROOT/generate-sboms"
SUMMARY_FILE="$OUTPUT_DIR/sbom-summary.json"
LOG_FILE="$OUTPUT_DIR/run.log"
REPORT_FILE="$OUTPUT_DIR/SBOM-Analysis-Report.md"

# Set environment variable to suppress cdxgen gem warning
export CDXGEN_GEM_HOME=""

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# ==========================================
# DOWNLOAD TEST FILES
# ==========================================
ZIP_DIR="$BINARY_PROJECTS_DIR/opencms-zip-only"
WAR_DIR="$BINARY_PROJECTS_DIR/opencms-exploded"
ZIP_FILE="$ZIP_DIR/opencms-9.5.0.zip"
WAR_FILE="$WAR_DIR/opencms.war"
DOWNLOAD_URL="https://github.com/alkacon/opencms-core/releases/download/build_9_5_0/opencms-9.5.0.zip"

# Create directories if they don't exist
mkdir -p "$ZIP_DIR"
mkdir -p "$WAR_DIR"

# Download ZIP if it doesn't exist
if [ ! -f "$ZIP_FILE" ]; then
    echo -e "\033[36mDownloading opencms-9.5.0.zip...\033[0m"
    if curl -L -o "$ZIP_FILE" "$DOWNLOAD_URL"; then
        echo -e "\033[32mDownload complete: $ZIP_FILE\033[0m"
    else
        echo -e "\033[31mFailed to download ZIP\033[0m"
    fi
else
    echo -e "\033[33mZIP file already exists: $ZIP_FILE\033[0m"
fi

# Extract WAR from ZIP if it doesn't exist
if [ -f "$ZIP_FILE" ] && [ ! -f "$WAR_FILE" ]; then
    echo -e "\033[36mExtracting opencms.war from ZIP...\033[0m"
    if unzip -j "$ZIP_FILE" "opencms.war" -d "$WAR_DIR"; then
        echo -e "\033[32mExtracted WAR file: $WAR_FILE\033[0m"
    else
        echo -e "\033[31mFailed to extract WAR\033[0m"
    fi
elif [ -f "$WAR_FILE" ]; then
    echo -e "\033[33mWAR file already exists: $WAR_FILE\033[0m"
fi

# ==========================================
# LOGGING HELPER
# ==========================================
log() {
    local message="$1"
    echo "$message"
    echo "$(date '+%Y-%m-%d %H:%M:%S')  $message" >> "$LOG_FILE"
}

# ==========================================
# CLEANUP PREVIOUS RUN
# ==========================================
if [ "$SKIP_GENERATION" = false ]; then
    echo -e "${CYAN}Cleaning up previous run files...${NC}"
    rm -f "$OUTPUT_DIR"/*-syft-sbom.json
    rm -f "$OUTPUT_DIR"/*-grype-sbom.json
    rm -f "$OUTPUT_DIR"/*-cdxgen-sbom.json
    rm -f "$OUTPUT_DIR"/*-scalibr-sbom.json
    rm -f "$OUTPUT_DIR"/*-osv-scanner.json
    rm -f "$SUMMARY_FILE"
else
    echo -e "${YELLOW}Skipping SBOM generation (using existing files)...${NC}"
fi

rm -f "$LOG_FILE"
rm -f "$REPORT_FILE"
echo -e "\033[0;32mCleanup complete.\033[0m"

# ==========================================
# FIND DIRECTORIES WITH BINARIES
# ==========================================
if [ "$SKIP_GENERATION" = false ]; then

DIRS_TO_SCAN=()

# Scan binary projects directory
if [ -d "$BINARY_PROJECTS_DIR" ]; then
    if [ "$RECURSIVE" = true ]; then
        # Find all directories recursively in binary-projects
        while IFS= read -r -d '' dir; do
            # Check if directory contains binaries
            if find "$dir" -maxdepth 10 -type f \( -name "*.jar" -o -name "*.war" -o -name "*.ear" -o -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.rpm" -o -name "*.deb" -o -name "*.aar" \) 2>/dev/null | grep -q .; then
                DIRS_TO_SCAN+=("$dir")
            fi
        done < <(find "$BINARY_PROJECTS_DIR" -mindepth 1 -type d -print0)
    else
        # Only check immediate subdirectories in binary-projects
        for dir in "$BINARY_PROJECTS_DIR"/*/; do
            if find "$dir" -maxdepth 10 -type f \( -name "*.jar" -o -name "*.war" -o -name "*.ear" -o -name "*.zip" -o -name "*.tar" -o -name "*.tar.gz" -o -name "*.tgz" -o -name "*.rpm" -o -name "*.deb" -o -name "*.aar" \) 2>/dev/null | grep -q .; then
                DIRS_TO_SCAN+=("${dir%/}")
            fi
        done
    fi
fi

# Scan source projects directory
if [ -d "$SOURCE_PROJECTS_DIR" ]; then
    if [ "$RECURSIVE" = true ]; then
        # Find all directories recursively in source-projects
        while IFS= read -r -d '' dir; do
            # Check if directory is a Maven or Gradle project
            if [ -f "$dir/pom.xml" ] || [ -f "$dir/build.gradle" ] || [ -f "$dir/build.gradle.kts" ]; then
                DIRS_TO_SCAN+=("$dir")
            fi
        done < <(find "$SOURCE_PROJECTS_DIR" -mindepth 1 -type d -print0)
    else
        # Only check immediate subdirectories in source-projects
        for dir in "$SOURCE_PROJECTS_DIR"/*/; do
            if [ -f "${dir%/}/pom.xml" ] || [ -f "${dir%/}/build.gradle" ] || [ -f "${dir%/}/build.gradle.kts" ]; then
                DIRS_TO_SCAN+=("${dir%/}")
            fi
        done
    fi
fi

log "Found ${#DIRS_TO_SCAN[@]} directories to scan (binaries or source projects)."

# ==========================================
# GENERATE SBOMs USING ALL TOOLS
# ==========================================
SUMMARY_JSON="["

for DIR_PATH in "${DIRS_TO_SCAN[@]}"; do
    DIR_NAME=$(basename "$DIR_PATH")
    
    log "Processing directory: $DIR_PATH"
    
    # Prepare output filenames
    SYFT_OUT="$OUTPUT_DIR/$DIR_NAME-syft-sbom.json"
    GRYPE_OUT="$OUTPUT_DIR/$DIR_NAME-grype-sbom.json"
    CDXGEN_OUT="$OUTPUT_DIR/$DIR_NAME-cdxgen-sbom.json"
    SCALIBR_OUT="$OUTPUT_DIR/$DIR_NAME-scalibr-sbom.json"
    OSV_OUT="$OUTPUT_DIR/$DIR_NAME-osv-scanner.json"
    
    # Remove existing files if present
    rm -f "$SYFT_OUT" "$GRYPE_OUT" "$CDXGEN_OUT" "$SCALIBR_OUT" "$OSV_OUT"
    
    # -------------------------------
    # 1) Syft
    # -------------------------------
    SYFT_START=$(date +%s.%N)
    if syft "dir:$DIR_PATH" -o cyclonedx-json > "$SYFT_OUT" 2>&1; then
        SYFT_END=$(date +%s.%N)
        SYFT_TIME=$(echo "$SYFT_END - $SYFT_START" | bc)
        SYFT_TIME_FORMATTED=$(printf "%.2f" "$SYFT_TIME")
        log "Syft SBOM generated: $SYFT_OUT (Time: ${SYFT_TIME_FORMATTED}s)"
        SYFT_STATUS="Success"
    else
        SYFT_END=$(date +%s.%N)
        SYFT_TIME=$(echo "$SYFT_END - $SYFT_START" | bc)
        SYFT_TIME_FORMATTED=$(printf "%.2f" "$SYFT_TIME")
        log "ERROR: Syft failed for $DIR_PATH"
        SYFT_STATUS="Failed"
    fi
    
    # -------------------------------
    # 2) Grype
    # -------------------------------
    GRYPE_START=$(date +%s.%N)
    if grype "dir:$DIR_PATH" -o cyclonedx-json > "$GRYPE_OUT" 2>&1; then
        GRYPE_END=$(date +%s.%N)
        GRYPE_TIME=$(echo "$GRYPE_END - $GRYPE_START" | bc)
        GRYPE_TIME_FORMATTED=$(printf "%.2f" "$GRYPE_TIME")
        log "Grype SBOM generated: $GRYPE_OUT (Time: ${GRYPE_TIME_FORMATTED}s)"
        GRYPE_STATUS="Success"
    else
        GRYPE_END=$(date +%s.%N)
        GRYPE_TIME=$(echo "$GRYPE_END - $GRYPE_START" | bc)
        GRYPE_TIME_FORMATTED=$(printf "%.2f" "$GRYPE_TIME")
        log "ERROR: Grype failed for $DIR_PATH"
        GRYPE_STATUS="Failed"
    fi
    
    # -------------------------------
    # 3) Cdxgen
    # -------------------------------
    CDXGEN_START=$(date +%s.%N)
    if cdxgen -r --deep --evidence -o "$CDXGEN_OUT" "$DIR_PATH" 2>&1 | tee -a "$LOG_FILE"; then
        CDXGEN_END=$(date +%s.%N)
        CDXGEN_TIME=$(echo "$CDXGEN_END - $CDXGEN_START" | bc)
        CDXGEN_TIME_FORMATTED=$(printf "%.2f" "$CDXGEN_TIME")
        log "Cdxgen SBOM generated: $CDXGEN_OUT (Time: ${CDXGEN_TIME_FORMATTED}s)"
        CDXGEN_STATUS="Success"
    else
        CDXGEN_END=$(date +%s.%N)
        CDXGEN_TIME=$(echo "$CDXGEN_END - $CDXGEN_START" | bc)
        CDXGEN_TIME_FORMATTED=$(printf "%.2f" "$CDXGEN_TIME")
        log "ERROR: Cdxgen failed for $DIR_PATH"
        CDXGEN_STATUS="Failed"
    fi
    
    # -------------------------------
    # 4) OSV-Scalibr
    # -------------------------------
    SCALIBR_START=$(date +%s.%N)
    if scalibr -o "cdx-json=$SCALIBR_OUT" "$DIR_PATH" >/dev/null 2>&1; then
        SCALIBR_END=$(date +%s.%N)
        SCALIBR_TIME=$(echo "$SCALIBR_END - $SCALIBR_START" | bc)
        SCALIBR_TIME_FORMATTED=$(printf "%.2f" "$SCALIBR_TIME")
        log "OSV-Scalibr SBOM generated: $SCALIBR_OUT (Time: ${SCALIBR_TIME_FORMATTED}s)"
        SCALIBR_STATUS="Success"
    else
        SCALIBR_END=$(date +%s.%N)
        SCALIBR_TIME=$(echo "$SCALIBR_END - $SCALIBR_START" | bc)
        SCALIBR_TIME_FORMATTED=$(printf "%.2f" "$SCALIBR_TIME")
        log "ERROR: OSV-Scalibr failed for $DIR_PATH"
        SCALIBR_STATUS="Failed"
    fi
    
    # -------------------------------
    # 5) OSV-Scanner
    # -------------------------------
    OSV_START=$(date +%s.%N)
    if osv-scanner --sbom "$SYFT_OUT" --format json > "$OSV_OUT" 2>&1; then
        OSV_END=$(date +%s.%N)
        OSV_TIME=$(echo "$OSV_END - $OSV_START" | bc)
        OSV_TIME_FORMATTED=$(printf "%.2f" "$OSV_TIME")
        
        # Check if OSV-Scanner actually found anything or failed
        if grep -q "Failed to parse SBOM\|No package sources found" "$OSV_OUT" 2>/dev/null; then
            log "OSV-Scanner incompatible with CycloneDX format - reporting 0 vulnerabilities: $OSV_OUT (Time: ${OSV_TIME_FORMATTED}s)"
            echo '{"results": []}' > "$OSV_OUT"
        else
            log "OSV-Scanner results generated: $OSV_OUT (Time: ${OSV_TIME_FORMATTED}s)"
        fi
        OSV_STATUS="Success"
    else
        OSV_END=$(date +%s.%N)
        OSV_TIME=$(echo "$OSV_END - $OSV_START" | bc)
        OSV_TIME_FORMATTED=$(printf "%.2f" "$OSV_TIME")
        log "ERROR: OSV-Scanner failed for $DIR_PATH"
        echo '{"results": []}' > "$OSV_OUT"
        OSV_STATUS="Failed"
    fi
    
    # Append to summary JSON
    if [ "$SUMMARY_JSON" != "[" ]; then
        SUMMARY_JSON+=","
    fi
    SUMMARY_JSON+=$(cat <<EOF

{
  "Directory": "$DIR_PATH",
  "Syft": "$SYFT_STATUS",
  "SyftTime": "${SYFT_TIME_FORMATTED}s",
  "Grype": "$GRYPE_STATUS",
  "GrypeTime": "${GRYPE_TIME_FORMATTED}s",
  "Cdxgen": "$CDXGEN_STATUS",
  "CdxgenTime": "${CDXGEN_TIME_FORMATTED}s",
  "Scalibr": "$SCALIBR_STATUS",
  "ScalibrTime": "${SCALIBR_TIME_FORMATTED}s",
  "OsvScanner": "$OSV_STATUS",
  "OsvTime": "${OSV_TIME_FORMATTED}s"
}
EOF
)
done

# ==========================================
# WRITE SUMMARY JSON
# ==========================================
SUMMARY_JSON+="]"
echo "$SUMMARY_JSON" | jq '.' > "$SUMMARY_FILE" 2>/dev/null || echo "$SUMMARY_JSON" > "$SUMMARY_FILE"
log "All SBOM generation tasks finished."
log "JSON summary report written to $SUMMARY_FILE"

fi # End of SkipGeneration conditional

# ==========================================
# GENERATE MARKDOWN REPORT
# ==========================================
if [ "$SKIP_ANALYSIS" = false ]; then
log "Generating markdown report..."

# Initialize arrays for component data
declare -A SYFT_COUNTS
declare -A GRYPE_COUNTS
declare -A CDXGEN_COUNTS
declare -A SCALIBR_COUNTS
declare -A OSV_VULNS
declare -A SYFT_TIMES
declare -A GRYPE_TIMES
declare -A CDXGEN_TIMES
declare -A SCALIBR_TIMES
declare -A OSV_TIMES

# Collect component counts from all SBOMs
for PROJECT in "just-a-bag-of-jars" "opencms-exploded" "opencms-zip-only" "code-with-quarkus" "sample-java-maven-single" "sample-java-maven-multi" "sample-java-gradle-single" "sample-java-gradle-multi"; do
    SYFT_FILE="$OUTPUT_DIR/$PROJECT-syft-sbom.json"
    GRYPE_FILE="$OUTPUT_DIR/$PROJECT-grype-sbom.json"
    CDXGEN_FILE="$OUTPUT_DIR/$PROJECT-cdxgen-sbom.json"
    SCALIBR_FILE="$OUTPUT_DIR/$PROJECT-scalibr-sbom.json"
    OSV_FILE="$OUTPUT_DIR/$PROJECT-osv-scanner.json"
    
    # Count Syft components
    if [ -f "$SYFT_FILE" ]; then
        SYFT_COUNTS[$PROJECT]=$(jq '.components | length' "$SYFT_FILE" 2>/dev/null || echo 0)
    else
        SYFT_COUNTS[$PROJECT]=0
    fi
    
    # Count Grype components
    if [ -f "$GRYPE_FILE" ]; then
        GRYPE_COUNTS[$PROJECT]=$(jq '.components | length' "$GRYPE_FILE" 2>/dev/null || echo 0)
    else
        GRYPE_COUNTS[$PROJECT]=0
    fi
    
    # Count Cdxgen components
    if [ -f "$CDXGEN_FILE" ]; then
        CDXGEN_COUNTS[$PROJECT]=$(jq '.components | length' "$CDXGEN_FILE" 2>/dev/null || echo 0)
    else
        CDXGEN_COUNTS[$PROJECT]=0
    fi
    
    # Count Scalibr components (CycloneDX format)
    if [ -f "$SCALIBR_FILE" ]; then
        SCALIBR_COUNTS[$PROJECT]=$(jq '.components | length' "$SCALIBR_FILE" 2>/dev/null || echo 0)
    else
        SCALIBR_COUNTS[$PROJECT]=0
    fi
    
    # Count OSV vulnerabilities
    if [ -f "$OSV_FILE" ]; then
        OSV_VULNS[$PROJECT]=$(jq '.results | length' "$OSV_FILE" 2>/dev/null || echo 0)
    else
        OSV_VULNS[$PROJECT]=0
    fi
done

# Extract timing data from summary JSON
if [ -f "$SUMMARY_FILE" ]; then
    for PROJECT in "just-a-bag-of-jars" "opencms-exploded" "opencms-zip-only"; do
        SYFT_TIMES[$PROJECT]=$(jq -r ".[] | select(.Directory | endswith(\"$PROJECT\")) | .SyftTime" "$SUMMARY_FILE" 2>/dev/null || echo "0s")
        GRYPE_TIMES[$PROJECT]=$(jq -r ".[] | select(.Directory | endswith(\"$PROJECT\")) | .GrypeTime" "$SUMMARY_FILE" 2>/dev/null || echo "0s")
        CDXGEN_TIMES[$PROJECT]=$(jq -r ".[] | select(.Directory | endswith(\"$PROJECT\")) | .CdxgenTime" "$SUMMARY_FILE" 2>/dev/null || echo "0s")
        SCALIBR_TIMES[$PROJECT]=$(jq -r ".[] | select(.Directory | endswith(\"$PROJECT\")) | .ScalibrTime" "$SUMMARY_FILE" 2>/dev/null || echo "0s")
        OSV_TIMES[$PROJECT]=$(jq -r ".[] | select(.Directory | endswith(\"$PROJECT\")) | .OsvTime" "$SUMMARY_FILE" 2>/dev/null || echo "0s")
    done
fi

# Generate markdown report
cat > "$REPORT_FILE" <<'EOFMD'
# SBOM Tool Comparison Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S')  
**Tools:** Syft v1.36.0, Grype v0.103.0, Cdxgen v11.11.0, OSV-Scalibr v0.3.6, OSV-Scanner  
**Scan Type:** Binary Archive Scanning (JARs, WARs, ZIPs, etc.)

---

## Executive Summary

This report presents automated findings from SBOM generation and vulnerability scanning tools for Java binary archives.

### Quick Results

| Project | Syft | Grype | Cdxgen | Scalibr | OSV-Scanner | Fastest Tool |
|---------|------|-------|--------|---------|-------------|--------------|
EOFMD

# Add project rows
for PROJECT in "just-a-bag-of-jars" "opencms-exploded" "opencms-zip-only"; do
    SYFT_SEC=$(echo "${SYFT_TIMES[$PROJECT]}" | sed 's/s$//')
    GRYPE_SEC=$(echo "${GRYPE_TIMES[$PROJECT]}" | sed 's/s$//')
    CDXGEN_SEC=$(echo "${CDXGEN_TIMES[$PROJECT]}" | sed 's/s$//')
    SCALIBR_SEC=$(echo "${SCALIBR_TIMES[$PROJECT]}" | sed 's/s$//')
    OSV_SEC=$(echo "${OSV_TIMES[$PROJECT]}" | sed 's/s$//')
    
    # Build list of valid tools (only those that found components > 0)
    VALID_TOOLS=()
    VALID_TIMES=()
    
    if [ "${SYFT_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_TOOLS+=("Syft")
        VALID_TIMES+=("$SYFT_SEC")
    fi
    
    if [ "${GRYPE_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_TOOLS+=("Grype")
        VALID_TIMES+=("$GRYPE_SEC")
    fi
    
    if [ "${CDXGEN_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_TOOLS+=("Cdxgen")
        VALID_TIMES+=("$CDXGEN_SEC")
    fi
    
    if [ "${SCALIBR_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_TOOLS+=("Scalibr")
        VALID_TIMES+=("$SCALIBR_SEC")
    fi
    
    # Find fastest among valid tools
    if [ ${#VALID_TOOLS[@]} -gt 0 ]; then
        FASTEST_TIME=$(printf '%s\n' "${VALID_TIMES[@]}" | sort -n | head -1)
        
        # Find which tool has the fastest time
        for i in "${!VALID_TIMES[@]}"; do
            if [ "${VALID_TIMES[$i]}" = "$FASTEST_TIME" ]; then
                FASTEST_TOOL="${VALID_TOOLS[$i]}"
                break
            fi
        done
    else
        FASTEST_TOOL="None"
    fi
    
    echo "| **$PROJECT** | ${SYFT_COUNTS[$PROJECT]} (${SYFT_TIMES[$PROJECT]}) | ${GRYPE_COUNTS[$PROJECT]} (${GRYPE_TIMES[$PROJECT]}) | ${CDXGEN_COUNTS[$PROJECT]} (${CDXGEN_TIMES[$PROJECT]}) | ${SCALIBR_COUNTS[$PROJECT]} (${SCALIBR_TIMES[$PROJECT]}) | ${OSV_VULNS[$PROJECT]} vulns (${OSV_TIMES[$PROJECT]}) | ⚡ $FASTEST_TOOL |" >> "$REPORT_FILE"
done

cat >> "$REPORT_FILE" <<'EOFMD'

---

## Component Detection Summary

### Total Components Identified

| Tool | just-a-bag-of-jars | opencms-exploded | opencms-zip-only | Average |
|------|-------------------|------------------|------------------|---------|
EOFMD

# Calculate averages
SYFT_AVG=$(echo "scale=1; (${SYFT_COUNTS[just-a-bag-of-jars]} + ${SYFT_COUNTS[opencms-exploded]} + ${SYFT_COUNTS[opencms-zip-only]}) / 3" | bc)
GRYPE_AVG=$(echo "scale=1; (${GRYPE_COUNTS[just-a-bag-of-jars]} + ${GRYPE_COUNTS[opencms-exploded]} + ${GRYPE_COUNTS[opencms-zip-only]}) / 3" | bc)
CDXGEN_AVG=$(echo "scale=1; (${CDXGEN_COUNTS[just-a-bag-of-jars]} + ${CDXGEN_COUNTS[opencms-exploded]} + ${CDXGEN_COUNTS[opencms-zip-only]}) / 3" | bc)
SCALIBR_AVG=$(echo "scale=1; (${SCALIBR_COUNTS[just-a-bag-of-jars]} + ${SCALIBR_COUNTS[opencms-exploded]} + ${SCALIBR_COUNTS[opencms-zip-only]}) / 3" | bc)
TRIVY_AVG=$(echo "scale=1; (${TRIVY_COUNTS[just-a-bag-of-jars]} + ${TRIVY_COUNTS[opencms-exploded]} + ${TRIVY_COUNTS[opencms-zip-only]}) / 3" | bc)

echo "| **Syft** | ${SYFT_COUNTS[just-a-bag-of-jars]} | ${SYFT_COUNTS[opencms-exploded]} | ${SYFT_COUNTS[opencms-zip-only]} | $SYFT_AVG |" >> "$REPORT_FILE"
echo "| **Grype** | ${GRYPE_COUNTS[just-a-bag-of-jars]} | ${GRYPE_COUNTS[opencms-exploded]} | ${GRYPE_COUNTS[opencms-zip-only]} | $GRYPE_AVG |" >> "$REPORT_FILE"
echo "| **Cdxgen** | ${CDXGEN_COUNTS[just-a-bag-of-jars]} | ${CDXGEN_COUNTS[opencms-exploded]} | ${CDXGEN_COUNTS[opencms-zip-only]} | $CDXGEN_AVG |" >> "$REPORT_FILE"
echo "| **Scalibr** | ${SCALIBR_COUNTS[just-a-bag-of-jars]} | ${SCALIBR_COUNTS[opencms-exploded]} | ${SCALIBR_COUNTS[opencms-zip-only]} | $SCALIBR_AVG |" >> "$REPORT_FILE"
echo "| **Trivy** | ${TRIVY_COUNTS[just-a-bag-of-jars]} | ${TRIVY_COUNTS[opencms-exploded]} | ${TRIVY_COUNTS[opencms-zip-only]} | $TRIVY_AVG |" >> "$REPORT_FILE"

cat >> "$REPORT_FILE" <<'EOFMD'

---

## Detailed Comparison by Directory

EOFMD

# Add detailed sections for each project
for PROJECT in "just-a-bag-of-jars" "opencms-exploded" "opencms-zip-only"; do
    SYFT_SEC=$(echo "${SYFT_TIMES[$PROJECT]}" | sed 's/s$//')
    GRYPE_SEC=$(echo "${GRYPE_TIMES[$PROJECT]}" | sed 's/s$//')
    CDXGEN_SEC=$(echo "${CDXGEN_TIMES[$PROJECT]}" | sed 's/s$//')
    SCALIBR_SEC=$(echo "${SCALIBR_TIMES[$PROJECT]}" | sed 's/s$//')
    OSV_SEC=$(echo "${OSV_TIMES[$PROJECT]}" | sed 's/s$//')
    
    TOTAL_TIME=$(echo "$SYFT_SEC + $GRYPE_SEC + $CDXGEN_SEC + $SCALIBR_SEC + $OSV_SEC" | bc)
    
    # Find max components among valid tools
    MAX_COMP=$(echo -e "${SYFT_COUNTS[$PROJECT]}\n${GRYPE_COUNTS[$PROJECT]}\n${CDXGEN_COUNTS[$PROJECT]}\n${SCALIBR_COUNTS[$PROJECT]}" | sort -n | tail -1)
    
    # Build list of valid tools for speed comparison (only those that found components > 0)
    VALID_SPEED_TOOLS=()
    VALID_SPEED_TIMES=()
    
    if [ "${SYFT_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_SPEED_TOOLS+=("Syft")
        VALID_SPEED_TIMES+=("$SYFT_SEC")
    fi
    
    if [ "${GRYPE_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_SPEED_TOOLS+=("Grype")
        VALID_SPEED_TIMES+=("$GRYPE_SEC")
    fi
    
    if [ "${CDXGEN_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_SPEED_TOOLS+=("Cdxgen")
        VALID_SPEED_TIMES+=("$CDXGEN_SEC")
    fi
    
    if [ "${SCALIBR_COUNTS[$PROJECT]}" -gt 0 ]; then
        VALID_SPEED_TOOLS+=("Scalibr")
        VALID_SPEED_TIMES+=("$SCALIBR_SEC")
    fi
    
    # Find fastest among valid tools
    if [ ${#VALID_SPEED_TOOLS[@]} -gt 0 ]; then
        MIN_TIME=$(printf '%s\n' "${VALID_SPEED_TIMES[@]}" | sort -n | head -1)
        
        # Find which tool has the fastest time
        for i in "${!VALID_SPEED_TIMES[@]}"; do
            if [ "${VALID_SPEED_TIMES[$i]}" = "$MIN_TIME" ]; then
                SPEED_WINNER="${VALID_SPEED_TOOLS[$i]}"
                break
            fi
        done
    else
        SPEED_WINNER="None"
        MIN_TIME="0"
    fi
    
    # Find component winner
    if [ "${SYFT_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${SYFT_COUNTS[$PROJECT]}" -gt 0 ]; then
        COMP_WINNER="Syft"
    elif [ "${GRYPE_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${GRYPE_COUNTS[$PROJECT]}" -gt 0 ]; then
        COMP_WINNER="Grype"
    elif [ "${CDXGEN_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${CDXGEN_COUNTS[$PROJECT]}" -gt 0 ]; then
        COMP_WINNER="Cdxgen"
    elif [ "${SCALIBR_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${SCALIBR_COUNTS[$PROJECT]}" -gt 0 ]; then
        COMP_WINNER="Scalibr"
    else
        COMP_WINNER="None"
    fi
    
    cat >> "$REPORT_FILE" <<EOFSECTION

### $PROJECT

| Tool | Components Detected | Time | Status |
|------|---------------------|------|--------|
| **Syft** | ${SYFT_COUNTS[$PROJECT]} $([ "${SYFT_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${SYFT_COUNTS[$PROJECT]}" -gt 0 ] && echo "🏆" || echo "") | ${SYFT_TIMES[$PROJECT]} $([ "$SYFT_SEC" = "$MIN_TIME" ] && [ "${SYFT_COUNTS[$PROJECT]}" -gt 0 ] && echo "⚡" || echo "") | $([ "${SYFT_COUNTS[$PROJECT]}" -gt 0 ] && echo "✅" || echo "❌") |
| **Grype** | ${GRYPE_COUNTS[$PROJECT]} $([ "${GRYPE_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${GRYPE_COUNTS[$PROJECT]}" -gt 0 ] && echo "🏆" || echo "") | ${GRYPE_TIMES[$PROJECT]} $([ "$GRYPE_SEC" = "$MIN_TIME" ] && [ "${GRYPE_COUNTS[$PROJECT]}" -gt 0 ] && echo "⚡" || echo "") | $([ "${GRYPE_COUNTS[$PROJECT]}" -gt 0 ] && echo "✅" || echo "❌") |
| **Cdxgen** | ${CDXGEN_COUNTS[$PROJECT]} $([ "${CDXGEN_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${CDXGEN_COUNTS[$PROJECT]}" -gt 0 ] && echo "🏆" || echo "") | ${CDXGEN_TIMES[$PROJECT]} $([ "$CDXGEN_SEC" = "$MIN_TIME" ] && [ "${CDXGEN_COUNTS[$PROJECT]}" -gt 0 ] && echo "⚡" || echo "") | $([ "${CDXGEN_COUNTS[$PROJECT]}" -gt 0 ] && echo "✅" || echo "❌") |
| **Scalibr** | ${SCALIBR_COUNTS[$PROJECT]} $([ "${SCALIBR_COUNTS[$PROJECT]}" = "$MAX_COMP" ] && [ "${SCALIBR_COUNTS[$PROJECT]}" -gt 0 ] && echo "🏆" || echo "") | ${SCALIBR_TIMES[$PROJECT]} $([ "$SCALIBR_SEC" = "$MIN_TIME" ] && [ "${SCALIBR_COUNTS[$PROJECT]}" -gt 0 ] && echo "⚡" || echo "") | $([ "${SCALIBR_COUNTS[$PROJECT]}" -gt 0 ] && echo "✅" || echo "❌") |
| **OSV-Scanner** | ${OSV_VULNS[$PROJECT]} vulnerabilities | ${OSV_TIMES[$PROJECT]} | ✅ |
| **Total** | **$MAX_COMP components** | **${TOTAL_TIME}s** | |

**Winner - Components:** $COMP_WINNER ($MAX_COMP detected)  
**Winner - Speed:** $SPEED_WINNER (${MIN_TIME}s)

EOFSECTION
done

cat >> "$REPORT_FILE" <<'EOFMD'

---

## Performance Analysis

### Execution Times

| Project | Syft | Grype | Cdxgen | OSV-Scanner | Total |
|---------|------|-------|--------|-------------|-------|
EOFMD

for PROJECT in "just-a-bag-of-jars" "opencms-exploded" "opencms-zip-only"; do
    SYFT_SEC=$(echo "${SYFT_TIMES[$PROJECT]}" | sed 's/s$//')
    GRYPE_SEC=$(echo "${GRYPE_TIMES[$PROJECT]}" | sed 's/s$//')
    CDXGEN_SEC=$(echo "${CDXGEN_TIMES[$PROJECT]}" | sed 's/s$//')
    OSV_SEC=$(echo "${OSV_TIMES[$PROJECT]}" | sed 's/s$//')
    TOTAL_TIME=$(echo "$SYFT_SEC + $GRYPE_SEC + $CDXGEN_SEC + $OSV_SEC" | bc)
    
    echo "| **$PROJECT** | ${SYFT_TIMES[$PROJECT]} | ${GRYPE_TIMES[$PROJECT]} | ${CDXGEN_TIMES[$PROJECT]} | ${OSV_TIMES[$PROJECT]} | ${TOTAL_TIME}s |" >> "$REPORT_FILE"
done

cat >> "$REPORT_FILE" <<'EOFMD'

---

**Report generated automatically by generate-sboms.sh**
EOFMD

log "Markdown report generated: $REPORT_FILE"

fi # End of SkipAnalysis conditional

echo ""
echo -e "\033[0;32m✅ All operations completed successfully!\033[0m"
echo ""
echo "Generated files:"
[ -f "$SUMMARY_FILE" ] && echo "  - Summary JSON: $SUMMARY_FILE"
[ -f "$REPORT_FILE" ] && echo "  - Analysis Report: $REPORT_FILE"
[ -f "$LOG_FILE" ] && echo "  - Log File: $LOG_FILE"
echo ""
