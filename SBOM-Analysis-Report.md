# SBOM Tool Comparison Report

**Generated:** 2025-11-14 16:56:55  
**Tools:** Syft v1.36.0, Grype v0.103.0, Cdxgen v11.11.0, OSV-Scanner  
**Scan Type:** Binary Archive Scanning (JARs, WARs, ZIPs, etc.)

---

## Executive Summary

This report presents automated findings from SBOM generation and vulnerability scanning tools for Java binary archives.

### Quick Results

| Project | Syft | Grype | Cdxgen | OSV-Scanner | Fastest Tool |
|---------|------|-------|--------|-------------|--------------|
| **just-a-bag-of-jars** | 18 (2.48s) | 18 (2.05s) | 18 (19.19s) | 0 vulns (0.1s) | ⚡ Grype |
| **opencms-exploded** | 158 (11.66s) | 151 (11.75s) | 143 (66.16s) | 0 vulns (0.08s) | ⚡ Syft |
| **opencms-zip-only** | 158 (12.78s) | 151 (12.37s) | 0 (13.37s) | 0 vulns (0.07s) | ⚡ Grype |

---

## Component Detection Summary

### Total Components Identified

| Tool | just-a-bag-of-jars | opencms-exploded | opencms-zip-only | Average |
|------|-------------------|------------------|------------------|---------|
| **Syft** | 18 | 158 | 158 | 111.3 |
| **Grype** | 18 | 151 | 151 | 106.7 |
| **Cdxgen** | 18 | 143 | 0 | 53.7 |

---

## Detailed Comparison by Directory

### just-a-bag-of-jars

| Tool | Components Detected | Time | Status |
|------|---------------------|------|--------|
| **Syft** | 18 🏆 | 2.48s  | ✅ |
| **Grype** | 18 🏆 | 2.05s ⚡ | ✅ |
| **Cdxgen** | 18 🏆 | 19.19s  | ✅ |
| **OSV-Scanner** | 0 vulnerabilities | 0.1s  | ✅ |
| **Total** | **18 components** | **23.82s** | |

**Winner - Components:** Syft (18 detected)  
**Winner - Speed:** Grype (2.05s)

### opencms-exploded

| Tool | Components Detected | Time | Status |
|------|---------------------|------|--------|
| **Syft** | 158 🏆 | 11.66s ⚡ | ✅ |
| **Grype** | 151  | 11.75s  | ✅ |
| **Cdxgen** | 143  | 66.16s  | ✅ |
| **OSV-Scanner** | 0 vulnerabilities | 0.08s  | ✅ |
| **Total** | **158 components** | **89.65s** | |

**Winner - Components:** Syft (158 detected)  
**Winner - Speed:** Syft (11.66s)

### opencms-zip-only

| Tool | Components Detected | Time | Status |
|------|---------------------|------|--------|
| **Syft** | 158 🏆 | 12.78s  | ✅ |
| **Grype** | 151  | 12.37s ⚡ | ✅ |
| **Cdxgen** | 0  | 13.37s  | ❌ |
| **OSV-Scanner** | 0 vulnerabilities | 0.07s  | ✅ |
| **Total** | **158 components** | **38.59s** | |

**Winner - Components:** Syft (158 detected)  
**Winner - Speed:** Grype (12.37s)

---

## Performance Analysis

### Execution Times

| Project | Syft | Grype | Cdxgen | OSV-Scanner | Total |
|---------|------|-------|--------|-------------|-------|
| **just-a-bag-of-jars** | 2.48s | 2.05s | 19.19s | 0.1s | 23.82s |
| **opencms-exploded** | 11.66s | 11.75s | 66.16s | 0.08s | 89.65s |
| **opencms-zip-only** | 12.78s | 12.37s | 13.37s | 0.07s | 38.59s |

### Average Execution Time per Tool

| Tool | Average Time | Performance Rating |
|------|-------------|-------------------|
| **Syft** | 8.97s | ⚡⚡⚡⚡⚡ Excellent |
| **Grype** | 8.72s | ⚡⚡⚡⚡⚡ Excellent |
| **Cdxgen** | 32.91s | ⚡⚡⚡ Fair |
| **OSV-Scanner** | 0.08s | ⚡⚡⚡⚡⚡ Excellent |

---

## Key Findings

### 1. Component Detection Accuracy

✅ **Perfect Agreement on just-a-bag-of-jars**: All three tools identified 18 components

- **opencms-exploded**: Syft found the most components (158)   - Syft found 7 more components than Grype (likely with UNKNOWN versions)   - Grype found 8 more components than Cdxgen

- **opencms-zip-only**: ❌ Cdxgen failed to detect any components in ZIP archive format

### 2. Performance Winners

- **just-a-bag-of-jars**: Grype was fastest at 2.05s - **opencms-exploded**: Syft was fastest at 11.66s - **opencms-zip-only**: Grype was fastest at 12.37s

### 3. Tool Success Rate

| Tool | Successful Scans | Success Rate |
|------|-----------------|--------------|
| **Syft** | 3/3 | ✅ 100% |
| **Grype** | 3/3 | ✅ 100% |
| **Cdxgen** | 2/3 | ⚠️ 66.7% |

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
| just-a-bag-of-jars | Success | Success | Success | Success |
| opencms-exploded | Success | Success | Success | Success |
| opencms-zip-only | Success | Success | Success | Success |

---

## Output Files

The following files have been generated:

### Syft SBOMs

- `just-a-bag-of-jars-syft-sbom.json`
- `opencms-exploded-syft-sbom.json`
- `opencms-zip-only-syft-sbom.json`

### Grype SBOMs

- `just-a-bag-of-jars-grype-sbom.json`
- `opencms-exploded-grype-sbom.json`
- `opencms-zip-only-grype-sbom.json`

### Cdxgen SBOMs

- `just-a-bag-of-jars-cdxgen-sbom.json`
- `opencms-exploded-cdxgen-sbom.json`
- `opencms-zip-only-cdxgen-sbom.json`

### OSV-Scanner Results

- `just-a-bag-of-jars-osv-scanner.json`
- `opencms-exploded-osv-scanner.json`
- `opencms-zip-only-osv-scanner.json`

---

**Report Location:** `D:\dev\github\Binary-scanning-examples\generate-sboms\SBOM-Analysis-Report.md`  
**Summary JSON:** `D:\dev\github\Binary-scanning-examples\generate-sboms\sbom-summary.json`  
**Log File:** `D:\dev\github\Binary-scanning-examples\generate-sboms\run.log`

---

Report generated automatically by generate-sboms.ps1
