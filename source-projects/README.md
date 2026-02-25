# Sample Java Applications

This directory contains sample Java applications for testing SBOM generation tools.

## Maven Projects

### 1. sample-java-maven-single
Single-module Maven application with Spring Boot.

**Dependencies:**
- Spring Boot Starter Web 3.1.5
- Apache Commons Lang3 3.12.0
- Gson 2.10.1
- JUnit Jupiter 5.9.3

**Build:**
```bash
cd sample-java-maven-single
mvn clean package
```

### 2. sample-java-maven-multi
Multi-module Maven application with 3 modules:
- **core** - Domain models and utilities
- **service** - Business logic layer
- **web** - REST API endpoints (Spring Boot)

**Build:**
```bash
cd sample-java-maven-multi
mvn clean package
```

The web module creates an executable JAR at `web/target/web-1.0.0.jar`

## Gradle Projects

### 3. sample-java-gradle-single
Single-module Gradle application with Spring Boot.

**Dependencies:**
- Spring Boot Starter Web 3.1.5
- Apache Commons Lang3 3.12.0
- Gson 2.10.1
- JUnit Jupiter 5.9.3

**Build:**
```bash
cd sample-java-gradle-single
./gradlew build
```
(On Windows use `gradlew.bat build`)

### 4. sample-java-gradle-multi
Multi-module Gradle application with 3 modules:
- **core** - Domain models and utilities
- **service** - Business logic layer
- **web** - REST API endpoints (Spring Boot)

**Build:**
```bash
cd sample-java-gradle-multi
./gradlew build
```

The web module creates an executable JAR at `web/build/libs/web-1.0.0.jar`

## Testing SBOM Tools

These projects are designed to test SBOM generation tools like:
- Syft
- Grype
- Cdxgen
- OSV-Scalibr
- Trivy
- Bei
- Vet
- OSV-Scanner (vulnerability scanning)

Each project includes various dependencies to ensure comprehensive testing of:
- Transitive dependency detection
- Multi-module project handling
- Different build systems (Maven vs Gradle)
- Common libraries (Spring Boot, Apache Commons, Gson)
