package js

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sbomparser/cyclonedx"
	"strings"
)

// PackageLock represents a dependency in package-lock.json
type PackageLock struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// NormalizePackageName strips node_modules/ and any preceding path, leaving only the final package name
func normalizePackageName(name string) string {
	// Handle cases where the name includes "node_modules/"
	if strings.Contains(name, "node_modules/") {
		parts := strings.Split(name, "node_modules/")
		name = parts[len(parts)-1]
	}
	return name
}

func ParsePackageLock(manifest cyclonedx.SBOM, packageLockFile string) {
	// Read and unmarshal package-lock.json
	packageLockBytes, err := os.ReadFile(packageLockFile)
	if err != nil {
		log.Fatalf("Failed to read package-lock.json: %v", err)
	}
	var packageLock PackageLock
	err = json.Unmarshal(packageLockBytes, &packageLock)
	if err != nil {
		log.Fatalf("Failed to unmarshal package-lock.json: %v", err)
	}

	// Normalize and map package-lock dependencies
	normalizedDependencies := make(map[string]string)
	for pkgName, details := range packageLock.Packages {
		normalizedName := normalizePackageName(pkgName)
		normalizedDependencies[normalizedName] = details.Version
	}

	// Compare dependencies
	missingInPackageLock := []string{}
	missingInMalwareDetection := []string{}
	versionMismatches := []string{}

	// Track which dependencies are checked
	checkedInPackageLock := make(map[string]bool)

	// Check for components in malware-detection.json that are missing or mismatched in package-lock.json
	for _, component := range manifest.BuildManifest.Manifest.Components {
		packageVersion, exists := normalizedDependencies[component.Name]
		if !exists {
			missingInPackageLock = append(missingInPackageLock, component.Name)
		} else if packageVersion != component.Version {
			versionMismatches = append(versionMismatches, fmt.Sprintf("%s (expected: %s, found: %s)", component.Name, component.Version, packageVersion))
		}
		checkedInPackageLock[component.Name] = true
	}

	// Check for dependencies in package-lock.json that are missing in malware-detection.json
	for pkgName := range normalizedDependencies {
		if !checkedInPackageLock[pkgName] {
			missingInMalwareDetection = append(missingInMalwareDetection, pkgName)
		}
	}

	// Output results
	if len(missingInPackageLock) > 0 {
		fmt.Println("Packages present in malware-detection.json but missing in package-lock.json:")
		for _, pkg := range missingInPackageLock {
			fmt.Printf("  - %s\n", pkg)
		}
	}

	if len(missingInMalwareDetection) > 0 {
		fmt.Println("Packages present in package-lock.json but missing in malware-detection.json:")
		for _, pkg := range missingInMalwareDetection {
			fmt.Printf("  - %s\n", pkg)
		}
	}

	if len(versionMismatches) > 0 {
		fmt.Println("Version mismatches between malware-detection.json and package-lock.json:")
		for _, mismatch := range versionMismatches {
			fmt.Printf("  - %s\n", mismatch)
		}
	}

	if len(missingInPackageLock) == 0 && len(missingInMalwareDetection) == 0 && len(versionMismatches) == 0 {
		fmt.Println("All packages and versions are coherent between malware-detection.json and package-lock.json.")
	}
}
