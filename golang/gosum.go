package golang

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sbomparser/cyclonedx"
	"strings"
)

// SumDependency represents a dependency in the go.sum file
type SumDependency struct {
	Name    string
	Version string
}

// ParseGoDeps parses go.sum and compares it with the SBOM (malware-detection.json)
func ParseGoDeps(manifest cyclonedx.SBOM, goSumFile string) {
	sumDependencies, err := parseGoSum(goSumFile)
	if err != nil {
		log.Fatalf("Failed to parse go.sum: %v", err)
	}

	missingInGoSum := []string{}
	versionMismatches := []string{}
	checkedInGoSum := make(map[string]bool)

	// Check for missing or mismatched dependencies in go.sum
	for _, component := range manifest.BuildManifest.Manifest.Components {
		if sumVersion, exists := sumDependencies[component.Name]; exists {
			// Ignore "/go.mod" suffix in go.sum version
			normalizedSumVersion := strings.TrimSuffix(sumVersion, "/go.mod")
			if normalizedSumVersion != component.Version {
				versionMismatches = append(versionMismatches, fmt.Sprintf("%s (SBOM: %s, go.sum: %s)", component.Name, component.Version, normalizedSumVersion))
			}
		} else {
			missingInGoSum = append(missingInGoSum, component.Name)
		}
		checkedInGoSum[component.Name] = true
	}

	// Check for dependencies in go.sum that are not in the SBOM
	missingInSBOM := []string{}
	for name := range sumDependencies {
		if !checkedInGoSum[name] {
			missingInSBOM = append(missingInSBOM, name)
		}
	}

	// Output results
	if len(missingInGoSum) > 0 {
		fmt.Println("Dependencies present in SBOM but missing in go.sum:")
		for _, pkg := range missingInGoSum {
			fmt.Printf("  - %s\n", pkg)
		}
	}

	if len(missingInSBOM) > 0 {
		fmt.Println("Dependencies present in go.sum but missing in SBOM:")
		for _, pkg := range missingInSBOM {
			fmt.Printf("  - %s\n", pkg)
		}
	}

	if len(versionMismatches) > 0 {
		fmt.Println("Version mismatches between SBOM and go.sum:")
		for _, mismatch := range versionMismatches {
			fmt.Printf("  - %s\n", mismatch)
		}
	}

	if len(missingInGoSum) == 0 && len(missingInSBOM) == 0 && len(versionMismatches) == 0 {
		fmt.Println("All dependencies and versions are coherent between SBOM and go.sum.")
	}
}

// parseGoSum parses the go.sum file and extracts dependencies
func parseGoSum(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dependencies := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			dependencies[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dependencies, nil
}
