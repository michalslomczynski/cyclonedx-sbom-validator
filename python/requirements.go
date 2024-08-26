package python

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sbomparser/cyclonedx"
	"strings"
)

// ReqDependency represents a dependency in the requirements.txt file
type ReqDependency struct {
	Name    string
	Version string
}

// ParseReqDeps parses requirements.txt and compares it with the SBOM (malware-detection.json)
func ParseReqDeps(manifest cyclonedx.SBOM, reqFile string) {
	reqDependencies, err := parseRequirements(reqFile)
	if err != nil {
		log.Fatalf("Failed to parse requirements.txt: %v", err)
	}

	missingInReq := []string{}
	versionMismatches := []string{}
	checkedInReq := make(map[string]bool)

	// Check for missing or mismatched dependencies in requirements.txt
	for _, component := range manifest.BuildManifest.Manifest.Components {
		if reqVersion, exists := reqDependencies[component.Name]; exists {
			if strings.Contains(reqVersion, ";") {
				reqVersion = strings.Split(reqVersion, ";")[0]
			}

			if reqVersion != component.Version {
				versionMismatches = append(versionMismatches, fmt.Sprintf("%s (SBOM: %s, requirements.txt: %s)", component.Name, component.Version, reqVersion))
			}
		} else {
			missingInReq = append(missingInReq, component.Name)
		}
		checkedInReq[component.Name] = true
	}

	// Check for dependencies in requirements.txt that are not in the SBOM
	missingInSBOM := []string{}
	for name := range reqDependencies {
		if !checkedInReq[name] {
			missingInSBOM = append(missingInSBOM, name)
		}
	}

	// Output results
	if len(missingInReq) > 0 {
		fmt.Println("Dependencies present in SBOM but missing in requirements.txt:")
		for _, pkg := range missingInReq {
			fmt.Printf("  - %s\n", pkg)
		}
	}

	if len(missingInSBOM) > 0 {
		fmt.Println("Dependencies present in requirements.txt but missing in SBOM:")
		for _, pkg := range missingInSBOM {
			fmt.Printf("  - %s\n", pkg)
		}
	}

	if len(versionMismatches) > 0 {
		fmt.Println("Version mismatches between SBOM and requirements.txt:")
		for _, mismatch := range versionMismatches {
			fmt.Printf("  - %s\n", mismatch)
		}
	}

	if len(missingInReq) == 0 && len(missingInSBOM) == 0 && len(versionMismatches) == 0 {
		fmt.Println("All dependencies and versions are coherent between SBOM and requirements.txt.")
	}
}

func parseRequirements(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dependencies := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			parts := strings.Split(line, "==")
			if len(parts) == 2 {
				dependencies[parts[0]] = parts[1]
			} else {
				dependencies[parts[0]] = ""
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dependencies, nil
}
