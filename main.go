package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sbomparser/cyclonedx"
	"sbomparser/golang"
	"sbomparser/js"
	"sbomparser/python"
)

func main() {
	if len(os.Args) < 4 {
		log.Fatalf("Usage: %s [go|js|python] <bom-manifest.json> [<package-lock.json>|<go.sum>]", os.Args[0])
	}

	bomManifest := os.Args[2]
	dependencyFile := os.Args[3]

	// Read and unmarshal malware-detection.json
	sbomFile, err := os.ReadFile(bomManifest)
	if err != nil {
		log.Fatalf("Failed to read malware-detection.json: %v", err)
	}
	var sbom cyclonedx.SBOM
	err = json.Unmarshal(sbomFile, &sbom)
	if err != nil {
		log.Fatalf("Failed to unmarshal malware-detection.json: %v", err)
	}

	switch os.Args[1] {
	case "go":
		golang.ParseGoDeps(sbom, dependencyFile)
	case "js":
		js.ParsePackageLock(sbom, dependencyFile)
	case "python":
		python.ParseReqDeps(sbom, dependencyFile)
	default:
		fmt.Printf("target %s not supported\n", os.Args[1])
	}
}
