package cyclonedx

// Define the structures based on the SBOM JSON structure
type BuildManifest struct {
	Format   string `json:"format"`
	Manifest struct {
		Components []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"components"`
	} `json:"manifest"`
}

type SBOM struct {
	BuildCompletedAt string        `json:"build_completed_at"`
	BuildManifest    BuildManifest `json:"build_manifest"`
}
