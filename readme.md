# Example
## Input
`go run main.go js sbom.json package-lock.json`
## Output
```
Packages present in sbom.json but missing in package-lock.json:
  - tzdata
  ...
Packages present in package-lock.json but missing in sbom.json:
  - fsevents
  ...
Version mismatches between sbom.json and package-lock.json:
  - yargs-parser (expected: 18.1.3, found: 21.1.1)
  ...

```