package utils

// OWASPDepCheckReport captures the top level report structure.
type OWASPDepCheckReport struct {
	ReportSchema string                    `json:"reportSchema"`
	Dependencies []OWASPDepCheckDependency `json:"dependencies"`
}

// OWASPDepCheckDependency captures a dependency.
type OWASPDepCheckDependency struct {
	Name        string                   `json:"fileName"`
	Path        string                   `json:"filePath"`
	Description string                   `json:"description"`
	License     string                   `json:"license"`
	FindingIds  []OWASPDepCheckFindingID `json:"vulnerabilityIds"`
	Findings    []OWASPDepCheckFinding   `json:"vulnerabilities"`
}

// OWASPDepCheckFindingID captures a finding.
type OWASPDepCheckFindingID struct {
	Name       string `json:"id"`
	Confidence string `json:"confidence"`
	URL        string `json:"url"`
}

// OWASPDepCheckFinding captures a finding.
type OWASPDepCheckFinding struct {
	Source      string      `json:"source"`
	Name        string      `json:"name"`
	Severity    string      `json:"severity"`
	Description string      `json:"description"`
	CWES        []string    `json:"cwes"`
	Score2      CVSS2       `json:"cvssv2"`
	Score3      CVSS3       `json:"cvssv3"`
	References  []Reference `json:"references"`
}

// CVSS2 is a CVSS Score
type CVSS2 struct {
	Score float64 `json:"score"`
}

// CVSS3 is a CVSS3 Score
type CVSS3 struct {
	Score float64 `json:"baseScore"`
}

// Reference is a reference.
type Reference struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	URL    string `json:"URL"`
}
