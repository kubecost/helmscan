package reports

type JSONReport struct {
	ReportType    string      `json:"report_type"`
	Comparison    interface{} `json:"comparison"`
	Summary       Summary     `json:"summary"`
	AddedCVEs     []CVE       `json:"added_cves"`
	RemovedCVEs   []CVE       `json:"removed_cves"`
	UnchangedCVEs []CVE       `json:"unchanged_cves"`
}

type Summary struct {
	SeverityCounts []SeverityCount `json:"severity_counts"`
	ImageChanges   []ImageChange   `json:"image_changes,omitempty"`
}

type SeverityCount struct {
	Severity   string `json:"severity"`
	Current    int    `json:"current_count"`
	Previous   int    `json:"previous_count"`
	Difference int    `json:"difference"`
}

type ImageChange struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	BeforeRepo string `json:"before_repo,omitempty"`
	AfterRepo  string `json:"after_repo,omitempty"`
	BeforeTag  string `json:"before_tag,omitempty"`
	AfterTag   string `json:"after_tag,omitempty"`
}

type CVE struct {
	ID             string   `json:"id"`
	Severity       string   `json:"severity"`
	Packages       []string `json:"packages,omitempty"`
	AffectedImages []string `json:"affected_images,omitempty"`
}
