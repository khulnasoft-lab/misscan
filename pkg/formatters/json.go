package formatters

import (
	"encoding/json"

	"github.com/khulnasoft-lab/misscan/pkg/scan"
)

func outputJSON(b ConfigurableFormatter, results scan.Results) error {
	jsonWriter := json.NewEncoder(b.Writer())
	jsonWriter.SetIndent("", "\t")
	var flatResults = []scan.FlatResult{}
	for _, result := range results {
		switch result.Status() {
		case scan.StatusIgnored:
			if !b.IncludeIgnored() {
				continue
			}
		case scan.StatusPassed:
			if !b.IncludePassed() {
				continue
			}
		}
		flat := result.Flatten()
		flat.Links = b.GetLinks(result)
		flat.Location.Filename = b.Path(result, result.Metadata())
		flatResults = append(flatResults, flat)
	}
	return jsonWriter.Encode(struct {
		Results []scan.FlatResult `json:"results"`
	}{flatResults})
}
