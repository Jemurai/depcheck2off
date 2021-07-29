package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/jemurai/fkit/finding"

	log "github.com/sirupsen/logrus"
)

func PrintFindings(findings []finding.Finding) {
	fjson, _ := json.MarshalIndent(findings, "", " ")
	fmt.Printf("%s", fjson)
}

// BuildFindingsFromOWASPDepCheckFile read a json file of Findings and build an array
// of findings that can be used for further processing.
func BuildFindingsFromOWASPDepCheckFile(file string) []finding.Finding {
	var findings []finding.Finding
	var dcreport OWASPDepCheckReport

	rfile, err := os.Open(file)
	if err != nil {
		log.Error(err)
	}
	bytes, err := ioutil.ReadAll(rfile)
	if err != nil {
		log.Error(err)
	}
	// TODO:  Remove the junk at the end of the JSON file;
	// 		"id" : "pkg:maven/commons-io/commons-io@2.6",
	//  	"confidence" : "HIGH",
	//  	"url" : "https://ossindex.sonatype.org/component/pkg:maven/commons-io/commons-io@2.6?utm_source=dependency-check&utm_medium=integration&utm_content=6.1.1"
	//		} ]
	//	} ]
	//	2021-02-27T16:24:51.545685284Z stdout P }

	var bracket byte = ']'
	var curly byte = '}'
	idx := len(bytes)
	bidx := 0
	log.Debugf("Length %s", idx)
	for {
		idx = idx - 1
		if idx > 0 && bytes[idx] == bracket { // Walk back to the ]
			bidx = idx
			break
		}
	}
	log.Debugf("Returning bytes 0-%s with the last chunk being %s", bidx, string(bytes[bidx-50:bidx]))
	bytes = bytes[:bidx]
	bytes = append(bytes, bracket)
	bytes = append(bytes, curly) // Add back the }

	err = json.Unmarshal(bytes, &dcreport)
	if err != nil {
		log.Error(err)
	}
	log.Debugf("OWASP Report summary for schema version %s with %v dependencies", dcreport.ReportSchema, len(dcreport.Dependencies))
	num := 0

	for i := 0; i < len(dcreport.Dependencies); i++ {
		dep := dcreport.Dependencies[i]

		// Process []vulnerabilities
		for j := 0; j < len(dep.Findings); j++ {
			vuln := dep.Findings[j]
			var refs []string
			for k := 0; k < len(vuln.References); k++ {
				refs = append(refs, vuln.References[k].URL)
			}
			var tags []string
			tags = append(tags, "dependency-check")

			var source string = "DependencyCheck: " + vuln.Source

			name := vuln.Name
			hasher := sha256.New()
			hasher.Write([]byte(dep.Path + name))
			fingerprint := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

			finding := finding.Finding{
				Name:        name,
				Description: dep.Name,
				Detail:      vuln.Description,
				Severity:    vuln.Severity,
				//Confidence:  vuln.Confidence,
				Fingerprint: fingerprint,
				Timestamp:   time.Now(),
				Source:      source,
				Location:    dep.Path,
				Cvss:        vuln.Score2.Score,
				References:  refs,
				Cwes:        vuln.CWES,
				Tags:        tags,
			}
			if vuln.Name != "" {
				num++
				findings = append(findings, finding)
			}
		}

		// Process []vulnerabilityIds
		/*
			for j := 0; j < len(dep.FindingIds); j++ {
				vuln := dep.FindingIds[j]
				var refs []string
				finding := finding.Finding{
					Name:        vuln.Name,
					Description: dep.Name,
					Detail:      dep.Description,
					//Severity:    vuln.Severity,
					Confidence: vuln.Confidence,
					//Fingerprint: viper.GetString("fingerprint"),
					Timestamp: time.Now(),
					Source:    "OWASP Dependency Check",
					Location:  dep.Path,
					//Cvss:       vuln.Score2.Score,
					References: append(refs, vuln.URL),
					//Cwes:       vuln.CWES,
					//Tags:        viper.GetStringSlice("tag"),
				}
				if vuln.URL != "" {
					num++
					findings = append(findings, finding)
				}
			}
		*/
	}
	log.Debugf("OWASP Dependency Check found %v vulns", num)
	return findings
}
