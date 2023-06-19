package report

import (
	"time"

	"github.com/google/osv-scanner/pkg/models"
)

const originRefKey = "malicious-packages-origins"

type OriginRef struct {
	Source     string         `json:"source"`
	SHASum     string         `json:"sha256"`
	ImportTime time.Time      `json:"import_time"`
	Ranges     []models.Range `json:"ranges,omitempty"`
	Versions   []string       `json:"versions,omitempty"`
}

func (r *Report) getOrigin(sourceID, shasum string) *OriginRef {
	for _, o := range r.origins {
		if o.Source == sourceID && o.SHASum == shasum {
			return o
		}
	}
	return nil
}

func (r *Report) HasOrigin(sourceID, shasum string) bool {
	return r.getOrigin(sourceID, shasum) != nil
}

func (r *Report) AddOrigin(sourceID, shasum string) *OriginRef {
	ref := &OriginRef{
		Source:     sourceID,
		SHASum:     shasum,
		ImportTime: time.Now().UTC(),
		Ranges:     r.raw.Affected[0].Ranges,
		Versions:   r.raw.Affected[0].Versions,
	}
	r.origins = append(r.origins, ref)
	return ref
}

func (r *Report) HasCommonOrigin(other *Report) bool {
	for _, o := range r.origins {
		if other.HasOrigin(o.Source, o.SHASum) {
			return true
		}
	}
	return false
}
