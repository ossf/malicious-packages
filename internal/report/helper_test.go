package report

import "github.com/google/osv-scanner/pkg/models"

// Vuln is a test helper method that provides access to the underlying raw
// vulnerability object.
func (r *Report) Vuln() *models.Vulnerability {
	return r.raw
}

// Origins is a test helper method that provides access to the underlying
// origins array.
func (r *Report) Origins() []*OriginRef {
	return r.origins
}
