package deps

import "github.com/malandas/andas/internal/osv"

// The dependency scanner shares one OSV client with the image scanner. These
// aliases keep the rest of the deps package unchanged while the implementation
// (batching + concurrent detail fetches) lives in internal/osv.
type pkgRef = osv.Ref
type advisory = osv.Advisory

func queryOSV(refs []pkgRef, timeoutS int) (map[string][]advisory, error) {
	return osv.Query(refs, timeoutS)
}
