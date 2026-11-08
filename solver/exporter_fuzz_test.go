package solver

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	digest "github.com/opencontainers/go-digest"
)

// recordingTarget is a CacheExporterTarget that keeps every Add call as a
// node so that the exported graph can be serialized canonically.
type recordingTarget struct {
	nodes []*recNode
}

type recNode struct {
	dgst    digest.Digest
	deps    [][]CacheLink
	results []CacheExportResult
	key     string
}

func (*recNode) isCacheExporterRecord() {}

func (t *recordingTarget) Add(dgst digest.Digest, deps [][]CacheLink, results []CacheExportResult) (CacheExporterRecord, bool, error) {
	for _, dd := range deps {
		for _, d := range dd {
			if _, ok := d.Src.(*recNode); !ok {
				return nil, false, fmt.Errorf("unexpected record type %T", d.Src)
			}
		}
	}
	n := &recNode{dgst: dgst, deps: deps, results: results}
	t.nodes = append(t.nodes, n)
	return n, true, nil
}

func (n *recNode) canonical(depth int) string {
	if n.key != "" {
		return n.key
	}
	if depth > 64 {
		return "<deep>"
	}
	var b strings.Builder
	b.WriteString(n.dgst.String())
	for _, dd := range n.deps {
		var in []string
		for _, d := range dd {
			in = append(in, d.Selector+"@"+d.Src.(*recNode).canonical(depth+1))
		}
		slices.Sort(in)
		fmt.Fprintf(&b, "[%s]", strings.Join(in, ","))
	}
	var rs []string
	for _, r := range n.results {
		var ds []string
		for _, d := range r.Result.Descriptors {
			ds = append(ds, d.Annotations["value"])
		}
		rs = append(rs, fmt.Sprintf("%v@%d", ds, r.CreatedAt.Unix()))
	}
	slices.Sort(rs)
	fmt.Fprintf(&b, "<%s>", strings.Join(rs, ","))
	n.key = digest.FromString(b.String()).String()
	return n.key
}

func (t *recordingTarget) canonical() string {
	set := map[string]struct{}{}
	for _, n := range t.nodes {
		set[n.canonical(0)] = struct{}{}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return strings.Join(keys, "\n")
}

// FuzzCacheExport builds a random graph of cache keys in a cache manager
// (as the solver does during a build), then exports it like a cache
// exporter (local/registry/...) would. The same graph exported twice must
// produce the same set of records, otherwise the exported cache, and thus
// its digest, depends on map iteration order.
func FuzzCacheExport(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	f.Add([]byte{0, 0, 1, 1, 0x41, 2, 0x82, 3, 0xc3, 1, 2, 0x45, 0x86, 7, 8})
	f.Add([]byte{3, 3, 3, 0x43, 0x43, 0x83, 0xc3, 0x43, 0x83, 0xc3, 0x10, 0x20, 0x30})

	f.Fuzz(func(t *testing.T, prog []byte) {
		if len(prog) > 160 {
			return
		}
		next := func() byte {
			if len(prog) == 0 {
				return 0
			}
			b := prog[0]
			prog = prog[1:]
			return b
		}
		m := NewInMemoryCacheManager()
		base := time.Unix(1700000000, 0).UTC()
		var saved []*ExportableCacheKey
		for len(prog) > 0 {
			op := next()
			d := dgst(fmt.Sprintf("op%d", op&7))
			out := Index((op >> 3) & 1)
			var deps [][]CacheKeyWithSelector
			if len(saved) > 0 {
				for i := range int(op>>6) & 3 {
					var in []CacheKeyWithSelector
					for range int(next()&1) + 1 {
						b := next()
						var sel digest.Digest
						if b&0x80 != 0 {
							sel = dgst(fmt.Sprintf("sel%d", b&1))
						}
						in = append(in, CacheKeyWithSelector{CacheKey: *saved[(int(b&0x7f)+i)%len(saved)], Selector: sel})
					}
					deps = append(deps, in)
				}
			}
			k := testCacheKeyWithDeps(d, out, deps)
			res := &dummyResult{id: fmt.Sprintf("res%d", next()%6)}
			res.intValue = int(res.id[3] - '0')
			ek, err := m.Save(k, res, base.Add(time.Duration(op>>4)*time.Second))
			if err != nil {
				continue
			}
			saved = append(saved, ek)
		}
		if len(saved) == 0 {
			return
		}

		for _, mode := range []bool{false, true} {
			opts := testExporterOpts(mode)
			opts.ExportRoots = true
			var first string
			for i := range 3 {
				tgt := &recordingTarget{}
				for _, ek := range saved {
					if _, err := ek.Exporter.ExportTo(context.Background(), tgt, opts); err != nil {
						t.Fatalf("export: %v", err)
					}
				}
				c := tgt.canonical()
				if i == 0 {
					first = c
					continue
				}
				if c != first {
					t.Fatalf("export (max=%v) not deterministic:\nfirst:\n%s\nrun %d:\n%s", mode, first, i, c)
				}
			}
		}
	})
}
