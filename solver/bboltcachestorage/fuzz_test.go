package bboltcachestorage

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/moby/buildkit/solver"
	digest "github.com/opencontainers/go-digest"
)

const (
	fuzzNumIDs     = 6
	fuzzNumResults = 4
)

func fuzzID(b byte) string     { return fmt.Sprintf("key%d", int(b)%fuzzNumIDs) }
func fuzzResult(b byte) string { return fmt.Sprintf("res%d", int(b)%fuzzNumResults) }

func fuzzLink(b byte) solver.CacheInfoLink {
	l := solver.CacheInfoLink{
		Input:  solver.Index(b & 1),
		Output: solver.Index((b >> 1) & 1),
		Digest: digest.FromString(fmt.Sprintf("op%d", (b>>2)&3)),
	}
	if b&0x10 != 0 {
		l.Selector = digest.FromString("sel")
	}
	return l
}

type storageState struct {
	ids       []string
	results   map[string][]string
	links     map[string][]string
	backlinks map[string][]string
	byResult  map[string][]string
}

func snapshot(t *testing.T, s solver.CacheKeyStorage) storageState {
	st := storageState{
		results:   map[string][]string{},
		links:     map[string][]string{},
		backlinks: map[string][]string{},
		byResult:  map[string][]string{},
	}
	for i := range fuzzNumIDs {
		id := fuzzID(byte(i))
		if s.Exists(id) {
			st.ids = append(st.ids, id)
		}
		var rs []string
		if err := s.WalkResults(id, func(r solver.CacheResult) error {
			rs = append(rs, fmt.Sprintf("%s@%d", r.ID, r.CreatedAt.Unix()))
			if _, err := s.Load(id, r.ID); err != nil {
				t.Fatalf("Load(%s,%s) failed after WalkResults: %v", id, r.ID, err)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		slices.Sort(rs)
		st.results[id] = rs

		var ls []string
		for lb := range 32 {
			l := fuzzLink(byte(lb))
			if err := s.WalkLinks(id, l, func(target string) error {
				ls = append(ls, fmt.Sprintf("%d/%d/%s/%s->%s", l.Input, l.Output, l.Digest, l.Selector, target))
				if !s.HasLink(id, l, target) {
					t.Fatalf("WalkLinks(%s) yields %s but HasLink false", id, target)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		}
		slices.Sort(ls)
		st.links[id] = ls

		var bls []string
		if err := s.WalkBacklinks(id, func(src string, l solver.CacheInfoLink) error {
			// Backlinks are returned rootKey-encoded (Output folded into
			// Digest), so they can't be checked with HasLink; the
			// differential comparison covers them.
			bls = append(bls, fmt.Sprintf("%s:%d/%d/%s/%s", src, l.Input, l.Output, l.Digest, l.Selector))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		slices.Sort(bls)
		bls = slices.Compact(bls)
		st.backlinks[id] = bls
	}
	for i := range fuzzNumResults {
		r := fuzzResult(byte(i))
		var ids []string
		if err := s.WalkIDsByResult(r, func(id string) error {
			ids = append(ids, id)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		slices.Sort(ids)
		st.byResult[r] = ids
	}
	return st
}

func diffState(a, b storageState) string {
	if !slices.Equal(a.ids, b.ids) {
		return fmt.Sprintf("Exists: mem=%v bolt=%v", a.ids, b.ids)
	}
	for _, m := range []struct {
		name string
		a, b map[string][]string
	}{
		{"results", a.results, b.results},
		{"links", a.links, b.links},
		{"backlinks", a.backlinks, b.backlinks},
		{"byResult", a.byResult, b.byResult},
	} {
		for k, va := range m.a {
			if !slices.Equal(va, m.b[k]) {
				return fmt.Sprintf("%s[%s]: mem=%v bolt=%v", m.name, k, va, m.b[k])
			}
		}
	}
	return ""
}

// FuzzStorageDifferential applies the same byte-driven sequence of
// AddResult / AddLink / Release operations to the in-memory and the bbolt
// cache key storages and checks that every observable query agrees.
func FuzzStorageDifferential(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 1, 2, 0, 1, 0})
	f.Add([]byte{1, 0, 0x11, 1, 0, 0x03, 2, 0, 1, 1, 0, 2, 0, 1, 2})
	f.Add([]byte{0, 1, 1, 0, 2, 2, 1, 1, 0, 2, 1, 2, 5, 3, 2, 1, 2, 2})

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 120 {
			return
		}
		mem := solver.NewInMemoryCacheStorage()
		bolt, err := NewStore(filepath.Join(t.TempDir(), "cache.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer bolt.Close()

		base := time.Unix(1700000000, 0).UTC()
		var trace []string
		for i := 0; i+3 <= len(ops); i += 4 {
			op, a, b := ops[i], ops[i+1], ops[i+2]
			var c byte
			if i+3 < len(ops) {
				c = ops[i+3]
			}
			var errM, errB error
			switch op % 4 {
			case 0, 3:
				res := solver.CacheResult{ID: fuzzResult(b), CreatedAt: base.Add(time.Duration(c) * time.Second)}
				trace = append(trace, fmt.Sprintf("AddResult(%s,%s)", fuzzID(a), res.ID))
				errM = mem.AddResult(fuzzID(a), res)
				errB = bolt.AddResult(fuzzID(a), res)
			case 1:
				// Real cache keys are content-addressed, so the link graph
				// is acyclic: only link from a lower to a higher key.
				src, dst := int(a)%fuzzNumIDs, int(b)%fuzzNumIDs
				if src == dst {
					continue
				}
				if src > dst {
					src, dst = dst, src
				}
				l := fuzzLink(c)
				trace = append(trace, fmt.Sprintf("AddLink(%s,%+v,%s)", fuzzID(byte(src)), l, fuzzID(byte(dst))))
				errM = mem.AddLink(fuzzID(byte(src)), l, fuzzID(byte(dst)))
				errB = bolt.AddLink(fuzzID(byte(src)), l, fuzzID(byte(dst)))
			case 2:
				trace = append(trace, fmt.Sprintf("Release(%s)", fuzzResult(b)))
				errM = mem.Release(fuzzResult(b))
				errB = bolt.Release(fuzzResult(b))
				// Known benign divergence: bolt returns ErrNotFound for an
				// unknown result, memory returns nil. Callers ignore it.
				if errors.Is(errB, solver.ErrNotFound) {
					errB = nil
				}
			}
			if (errM == nil) != (errB == nil) {
				t.Fatalf("error mismatch mem=%v bolt=%v\ntrace: %v", errM, errB, trace)
			}
			if d := diffState(snapshot(t, mem), snapshot(t, bolt)); d != "" {
				t.Fatalf("divergence: %s\ntrace:\n  %s", d, joinLines(trace))
			}
		}
	})
}

func joinLines(s []string) string {
	out := ""
	for i, l := range s {
		if i > 0 {
			out += "\n  "
		}
		out += l
	}
	return out
}
