package cacheimport

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/moby/buildkit/solver"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

// providerFor returns a DescriptorProvider containing every blob referenced
// by the config, except those whose bit is cleared in mask (so that both the
// "blob present" and "blob missing" code paths are exercised).
func providerFor(cfg cacheimporttypes.CacheConfig, mask uint64) DescriptorProvider {
	p := DescriptorProvider{}
	for i, l := range cfg.Layers {
		// Exporters only ever reference valid digests; an invalid (e.g. empty)
		// blob makes marshalRemote emit an orphan layer, which is not
		// interesting here.
		if mask&(1<<(uint(i)%64)) == 0 || l.Blob.Validate() != nil {
			continue
		}
		p[l.Blob] = DescriptorProviderPair{
			Descriptor: ocispecs.Descriptor{
				Digest:    l.Blob,
				MediaType: ocispecs.MediaTypeImageLayerGzip,
				Size:      int64(i + 1),
			},
		}
	}
	return p
}

func walkStorage(t *testing.T, cc *CacheChains) {
	keys, results, err := NewCacheKeyStorage(cc, nil)
	if err != nil {
		return
	}
	var ids []string
	if err := keys.Walk(func(id string) error {
		ids = append(ids, id)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if !keys.Exists(id) {
			t.Fatalf("walked id %q does not exist", id)
		}
		_ = keys.WalkResults(id, func(r solver.CacheResult) error {
			if _, err := keys.Load(id, r.ID); err != nil {
				t.Fatalf("Load(%q,%q) after WalkResults: %v", id, r.ID, err)
			}
			found := false
			_ = keys.WalkIDsByResult(r.ID, func(rid string) error {
				if rid == id {
					found = true
				}
				return nil
			})
			if !found {
				t.Fatalf("WalkIDsByResult(%q) missing key %q", r.ID, id)
			}
			if !results.Exists(t.Context(), r.ID) {
				t.Fatalf("result %q for key %q not in result storage", r.ID, id)
			}
			return nil
		})
		_ = keys.WalkBacklinks(id, func(src string, l solver.CacheInfoLink) error {
			if !keys.Exists(src) {
				t.Fatalf("backlink source %q of %q does not exist", src, id)
			}
			// NOTE: v1 backlinks carry the already outputKey-encoded digest
			// (Output=0), so they cannot be fed back into HasLink/WalkLinks
			// (which re-encode). Check against WalkLinksAll instead.
			found := false
			_ = keys.(*cacheKeyStorage).WalkLinksAll(src, func(target string, fl solver.CacheInfoLink) error {
				if target == id && fl == l {
					found = true
				}
				return nil
			})
			if !found {
				t.Fatalf("backlink %q -%v-> %q has no forward link", src, l, id)
			}
			return nil
		})
	}
}

// FuzzParse feeds arbitrary bytes as a remote cache config (as fetched from
// a registry / local / gha / s3 cache import), then exercises the key storage
// built from it, and checks that Marshal output re-parses to a stable config.
func FuzzParse(f *testing.F) {
	d := func(s string) digest.Digest { return digest.FromString(s) }
	seed := cacheimporttypes.CacheConfig{
		Layers: []cacheimporttypes.CacheLayer{
			{Blob: d("l0"), ParentIndex: -1},
			{Blob: d("l1"), ParentIndex: 0},
		},
		Records: []cacheimporttypes.CacheRecord{
			{Digest: outputKey(d("baz"), 0), Inputs: [][]cacheimporttypes.CacheInput{{{LinkIndex: 1}}, {{LinkIndex: 2, Selector: "sel"}}}, Results: []cacheimporttypes.CacheResult{{LayerIndex: 1}}},
			{Digest: outputKey(d("foo"), 0)},
			{Digest: outputKey(d("bar"), 1), ChainedResults: []cacheimporttypes.ChainedResult{{LayerIndexes: []int{0, 1}}}},
		},
	}
	dt, _ := json.Marshal(seed)
	f.Add(dt, ^uint64(0))
	f.Add(dt, uint64(1))
	f.Add([]byte(`{"layers":[{"blob":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","parent":-1}],"records":[{"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","layers":[{"layer":0}]},{"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","inputs":[[{"link":0}]]}]}`), ^uint64(0))
	f.Add([]byte(`{"records":[{"digest":"sha256:aa","inputs":[[{"link":0}]]}]}`), ^uint64(0))

	f.Fuzz(func(t *testing.T, dt []byte, mask uint64) {
		var cfg cacheimporttypes.CacheConfig
		if err := json.Unmarshal(dt, &cfg); err != nil {
			return
		}
		if len(cfg.Records) > 64 || len(cfg.Layers) > 64 {
			return
		}
		provider := providerFor(cfg, mask)

		cc := NewCacheChains()
		if err := Parse(dt, provider, cc); err != nil {
			return
		}
		walkStorage(t, cc)

		cfg1, desc1, err := cc.Marshal(t.Context())
		if err != nil {
			return
		}
		dt1, err := json.Marshal(cfg1)
		if err != nil {
			t.Fatal(err)
		}

		cc2 := NewCacheChains()
		if err := Parse(dt1, desc1, cc2); err != nil {
			t.Fatalf("re-parse of marshaled config failed: %v\ninput: %s\nmarshaled: %s", err, dt, dt1)
		}
		walkStorage(t, cc2)
		cfg2, _, err := cc2.Marshal(t.Context())
		if err != nil {
			t.Fatalf("re-marshal failed: %v", err)
		}
		dt2, _ := json.Marshal(cfg2)
		if string(dt1) != string(dt2) {
			t.Fatalf("marshal not idempotent\ninput: %s\nfirst:  %s\nsecond: %s", dt, dt1, dt2)
		}
	})
}

// FuzzCacheChainsAdd builds a CacheChains (as the exporter does during a
// build) from a byte-driven sequence of Add operations, then checks that
// Marshal -> JSON -> Parse -> Marshal is a fixed point.
func FuzzCacheChainsAdd(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	f.Add([]byte{3, 0, 0, 0, 1, 1, 0, 2, 0x81, 1, 2, 0x42, 3, 3})
	f.Add([]byte{0x10, 0x20, 0x30, 0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7, 0xb8, 0xc9})

	f.Fuzz(func(t *testing.T, ops []byte) {
		if len(ops) > 256 {
			return
		}
		cc := NewCacheChains()
		var recs []solver.CacheExporterRecord
		base := time.Unix(1700000000, 0).UTC()
		next := func() byte {
			if len(ops) == 0 {
				return 0
			}
			b := ops[0]
			ops = ops[1:]
			return b
		}
		for len(ops) > 0 {
			op := next()
			dgst := outputKey(digest.FromString(fmt.Sprintf("op%d", op&0x0f)), int(op>>4)&1)
			var deps [][]solver.CacheLink
			if len(recs) > 0 {
				nInputs := int(op>>5) & 3
				for range nInputs {
					var in []solver.CacheLink
					nLinks := int(next()&1) + 1
					for range nLinks {
						b := next()
						sel := ""
						if b&0x80 != 0 {
							sel = fmt.Sprintf("sel%d", b&3)
						}
						in = append(in, solver.CacheLink{Src: recs[int(b&0x7f)%len(recs)], Selector: sel})
					}
					deps = append(deps, in)
				}
			}
			var results []solver.CacheExportResult
			if op&0x80 != 0 {
				b := next()
				nDesc := int(b&3) + 1
				r := &solver.Remote{}
				for i := range nDesc {
					r.Descriptors = append(r.Descriptors, ocispecs.Descriptor{
						Digest:    digest.FromString(fmt.Sprintf("blob%d", (int(b>>2)+i)%8)),
						MediaType: ocispecs.MediaTypeImageLayerGzip,
						Size:      int64(i + 1),
					})
				}
				results = append(results, solver.CacheExportResult{
					CreatedAt: base.Add(time.Duration(b>>4) * time.Second),
					Result:    r,
				})
			}
			rec, _, err := cc.Add(dgst, deps, results)
			if err != nil {
				continue
			}
			if rec != nil {
				recs = append(recs, rec)
			}
		}

		walkStorage(t, cc)

		cfg1, desc1, err := cc.Marshal(t.Context())
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		dt1, err := json.Marshal(cfg1)
		if err != nil {
			t.Fatal(err)
		}
		cc2 := NewCacheChains()
		if err := Parse(dt1, desc1, cc2); err != nil {
			t.Fatalf("parse of marshaled config failed: %v\n%s", err, dt1)
		}
		cfg2, desc2, err := cc2.Marshal(t.Context())
		if err != nil {
			t.Fatalf("re-marshal: %v", err)
		}
		dt2, _ := json.Marshal(cfg2)

		// Exporting the same chains again must give identical bytes.
		cfg1b, _, err := cc.Marshal(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if dt1b, _ := json.Marshal(cfg1b); string(dt1) != string(dt1b) {
			t.Fatalf("export not deterministic\nfirst:  %s\nsecond: %s", dt1, dt1b)
		}

		// Import may normalize some pathological graphs once (alternative
		// links in one input slot are matched as a union), but after that
		// export->import->export must be a fixpoint.
		cc3 := NewCacheChains()
		if err := Parse(dt2, desc2, cc3); err != nil {
			t.Fatalf("parse of re-marshaled config failed: %v\n%s", err, dt2)
		}
		cfg3, _, err := cc3.Marshal(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if dt3, _ := json.Marshal(cfg3); string(dt2) != string(dt3) {
			t.Fatalf("export->import->export not a fixpoint\nsecond: %s\nthird:  %s", dt2, dt3)
		}
	})
}
