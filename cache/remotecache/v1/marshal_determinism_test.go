package cacheimport

import (
	"encoding/json"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/moby/buildkit/solver"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// TestMarshalDeterministic builds cache chains with the ties sortConfig has
// to break (links differing only by selector, records sharing a digest at
// several levels, layers sharing a blob) and checks that marshaling gives
// identical bytes every time.
func TestMarshalDeterministic(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	remote := func(blobs ...string) []solver.CacheExportResult {
		r := &solver.Remote{}
		for _, b := range blobs {
			r.Descriptors = append(r.Descriptors, ocispecs.Descriptor{
				Digest:    dgst(b),
				MediaType: ocispecs.MediaTypeImageLayerGzip,
				Size:      1,
			})
		}
		return []solver.CacheExportResult{{CreatedAt: now, Result: r}}
	}
	build := func() *CacheChains {
		cc := NewCacheChains()
		add := func(d string, deps [][]solver.CacheLink, res []solver.CacheExportResult) solver.CacheExporterRecord {
			r, _, err := cc.Add(outputKey(dgst(d), 0), deps, res)
			require.NoError(t, err)
			return r
		}
		foo := add("foo", nil, nil)
		bar := add("bar", nil, nil)
		// links to the same record that differ only by selector
		add("sel", [][]solver.CacheLink{{{Src: foo}, {Src: foo, Selector: "sel1"}}}, remote("l0"))
		// same op on different bases, and again on top of those
		x := add("run", [][]solver.CacheLink{{{Src: foo}}}, nil)
		y := add("run", [][]solver.CacheLink{{{Src: bar}}}, nil)
		add("run2", [][]solver.CacheLink{{{Src: x}}}, remote("l0", "l1"))
		add("run2", [][]solver.CacheLink{{{Src: y}}}, remote("l1", "l0"))
		add("run3", [][]solver.CacheLink{{{Src: x}}, {{Src: y}}}, remote("l1"))
		return cc
	}

	var first string
	for i := range 100 {
		cfg, _, err := build().Marshal(t.Context())
		require.NoError(t, err)
		dt, err := json.Marshal(cfg)
		require.NoError(t, err)
		if i == 0 {
			first = string(dt)
			continue
		}
		require.Equal(t, first, string(dt), "iteration %d", i)
	}
}

// TestSortConfigIgnoresInputOrder gives sortConfig the same config with layers,
// records and inputs in many different orders, and checks it always produces
// the same bytes. Each case is a tie that a shallow comparison can't break.
func TestSortConfigIgnoresInputOrder(t *testing.T) {
	type (
		layer  = cacheimporttypes.CacheLayer
		record = cacheimporttypes.CacheRecord
		result = cacheimporttypes.CacheResult
		inputs = [][]cacheimporttypes.CacheInput
	)
	link := func(i int) []cacheimporttypes.CacheInput {
		return []cacheimporttypes.CacheInput{{LinkIndex: i}}
	}

	for name, tc := range map[string]struct {
		layers      []layer
		records     []record
		wantRecords int
	}{
		"layers with same blob on different parents": {
			layers: []layer{
				{Blob: dgst("a"), ParentIndex: -1},
				{Blob: dgst("b"), ParentIndex: -1},
				{Blob: dgst("x"), ParentIndex: 0},
				{Blob: dgst("x"), ParentIndex: 1},
			},
			records: []record{
				{Digest: dgst("r1"), Results: []result{{LayerIndex: 2}}},
				{Digest: dgst("r2"), Results: []result{{LayerIndex: 3}}},
			},
			wantRecords: 2,
		},
		"records with same digest and different results": {
			layers: []layer{
				{Blob: dgst("a"), ParentIndex: -1},
				{Blob: dgst("b"), ParentIndex: -1},
			},
			records: []record{
				{Digest: dgst("r"), Results: []result{{LayerIndex: 0}}},
				{Digest: dgst("r"), Results: []result{{LayerIndex: 1}}},
			},
			wantRecords: 2,
		},
		"records differing only two levels down": {
			records: []record{
				{Digest: dgst("foo")},
				{Digest: dgst("bar")},
				{Digest: dgst("run"), Inputs: inputs{link(0)}},
				{Digest: dgst("run"), Inputs: inputs{link(1)}},
				{Digest: dgst("run2"), Inputs: inputs{link(2)}},
				{Digest: dgst("run2"), Inputs: inputs{link(3)}},
			},
			wantRecords: 6,
		},
		"identical records are collapsed": {
			records: []record{
				{Digest: dgst("foo")},
				{Digest: dgst("run"), Inputs: inputs{link(0)}},
				{Digest: dgst("run"), Inputs: inputs{link(0)}},
				{Digest: dgst("next"), Inputs: inputs{{{LinkIndex: 1}, {LinkIndex: 2}}}},
			},
			wantRecords: 3,
		},
	} {
		t.Run(name, func(t *testing.T) {
			rng := rand.New(rand.NewPCG(1, 2))
			var first string
			for i := range 200 {
				cfg := shuffledConfig(rng, tc.layers, tc.records)
				sortConfig(&cfg)
				require.Len(t, cfg.Records, tc.wantRecords)
				for _, r := range cfg.Records {
					for _, in := range r.Inputs {
						require.Len(t, slices.Compact(slices.Clone(in)), len(in), "duplicate inputs in %s", r.Digest)
					}
				}
				dt, err := json.Marshal(cfg)
				require.NoError(t, err)
				if i == 0 {
					first = string(dt)
					continue
				}
				require.Equal(t, first, string(dt), "iteration %d", i)
			}
		})
	}
}

// shuffledConfig returns a copy of the given layers and records in random
// order, with all indexes pointing to the same elements as before.
func shuffledConfig(rng *rand.Rand, layers []cacheimporttypes.CacheLayer, records []cacheimporttypes.CacheRecord) cacheimporttypes.CacheConfig {
	layerPos, recordPos := rng.Perm(len(layers)), rng.Perm(len(records))
	cfg := cacheimporttypes.CacheConfig{
		Layers:  make([]cacheimporttypes.CacheLayer, len(layers)),
		Records: make([]cacheimporttypes.CacheRecord, len(records)),
	}
	for i, l := range layers {
		if l.ParentIndex != -1 {
			l.ParentIndex = layerPos[l.ParentIndex]
		}
		cfg.Layers[layerPos[i]] = l
	}
	for i, r := range records {
		r.Results = slices.Clone(r.Results)
		for j := range r.Results {
			r.Results[j].LayerIndex = layerPos[r.Results[j].LayerIndex]
		}
		r.Inputs = slices.Clone(r.Inputs)
		for j := range r.Inputs {
			r.Inputs[j] = slices.Clone(r.Inputs[j])
			for k := range r.Inputs[j] {
				r.Inputs[j][k].LinkIndex = recordPos[r.Inputs[j][k].LinkIndex]
			}
			rng.Shuffle(len(r.Inputs[j]), func(a, b int) {
				r.Inputs[j][a], r.Inputs[j][b] = r.Inputs[j][b], r.Inputs[j][a]
			})
		}
		cfg.Records[recordPos[i]] = r
	}
	return cfg
}
