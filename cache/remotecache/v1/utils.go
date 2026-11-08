package cacheimport

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	cerrdefs "github.com/containerd/errdefs"
	cacheimporttypes "github.com/moby/buildkit/cache/remotecache/v1/types"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/compression"
	digest "github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

// sortConfig sorts the config structure to make sure it is deterministic
func sortConfig(cc *cacheimporttypes.CacheConfig) {
	type indexedLayer struct {
		oldIndex int
		newIndex int
		l        cacheimporttypes.CacheLayer
	}

	unsortedLayers := make([]*indexedLayer, len(cc.Layers))
	sortedLayers := make([]*indexedLayer, len(cc.Layers))

	for i, l := range cc.Layers {
		il := &indexedLayer{oldIndex: i, l: l}
		unsortedLayers[i] = il
		sortedLayers[i] = il
	}
	// ParentIndex refers to the unsorted (insertion) order, so it can't be
	// used as a tie-breaker. Compare the full blob chain from the root
	// instead, which identifies a layer independently of insertion order.
	chains := make([][]digest.Digest, len(cc.Layers))
	var chainOf func(i int, depth int) []digest.Digest
	chainOf = func(i int, depth int) []digest.Digest {
		if chains[i] != nil {
			return chains[i]
		}
		var c []digest.Digest
		if p := cc.Layers[i].ParentIndex; p >= 0 && p < len(cc.Layers) && depth < len(cc.Layers) {
			c = slices.Clone(chainOf(p, depth+1))
		}
		c = append(c, cc.Layers[i].Blob)
		chains[i] = c
		return c
	}
	for i := range cc.Layers {
		chainOf(i, 0)
	}
	slices.SortStableFunc(sortedLayers, func(a, b *indexedLayer) int {
		return cmp.Or(cmp.Compare(a.l.Blob, b.l.Blob), slices.Compare(chains[a.oldIndex], chains[b.oldIndex]))
	})
	for i, l := range sortedLayers {
		l.newIndex = i
	}

	layers := make([]cacheimporttypes.CacheLayer, len(sortedLayers))
	for i, l := range sortedLayers {
		if pID := l.l.ParentIndex; pID != -1 {
			l.l.ParentIndex = unsortedLayers[pID].newIndex
		}
		layers[i] = l.l
	}

	type indexedRecord struct {
		oldIndex int
		newIndex int
		r        cacheimporttypes.CacheRecord
	}

	unsortedRecords := make([]*indexedRecord, len(cc.Records))
	sortedRecords := make([]*indexedRecord, len(cc.Records))

	// Several records can share a digest (a cache record digest does not
	// include its inputs, e.g. the same RUN on different bases), and their
	// inputs can in turn share digests. Comparing one level deep leaves ties
	// whose order depends on map iteration, so records are ordered by a
	// structural key covering the whole input subgraph and the results.
	// Inputs are collected from map iteration too, so they are canonicalized
	// by the same key.
	keys := make([]string, len(cc.Records))
	const inProgress = "\x00"
	var keyOf func(i int) string
	keyOf = func(i int) string {
		if keys[i] == inProgress {
			// cycles can't come out of Marshal; be defensive anyway
			return cc.Records[i].Digest.String()
		}
		if keys[i] != "" {
			return keys[i]
		}
		keys[i] = inProgress
		r := cc.Records[i]
		var b []byte
		b = fmt.Appendf(b, "%s|", r.Digest)
		for _, inputs := range r.Inputs {
			in := make([]string, 0, len(inputs))
			for _, inp := range inputs {
				src := ""
				if inp.LinkIndex >= 0 && inp.LinkIndex < len(cc.Records) {
					src = keyOf(inp.LinkIndex)
				}
				in = append(in, inp.Selector+"@"+src)
			}
			slices.Sort(in)
			b = fmt.Appendf(b, "[%v]", in)
		}
		for _, res := range r.Results {
			var chain []digest.Digest
			if res.LayerIndex >= 0 && res.LayerIndex < len(chains) {
				chain = chains[res.LayerIndex]
			}
			b = fmt.Appendf(b, "<%v@%d>", chain, res.CreatedAt.UnixNano())
		}
		keys[i] = digest.FromBytes(b).String()
		return keys[i]
	}
	for i := range cc.Records {
		keyOf(i)
	}

	for _, r := range cc.Records {
		for _, inputs := range r.Inputs {
			slices.SortStableFunc(inputs, func(a, b cacheimporttypes.CacheInput) int {
				return cmp.Or(
					cmp.Compare(a.Selector, b.Selector),
					cmp.Compare(keys[a.LinkIndex], keys[b.LinkIndex]),
				)
			})
		}
	}

	for i, r := range cc.Records {
		ir := &indexedRecord{oldIndex: i, r: r}
		unsortedRecords[i] = ir
		sortedRecords[i] = ir
	}
	slices.SortStableFunc(sortedRecords, func(a, b *indexedRecord) int {
		return cmp.Or(
			cmp.Compare(a.r.Digest, b.r.Digest),
			cmp.Compare(len(a.r.Inputs), len(b.r.Inputs)),
			cmp.Compare(keys[a.oldIndex], keys[b.oldIndex]),
		)
	})
	// Structurally identical records (same key) can't be told apart, so
	// whichever of them a link points to would depend on insertion order.
	// Collapse them into one record: this keeps the output deterministic
	// and the config smaller.
	newIndexByKey := map[string]int{}
	n := 0
	for _, l := range sortedRecords {
		if idx, ok := newIndexByKey[keys[l.oldIndex]]; ok {
			l.newIndex = idx
			continue
		}
		l.newIndex = n
		newIndexByKey[keys[l.oldIndex]] = n
		n++
	}

	records := make([]cacheimporttypes.CacheRecord, 0, n)
	for _, r := range sortedRecords {
		if r.newIndex < len(records) {
			continue // duplicate of an already emitted record
		}
		for j := range r.r.Results {
			r.r.Results[j].LayerIndex = unsortedLayers[r.r.Results[j].LayerIndex].newIndex
		}
		for j, inputs := range r.r.Inputs {
			for k := range inputs {
				inputs[k].LinkIndex = unsortedRecords[inputs[k].LinkIndex].newIndex
			}
			slices.SortFunc(inputs, func(a, b cacheimporttypes.CacheInput) int {
				return cmp.Or(cmp.Compare(a.LinkIndex, b.LinkIndex), cmp.Compare(a.Selector, b.Selector))
			})
			r.r.Inputs[j] = slices.Compact(inputs)
		}
		records = append(records, r.r)
	}

	cc.Layers = layers
	cc.Records = records
}

func outputKey(dgst digest.Digest, idx int) digest.Digest {
	return digest.FromBytes(fmt.Appendf(nil, "%s@%d", dgst, idx))
}

type nlink struct {
	dgst     digest.Digest
	input    int
	selector string
}

type marshalState struct {
	layers      []cacheimporttypes.CacheLayer
	chainsByID  map[string]int
	descriptors DescriptorProvider

	records       []cacheimporttypes.CacheRecord
	recordsByItem map[*item]int
}

func marshalRemote(ctx context.Context, r *solver.Remote, state *marshalState) string {
	if len(r.Descriptors) == 0 {
		return ""
	}

	if r.Provider != nil {
		for _, d := range r.Descriptors {
			if _, err := r.Provider.Info(ctx, d.Digest); err != nil && !cerrdefs.IsNotImplemented(err) {
				bklog.G(ctx).WithError(err).Warnf("skipping cache result: blob %s is not available", d.Digest)
				return ""
			}
		}
	}

	var parentID string
	for _, desc := range r.Descriptors {
		if desc.MediaType != "" {
			desc = compression.ConvertAllLayerMediaTypes(ctx, true, desc)[0]
		}

		state.descriptors[desc.Digest] = DescriptorProviderPair{
			Descriptor: desc,
			Provider:   r.Provider,
		}

		id := desc.Digest.String() + parentID

		if _, ok := state.chainsByID[id]; !ok {
			state.chainsByID[id] = len(state.layers)
			l := cacheimporttypes.CacheLayer{
				Blob:        desc.Digest,
				ParentIndex: -1,
			}
			if parentID != "" {
				l.ParentIndex = state.chainsByID[parentID]
			}
			state.layers = append(state.layers, l)
		}
		parentID = id
	}
	return parentID
}

func marshalItem(ctx context.Context, it *item, state *marshalState) error {
	if _, ok := state.recordsByItem[it]; ok {
		return nil
	}
	state.recordsByItem[it] = -1

	rec := cacheimporttypes.CacheRecord{
		Digest: it.dgst,
		Inputs: make([][]cacheimporttypes.CacheInput, len(it.parents)),
	}

	for i, m := range it.parents {
		for l := range m {
			if err := marshalItem(ctx, l.src, state); err != nil {
				return err
			}
			idx, ok := state.recordsByItem[l.src]
			if !ok {
				return errors.Errorf("invalid source record: %v", l.src)
			}
			if idx == -1 {
				continue
			}
			rec.Inputs[i] = append(rec.Inputs[i], cacheimporttypes.CacheInput{
				Selector:  l.selector,
				LinkIndex: idx,
			})
		}
	}

	if res := it.bestResult(); res != nil {
		id := marshalRemote(ctx, res.Result, state)
		if id != "" {
			idx, ok := state.chainsByID[id]
			if !ok {
				return errors.New("parent chainid not found")
			}
			rec.Results = append(rec.Results, cacheimporttypes.CacheResult{LayerIndex: idx, CreatedAt: res.CreatedAt})
		}
	}

	state.recordsByItem[it] = len(state.records)
	state.records = append(state.records, rec)
	return nil
}

func isSubRemote(sub, main solver.Remote) bool {
	if len(sub.Descriptors) > len(main.Descriptors) {
		return false
	}
	for i := range sub.Descriptors {
		if sub.Descriptors[i].Digest != main.Descriptors[i].Digest {
			return false
		}
	}
	return true
}
