package remotecache

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/moby/buildkit/util/contentutil"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

// TestResolveInlineCacheShortHistory imports inline cache from images whose
// config has fewer non-empty history entries than layers. History is optional
// in the image spec. Such images used to panic buildkitd.
func TestResolveInlineCacheShortHistory(t *testing.T) {
	type history = map[string]any
	created := "2024-01-01T00:00:00Z"

	for name, hist := range map[string][]history{
		"none":       nil,
		"short":      {{"created": created, "created_by": "RUN a"}},
		"only empty": {{"created": created, "empty_layer": true}},
		"one per layer": {
			{"created": created, "created_by": "RUN a"},
			{"created": created, "created_by": "RUN b"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := t.Context()
			store := contentutil.NewBuffer()
			put := func(mediaType string, dt []byte) ocispecs.Descriptor {
				desc := ocispecs.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(dt), Size: int64(len(dt))}
				require.NoError(t, content.WriteBlob(ctx, store, desc.Digest.String(), bytes.NewReader(dt), desc))
				return desc
			}
			putJSON := func(mediaType string, v any) ocispecs.Descriptor {
				dt, err := json.Marshal(v)
				require.NoError(t, err)
				return put(mediaType, dt)
			}

			diffIDs := []digest.Digest{digest.FromString("diff0"), digest.FromString("diff1")}
			config := putJSON(ocispecs.MediaTypeImageConfig, map[string]any{
				"rootfs":                 map[string]any{"type": "layers", "diff_ids": diffIDs},
				"history":                hist,
				"moby.buildkit.cache.v0": []byte(`[{"digest":"` + digest.FromString("rec").String() + `","layers":[{"layer":1}]}]`),
			})
			manifest := putJSON(ocispecs.MediaTypeImageManifest, ocispecs.Manifest{
				MediaType: ocispecs.MediaTypeImageManifest,
				Config:    config,
				Layers: []ocispecs.Descriptor{
					put(ocispecs.MediaTypeImageLayerGzip, []byte("layer0")),
					put(ocispecs.MediaTypeImageLayerGzip, []byte("layer1")),
				},
			})
			index := putJSON(ocispecs.MediaTypeImageIndex, ocispecs.Index{
				MediaType: ocispecs.MediaTypeImageIndex,
				Manifests: []ocispecs.Descriptor{manifest},
			})

			ci := &contentCacheImporter{provider: store}
			cm, err := ci.Resolve(ctx, index, "test", nil)
			require.NoError(t, err)
			require.NotNil(t, cm)
		})
	}
}
