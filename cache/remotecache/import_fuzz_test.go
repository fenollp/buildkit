package remotecache

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	cerrdefs "github.com/containerd/errdefs"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

type fuzzBlobProvider map[digest.Digest][]byte

type fuzzReaderAt struct{ *bytes.Reader }

func (fuzzReaderAt) Close() error { return nil }

func (p fuzzBlobProvider) ReaderAt(_ context.Context, desc ocispecs.Descriptor) (content.ReaderAt, error) {
	dt, ok := p[desc.Digest]
	if !ok {
		return nil, cerrdefs.ErrNotFound
	}
	return fuzzReaderAt{bytes.NewReader(dt)}, nil
}

// buildBlobs substitutes "@N" placeholders in blob i with "<digest>" and
// "#N" with the size of blob N, for N > i. Processing from the last blob
// backwards yields a content-addressed DAG like a real registry would serve.
func buildBlobs(raw [][]byte) ([]digest.Digest, fuzzBlobProvider) {
	p := fuzzBlobProvider{}
	dgsts := make([]digest.Digest, len(raw))
	blobs := make([][]byte, len(raw))
	for i := len(raw) - 1; i >= 0; i-- {
		dt := raw[i]
		for j := len(raw) - 1; j > i; j-- {
			dt = bytes.ReplaceAll(dt, fmt.Appendf(nil, "@%d", j), []byte(dgsts[j]))
			dt = bytes.ReplaceAll(dt, fmt.Appendf(nil, "#%d", j), fmt.Appendf(nil, "%d", len(blobs[j])))
		}
		blobs[i] = dt
		dgsts[i] = digest.FromBytes(dt)
		p[dgsts[i]] = dt
	}
	return dgsts, p
}

// FuzzImporterResolve fuzzes the remote cache import path used by the
// registry, local, gha, s3 and azblob cache importers: a root manifest or
// index, an optional cache config blob, and inline cache in image configs.
func FuzzImporterResolve(f *testing.F) {
	const (
		cfg   = `{"layers":[{"blob":"@3","parent":-1}],"records":[{"digest":"sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","layers":[{"layer":0}]},{"digest":"sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03","inputs":[[{"link":0}]]}]}`
		layer = "layerdata"
	)
	// index (registry cache, mode=max) -> cache config + layer
	f.Add(
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"@3","size":#3},{"mediaType":"application/vnd.buildkit.cacheconfig.v0","digest":"@1","size":#1}]}`),
		[]byte(cfg), []byte(""), []byte(layer))
	// image manifest with cache config as config
	f.Add(
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.buildkit.cacheconfig.v0","digest":"@1","size":#1},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"@3","size":#3}]}`),
		[]byte(cfg), []byte(""), []byte(layer))
	// inline cache: index -> manifest -> image config with moby.buildkit.cache.v0
	f.Add(
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"@1","size":#1}]}`),
		[]byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"@2","size":#2},"layers":[{"mediaType":"application/vnd.oci.image.layer.v1.tar+gzip","digest":"@3","size":#3}]}`),
		[]byte(`{"rootfs":{"type":"layers","diff_ids":["sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]},"history":[{"created":"2024-01-01T00:00:00Z","created_by":"RUN x"}],"moby.buildkit.cache.v0":"W3siZGlnZXN0Ijoic2hhMjU2OmUzYjBjNDQyOThmYzFjMTQ5YWZiZjRjODk5NmZiOTI0MjdhZTQxZTQ2NDliOTM0Y2E0OTU5OTFiNzg1MmI4NTUiLCJsYXllcnMiOlt7ImxheWVyIjowfV19XQ=="}`),
		[]byte(layer))

	f.Fuzz(func(t *testing.T, root, b1, b2, b3 []byte) {
		dgsts, p := buildBlobs([][]byte{root, b1, b2, b3})
		ci := &contentCacheImporter{provider: p}
		desc := ocispecs.Descriptor{Digest: dgsts[0], Size: int64(len(p[dgsts[0]]))}
		cm, err := ci.Resolve(t.Context(), desc, "fuzz", nil)
		if err != nil || cm == nil {
			return
		}
		_ = cm.ID()
	})
}
