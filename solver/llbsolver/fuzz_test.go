package llbsolver

import (
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/solver/pb"
)

// FuzzLoadDefinition feeds an arbitrary (client-controlled) LLB definition
// into the solver loader that turns it into a vertex graph.
func FuzzLoadDefinition(f *testing.F) {
	ctx := f.Context()
	add := func(s llb.State) {
		def, err := s.Marshal(ctx)
		if err != nil {
			f.Fatal(err)
		}
		dt, err := def.ToPB().Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(dt)
	}
	img := llb.Image("docker.io/library/alpine:latest")
	add(img.Run(llb.Shlex("echo hi"), llb.AddEnv("A", "b"), llb.Dir("/w")).Root())
	add(img.File(llb.Mkdir("/a", 0o755).Mkfile("/a/b", 0o644, []byte("x")).Copy(llb.Local("ctx"), "/", "/c")))
	add(llb.Merge([]llb.State{img, llb.Scratch().File(llb.Mkfile("/f", 0o600, nil))}))
	add(llb.Diff(img, img.Run(llb.Shlex("true")).Root()))
	add(llb.Git("https://github.com/moby/buildkit.git", "master").File(llb.Rm("/x")))

	f.Fuzz(func(t *testing.T, dt []byte) {
		var def pb.Definition
		if err := def.Unmarshal(dt); err != nil {
			return
		}
		if len(def.Def) > 64 {
			return
		}
		edge, err := Load(t.Context(), &def, nil)
		if err != nil {
			return
		}
		seen := map[solver.Vertex]struct{}{}
		var walk func(v solver.Vertex)
		walk = func(v solver.Vertex) {
			if _, ok := seen[v]; ok {
				return
			}
			seen[v] = struct{}{}
			_ = v.Digest()
			_ = v.Name()
			_ = v.Options()
			_ = v.Sys()
			for _, in := range v.Inputs() {
				walk(in.Vertex)
			}
		}
		walk(edge.Vertex)
	})
}
