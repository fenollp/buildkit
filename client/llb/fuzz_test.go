package llb

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/moby/buildkit/solver/pb"
	digest "github.com/opencontainers/go-digest"
	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
)

// buildFromBytes deterministically builds an LLB graph from a byte program.
// Many options are backed by maps or are applied in user order; equivalent
// programs must produce identical definitions, otherwise identical builds
// get different cache keys (cache misses).
func buildFromBytes(prog []byte) State {
	next := func() byte {
		if len(prog) == 0 {
			return 0
		}
		b := prog[0]
		prog = prog[1:]
		return b
	}
	states := []State{Scratch(), Image("docker.io/library/busybox:latest"), Local("ctx")}
	pick := func() State { return states[int(next())%len(states)] }
	for len(prog) > 0 {
		op := next()
		var s State
		switch op % 8 {
		case 0:
			var ro []RunOption
			ro = append(ro, Shlex(fmt.Sprintf("echo %d", next())))
			for i := range int(next() % 6) {
				ro = append(ro, AddEnv(fmt.Sprintf("K%d", (int(next())+i)%5), fmt.Sprintf("v%d", next())))
			}
			for range int(next() % 4) {
				ro = append(ro, AddExtraHost(fmt.Sprintf("h%d", next()%3), net.IPv4(10, 0, 0, next())))
			}
			for range int(next() % 3) {
				ro = append(ro, AddUlimit(UlimitNofile, int64(next()), int64(next())+256))
			}
			if next()&1 != 0 {
				ro = append(ro, AddMount("/m", pick(), Readonly))
			}
			if next()&1 != 0 {
				ro = append(ro, AddSecret("/s", SecretID(fmt.Sprintf("s%d", next()%2))))
			}
			ro = append(ro, Network(pb.NetMode(next()%3)))
			s = pick().Run(ro...).Root()
		case 1:
			s = pick().File(Mkdir(fmt.Sprintf("/d%d", next()%4), os.FileMode(0o700+int(next()%8)), WithParents(true)))
		case 2:
			s = pick().File(Mkfile(fmt.Sprintf("/f%d", next()%4), 0o644, []byte{next()}).Rm("/x", WithAllowNotFound(true)))
		case 3:
			s = pick().File(Copy(pick(), "/", fmt.Sprintf("/c%d", next()%3), &CopyInfo{
				IncludePatterns: []string{"*.go", fmt.Sprintf("p%d", next()%2)},
				ExcludePatterns: []string{"vendor"},
			}))
		case 4:
			s = Merge([]State{pick(), pick(), pick()})
		case 5:
			s = Diff(pick(), pick())
		case 6:
			s = pick().AddEnv(fmt.Sprintf("E%d", next()%4), "x").Dir(fmt.Sprintf("/w%d", next()%3)).User("u")
		case 7:
			s = Image(fmt.Sprintf("docker.io/library/img%d:latest", next()%3), WithCustomName("n"), Platform(ocispecs.Platform{OS: "linux", Architecture: []string{"amd64", "arm64"}[next()%2]}))
		}
		states = append(states, s)
	}
	return states[len(states)-1]
}

func FuzzLLBMarshalDeterminism(f *testing.F) {
	f.Add([]byte{0, 1, 3, 0, 1, 2, 3, 4, 5, 6, 7, 1, 1, 1})
	f.Add([]byte{3, 1, 2, 4, 3, 4, 5, 5, 4, 6, 1, 7, 2, 0, 9, 5, 1, 2, 2, 3, 3, 1, 1, 1, 1})
	f.Add([]byte{0, 5, 5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 3, 1, 2, 3, 4, 5, 6, 1, 1, 2})
	f.Fuzz(func(t *testing.T, prog []byte) {
		if len(prog) > 200 {
			return
		}
		ctx := t.Context()
		var first digest.Digest
		var firstDef []string
		for i := range 4 {
			def, err := buildFromBytes(prog).Marshal(ctx, LocalUniqueID("fuzz"))
			if err != nil {
				return
			}
			dt, err := def.ToPB().Marshal()
			if err != nil {
				t.Fatal(err)
			}
			_ = dt
			if len(def.Def) == 0 {
				return // scratch
			}
			var ops []string
			for _, d := range def.Def {
				ops = append(ops, digest.FromBytes(d).String())
			}
			last := digest.FromBytes(def.Def[len(def.Def)-1])
			if i == 0 {
				first, firstDef = last, ops
				continue
			}
			if last != first {
				t.Fatalf("non-deterministic LLB: run %d head %s != %s\nops0=%v\nops%d=%v", i, last, first, firstDef, i, ops)
			}
			if fmt.Sprint(ops) != fmt.Sprint(firstDef) {
				t.Fatalf("non-deterministic op order: run %d\nops0=%v\nops%d=%v", i, firstDef, i, ops)
			}
		}
	})
}
