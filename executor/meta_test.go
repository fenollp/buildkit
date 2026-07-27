package executor

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMetaProcessEnv(t *testing.T) {
	t.Parallel()

	env := []string{"PATH=/bin", "FOO=bar"}

	// A process that was not moved anywhere has no OLDPWD to report, the same
	// way a freshly started shell does not.
	m := Meta{Env: env, Cwd: "/a"}
	require.Equal(t, env, m.ProcessEnv())

	m = Meta{Env: env, Cwd: "/b", OldCwd: "/a"}
	require.Equal(t, []string{"PATH=/bin", "FOO=bar", "OLDPWD=/a"}, m.ProcessEnv())
	// The caller's slice is left alone.
	require.Equal(t, []string{"PATH=/bin", "FOO=bar"}, env)

	// A value the build set itself wins, so that it can override or opt out.
	m = Meta{Env: []string{"OLDPWD=/elsewhere"}, Cwd: "/b", OldCwd: "/a"}
	require.Equal(t, []string{"OLDPWD=/elsewhere"}, m.ProcessEnv())

	m = Meta{Env: []string{"OLDPWD="}, Cwd: "/b", OldCwd: "/a"}
	require.Equal(t, []string{"OLDPWD="}, m.ProcessEnv())

	// Valueless entries are names too.
	m = Meta{Env: []string{"OLDPWD"}, Cwd: "/b", OldCwd: "/a"}
	require.Equal(t, []string{"OLDPWD"}, m.ProcessEnv())

	// Names that merely start with OLDPWD are unrelated.
	m = Meta{Env: []string{"OLDPWD_KEEP=1"}, Cwd: "/b", OldCwd: "/a"}
	require.Equal(t, []string{"OLDPWD_KEEP=1", "OLDPWD=/a"}, m.ProcessEnv())
}
