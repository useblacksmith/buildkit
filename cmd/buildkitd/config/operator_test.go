package config

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func boolPtr(b bool) *bool { return &b }

func ttlPolicy(d time.Duration) GCPolicy {
	return GCPolicy{All: true, KeepDuration: Duration{Duration: d}}
}

func TestApplyOperatorGC(t *testing.T) {
	operator := GCConfig{GC: boolPtr(true), GCPolicy: []GCPolicy{ttlPolicy(192 * time.Hour)}}

	t.Run("applies to gc=false without policy", func(t *testing.T) {
		dst := GCConfig{GC: boolPtr(false)}
		applied, err := ApplyOperatorGC(&dst, operator, true)
		require.NoError(t, err)
		require.True(t, applied)
		require.NotNil(t, dst.GC)
		require.True(t, *dst.GC)
		require.Equal(t, operator.GCPolicy, dst.GCPolicy)
	})

	t.Run("leaves gc=true alone", func(t *testing.T) {
		dst := GCConfig{GC: boolPtr(true)}
		applied, err := ApplyOperatorGC(&dst, operator, true)
		require.NoError(t, err)
		require.False(t, applied)
		require.Empty(t, dst.GCPolicy)
	})

	t.Run("leaves unset gc alone", func(t *testing.T) {
		dst := GCConfig{}
		applied, err := ApplyOperatorGC(&dst, operator, true)
		require.NoError(t, err)
		require.False(t, applied)
		require.Nil(t, dst.GC)
		require.Empty(t, dst.GCPolicy)
	})

	t.Run("never overrides an explicit gcpolicy", func(t *testing.T) {
		own := []GCPolicy{ttlPolicy(24 * time.Hour)}
		dst := GCConfig{GC: boolPtr(false), GCPolicy: own}
		applied, err := ApplyOperatorGC(&dst, operator, true)
		require.NoError(t, err)
		require.False(t, applied)
		require.False(t, *dst.GC)
		require.Equal(t, own, dst.GCPolicy)
	})

	t.Run("empty operator config is a no-op", func(t *testing.T) {
		dst := GCConfig{GC: boolPtr(false)}
		applied, err := ApplyOperatorGC(&dst, GCConfig{}, true)
		require.NoError(t, err)
		require.False(t, applied)
		require.False(t, *dst.GC)
	})

	t.Run("operator gc=false is rejected", func(t *testing.T) {
		dst := GCConfig{GC: boolPtr(false)}
		_, err := ApplyOperatorGC(&dst, GCConfig{GC: boolPtr(false), GCPolicy: operator.GCPolicy}, true)
		require.ErrorContains(t, err, "disables gc")
		require.False(t, *dst.GC)
	})

	t.Run("operator gc without policy is rejected", func(t *testing.T) {
		dst := GCConfig{GC: boolPtr(false)}
		_, err := ApplyOperatorGC(&dst, GCConfig{GC: boolPtr(true)}, true)
		require.ErrorContains(t, err, "without a gcpolicy")
		require.False(t, *dst.GC)
	})

	t.Run("size rule is rejected while pruneInUse", func(t *testing.T) {
		sized := GCConfig{GC: boolPtr(true), GCPolicy: []GCPolicy{
			ttlPolicy(time.Hour),
			{All: true, MaxUsedSpace: DiskSpace{Bytes: 1 << 30}},
		}}
		dst := GCConfig{GC: boolPtr(false)}
		applied, err := ApplyOperatorGC(&dst, sized, true)
		require.ErrorContains(t, err, "gcpolicy[1] is size-based")
		require.False(t, applied)
		require.False(t, *dst.GC)
		require.Empty(t, dst.GCPolicy)
	})

	t.Run("size rule is accepted with pruneInUse=false", func(t *testing.T) {
		sized := GCConfig{GCPolicy: []GCPolicy{{All: true, ReservedSpace: DiskSpace{Percentage: 10}}}}
		dst := GCConfig{GC: boolPtr(false)}
		applied, err := ApplyOperatorGC(&dst, sized, false)
		require.NoError(t, err)
		require.True(t, applied)
		require.True(t, *dst.GC)
		require.Equal(t, sized.GCPolicy, dst.GCPolicy)
	})
}

func TestApplyOperatorGCFromTOML(t *testing.T) {
	const clientConfig = `
[worker.oci]
enabled = true
gc = false
snapshotter = "overlayfs"
`
	const operatorConfig = `
[worker.oci]
gc = true
[[worker.oci.gcpolicy]]
keepDuration = "192h"
all = true
`
	cfg, err := Load(bytes.NewBuffer([]byte(clientConfig)))
	require.NoError(t, err)
	op, err := Load(bytes.NewBuffer([]byte(operatorConfig)))
	require.NoError(t, err)

	pruneInUse := cfg.Workers.OCI.PruneInUse == nil || *cfg.Workers.OCI.PruneInUse
	applied, err := ApplyOperatorGC(&cfg.Workers.OCI.GCConfig, op.Workers.OCI.GCConfig, pruneInUse)
	require.NoError(t, err)
	require.True(t, applied)
	require.True(t, *cfg.Workers.OCI.GC)
	require.Len(t, cfg.Workers.OCI.GCPolicy, 1)
	require.Equal(t, 192*time.Hour, cfg.Workers.OCI.GCPolicy[0].KeepDuration.Duration)
	require.True(t, cfg.Workers.OCI.GCPolicy[0].All)
	require.Equal(t, "overlayfs", cfg.Workers.OCI.Snapshotter)

	// the operator file says nothing about containerd, so that worker is untouched
	applied, err = ApplyOperatorGC(&cfg.Workers.Containerd.GCConfig, op.Workers.Containerd.GCConfig, true)
	require.NoError(t, err)
	require.False(t, applied)
}
