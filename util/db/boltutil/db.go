package boltutil

import (
	"io/fs"
	"sync"

	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/db"
	bolt "go.etcd.io/bbolt"
)

// syncingDB wraps a bolt.DB to ensure data is synced to disk before closing.
// This is important when using NoSync mode, as otherwise dirty pages may not
// be flushed to disk before unmount, leading to corruption on network block
// devices or when taking filesystem snapshots.
type syncingDB struct {
	*bolt.DB
	closeOnce sync.Once
	closeErr  error
}

// Close syncs the database to disk before closing.
// This ensures all pending writes are flushed even when NoSync is enabled,
// preventing corruption during graceful shutdown. Safe to call multiple times.
func (s *syncingDB) Close() error {
	s.closeOnce.Do(func() {
		if err := s.Sync(); err != nil {
			bklog.L.Warnf("failed to sync database before close: %v", err)
		}
		s.closeErr = s.DB.Close()
	})
	return s.closeErr
}

func Open(p string, mode fs.FileMode, options *bolt.Options) (db.DB, error) {
	bdb, err := bolt.Open(p, mode, options)
	if err != nil {
		return nil, err
	}
	return &syncingDB{DB: bdb}, nil
}
