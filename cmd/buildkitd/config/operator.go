package config

import (
	"github.com/pkg/errors"
)

// ApplyOperatorGC fills in a worker's garbage collection settings from an
// operator-provided floor when, and only when, the worker's own config has
// explicitly disabled GC without declaring a policy (`gc = false` and no
// `gcpolicy`). Any other shape is left untouched: an explicit gcpolicy, or gc
// left enabled, is the config author's decision and is never overridden.
//
// An operator floor that carries size-based rules (reservedSpace,
// maxUsedSpace, minFreeSpace or the deprecated keepBytes) is refused while
// pruneInUse is in effect, because a size-bounded prune with pruneInUse may
// remove records that still have live refs. Only a time-based floor
// (keepDuration) is safe to impose on a config that did not opt out of
// pruneInUse.
//
// The bool reports whether dst was modified. A non-nil error means the
// operator floor was present but could not be applied; dst is unchanged.
func ApplyOperatorGC(dst *GCConfig, op GCConfig, pruneInUse bool) (bool, error) {
	if op.GC == nil && len(op.GCPolicy) == 0 {
		return false, nil
	}
	if op.GC != nil && !*op.GC {
		return false, errors.New("operator config disables gc")
	}
	if len(op.GCPolicy) == 0 {
		return false, errors.New("operator config enables gc without a gcpolicy")
	}
	if dst.GC == nil || *dst.GC || len(dst.GCPolicy) > 0 {
		return false, nil
	}
	if pruneInUse {
		for i, rule := range op.GCPolicy {
			if hasSizeRule(rule) {
				return false, errors.Errorf("operator gcpolicy[%d] is size-based, which requires pruneInUse = false", i)
			}
		}
	}

	enabled := true
	dst.GC = &enabled
	dst.GCPolicy = append([]GCPolicy(nil), op.GCPolicy...)
	return true, nil
}

func hasSizeRule(rule GCPolicy) bool {
	return rule.KeepBytes != (DiskSpace{}) ||
		rule.ReservedSpace != (DiskSpace{}) ||
		rule.MaxUsedSpace != (DiskSpace{}) ||
		rule.MinFreeSpace != (DiskSpace{})
}
