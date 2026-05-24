package tables

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dh/osquery-cgroup/pkg/cgroup"
	"github.com/osquery/osquery-go/plugin/table"
)

// resolvePaths determines which cgroup paths to scan based on the query constraints.
// If a "path" constraint is provided, use it directly. If it contains a wildcard-like
// pattern (ends with %), enumerate matching directories. Otherwise, discover cgroups.
func resolvePaths(queryContext table.QueryContext, requiredFile string) ([]string, error) {
	cl, ok := queryContext.Constraints["path"]
	if ok {
		var paths []string
		for _, c := range cl.Constraints {
			if c.Operator == table.OperatorEquals {
				if _, err := os.Stat(filepath.Join(c.Expression, requiredFile)); err == nil {
					paths = append(paths, c.Expression)
				}
			} else if c.Operator == table.OperatorLike {
				// Handle LIKE patterns: /sys/fs/cgroup/lxc/%
				pattern := strings.TrimSuffix(c.Expression, "%")
				pattern = strings.TrimSuffix(pattern, "/")
				entries, err := os.ReadDir(pattern)
				if err != nil {
					continue
				}
				for _, entry := range entries {
					if !entry.IsDir() {
						continue
					}
					full := filepath.Join(pattern, entry.Name())
					if _, err := os.Stat(filepath.Join(full, requiredFile)); err == nil {
						paths = append(paths, full)
					}
				}
			}
		}
		return paths, nil
	}
	return cgroup.DiscoverCgroups(cgroup.DefaultCgroupRoot)
}
