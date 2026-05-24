package tables

import (
	"context"
	"fmt"

	"github.com/dh/osquery-cgroup/pkg/cgroup"
	"github.com/osquery/osquery-go/plugin/table"
)

func PIDsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("path"),
		table.TextColumn("cgroup_name"),
		table.BigIntColumn("pids_current"),
		table.BigIntColumn("pids_max"),
		table.BigIntColumn("pids_peak"),
	}
}

func PIDsGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	paths, err := resolvePaths(queryContext, "pids.current")
	if err != nil {
		return nil, err
	}

	var rows []map[string]string
	for _, p := range paths {
		current, err := cgroup.ReadInt(p, "pids.current")
		if err != nil {
			continue
		}
		max, _ := cgroup.ReadInt(p, "pids.max")
		peak, _ := cgroup.ReadInt(p, "pids.peak")

		rows = append(rows, map[string]string{
			"path":         p,
			"cgroup_name":  cgroup.CgroupName(p),
			"pids_current": fmt.Sprintf("%d", current),
			"pids_max":     fmt.Sprintf("%d", max),
			"pids_peak":    fmt.Sprintf("%d", peak),
		})
	}
	return rows, nil
}
