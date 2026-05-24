package tables

import (
	"context"
	"fmt"

	"github.com/dh/osquery-cgroup/pkg/cgroup"
	"github.com/osquery/osquery-go/plugin/table"
)

func MemoryColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("path"),
		table.TextColumn("cgroup_name"),
		table.BigIntColumn("memory_current"),
		table.BigIntColumn("memory_max"),
		table.BigIntColumn("memory_peak"),
		table.BigIntColumn("swap_current"),
		table.BigIntColumn("swap_max"),
		table.TextColumn("memory_usage_pct"),
	}
}

func MemoryGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	paths, err := resolvePaths(queryContext, "memory.current")
	if err != nil {
		return nil, err
	}

	var rows []map[string]string
	for _, p := range paths {
		current, err := cgroup.ReadInt(p, "memory.current")
		if err != nil {
			continue
		}
		max, _ := cgroup.ReadInt(p, "memory.max")
		peak, _ := cgroup.ReadInt(p, "memory.peak")
		swapCur, _ := cgroup.ReadInt(p, "memory.swap.current")
		swapMax, _ := cgroup.ReadInt(p, "memory.swap.max")

		var usagePct string
		if max > 0 {
			usagePct = fmt.Sprintf("%.4f", float64(current)/float64(max))
		} else {
			usagePct = "0"
		}

		rows = append(rows, map[string]string{
			"path":              p,
			"cgroup_name":       cgroup.CgroupName(p),
			"memory_current":    fmt.Sprintf("%d", current),
			"memory_max":        fmt.Sprintf("%d", max),
			"memory_peak":       fmt.Sprintf("%d", peak),
			"swap_current":      fmt.Sprintf("%d", swapCur),
			"swap_max":          fmt.Sprintf("%d", swapMax),
			"memory_usage_pct":  usagePct,
		})
	}
	return rows, nil
}
