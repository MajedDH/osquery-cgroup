// Copyright 2026 MajedDH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
