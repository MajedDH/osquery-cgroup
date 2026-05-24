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
