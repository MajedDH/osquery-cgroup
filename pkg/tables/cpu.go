// Copyright 2026 Majed Al-Daas
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
	"strings"

	"github.com/dh/osquery-cgroup/pkg/cgroup"
	"github.com/osquery/osquery-go/plugin/table"
)

func CPUColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("path"),
		table.TextColumn("cgroup_name"),
		table.BigIntColumn("usage_usec"),
		table.BigIntColumn("user_usec"),
		table.BigIntColumn("system_usec"),
		table.BigIntColumn("nr_throttled"),
		table.BigIntColumn("throttled_usec"),
		table.BigIntColumn("cpu_max_quota"),
		table.BigIntColumn("cpu_max_period"),
		table.TextColumn("cpus_effective"),
	}
}

func CPUGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	paths, err := resolvePaths(queryContext, "cpu.stat")
	if err != nil {
		return nil, err
	}

	var rows []map[string]string
	for _, p := range paths {
		kv, err := cgroup.ReadKV(p, "cpu.stat")
		if err != nil {
			continue
		}

		// Parse cpu.max: "quota period" or "max period"
		var quota int64 = -1
		var period int64 = 100000
		if cpuMax, err := cgroup.ReadFile(p, "cpu.max"); err == nil {
			parts := strings.Fields(cpuMax)
			if len(parts) == 2 {
				if parts[0] == "max" {
					quota = -1
				} else {
					fmt.Sscanf(parts[0], "%d", &quota)
				}
				fmt.Sscanf(parts[1], "%d", &period)
			}
		}

		cpusEffective, _ := cgroup.ReadFile(p, "cpuset.cpus.effective")

		rows = append(rows, map[string]string{
			"path":            p,
			"cgroup_name":     cgroup.CgroupName(p),
			"usage_usec":      fmt.Sprintf("%d", kv["usage_usec"]),
			"user_usec":       fmt.Sprintf("%d", kv["user_usec"]),
			"system_usec":     fmt.Sprintf("%d", kv["system_usec"]),
			"nr_throttled":    fmt.Sprintf("%d", kv["nr_throttled"]),
			"throttled_usec":  fmt.Sprintf("%d", kv["throttled_usec"]),
			"cpu_max_quota":   fmt.Sprintf("%d", quota),
			"cpu_max_period":  fmt.Sprintf("%d", period),
			"cpus_effective":  cpusEffective,
		})
	}
	return rows, nil
}
