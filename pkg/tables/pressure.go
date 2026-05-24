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

func PressureColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("path"),
		table.TextColumn("cgroup_name"),
		table.TextColumn("resource"),
		table.TextColumn("some_avg10"),
		table.TextColumn("some_avg60"),
		table.TextColumn("some_avg300"),
		table.BigIntColumn("some_total"),
		table.TextColumn("full_avg10"),
		table.TextColumn("full_avg60"),
		table.TextColumn("full_avg300"),
		table.BigIntColumn("full_total"),
	}
}

func PressureGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	paths, err := resolvePaths(queryContext, "cpu.pressure")
	if err != nil {
		return nil, err
	}

	resources := []string{"cpu", "memory", "io"}

	var rows []map[string]string
	for _, p := range paths {
		name := cgroup.CgroupName(p)
		for _, res := range resources {
			content, err := cgroup.ReadFile(p, res+".pressure")
			if err != nil {
				continue
			}
			row := map[string]string{
				"path":        p,
				"cgroup_name": name,
				"resource":    res,
			}
			for _, line := range strings.Split(content, "\n") {
				if line == "" {
					continue
				}
				avg10, avg60, avg300, total, err := cgroup.ParsePressureLine(line)
				if err != nil {
					continue
				}
				prefix := strings.Fields(line)[0]
				if prefix == "some" {
					row["some_avg10"] = fmt.Sprintf("%.2f", avg10)
					row["some_avg60"] = fmt.Sprintf("%.2f", avg60)
					row["some_avg300"] = fmt.Sprintf("%.2f", avg300)
					row["some_total"] = fmt.Sprintf("%d", total)
				} else if prefix == "full" {
					row["full_avg10"] = fmt.Sprintf("%.2f", avg10)
					row["full_avg60"] = fmt.Sprintf("%.2f", avg60)
					row["full_avg300"] = fmt.Sprintf("%.2f", avg300)
					row["full_total"] = fmt.Sprintf("%d", total)
				}
			}
			rows = append(rows, row)
		}
	}
	return rows, nil
}
