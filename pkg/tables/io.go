package tables

import (
	"context"
	"fmt"
	"strings"

	"github.com/dh/osquery-cgroup/pkg/cgroup"
	"github.com/osquery/osquery-go/plugin/table"
)

func IOColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("path"),
		table.TextColumn("cgroup_name"),
		table.BigIntColumn("device_major"),
		table.BigIntColumn("device_minor"),
		table.BigIntColumn("rbytes"),
		table.BigIntColumn("wbytes"),
		table.BigIntColumn("rios"),
		table.BigIntColumn("wios"),
		table.BigIntColumn("dbytes"),
		table.BigIntColumn("dios"),
	}
}

func IOGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	paths, err := resolvePaths(queryContext, "io.stat")
	if err != nil {
		return nil, err
	}

	var rows []map[string]string
	for _, p := range paths {
		content, err := cgroup.ReadFile(p, "io.stat")
		if err != nil {
			continue
		}
		name := cgroup.CgroupName(p)
		for _, line := range strings.Split(content, "\n") {
			if line == "" {
				continue
			}
			major, minor, stats, err := cgroup.ParseIOStatLine(line)
			if err != nil {
				continue
			}
			rows = append(rows, map[string]string{
				"path":         p,
				"cgroup_name":  name,
				"device_major": fmt.Sprintf("%d", major),
				"device_minor": fmt.Sprintf("%d", minor),
				"rbytes":       fmt.Sprintf("%d", stats["rbytes"]),
				"wbytes":       fmt.Sprintf("%d", stats["wbytes"]),
				"rios":         fmt.Sprintf("%d", stats["rios"]),
				"wios":         fmt.Sprintf("%d", stats["wios"]),
				"dbytes":       fmt.Sprintf("%d", stats["dbytes"]),
				"dios":         fmt.Sprintf("%d", stats["dios"]),
			})
		}
	}
	return rows, nil
}
