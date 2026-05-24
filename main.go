package main

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dh/osquery-cgroup/pkg/tables"
	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

// parseArgs parses flags manually to avoid crashing on unknown flags
// that osquery passes to extensions (e.g. --verbose).
func parseArgs() (socket string, timeout, interval int) {
	timeout = 3
	interval = 3
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		var key, val string
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			key = strings.TrimLeft(parts[0], "-")
			val = parts[1]
		} else if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
			key = strings.TrimLeft(arg, "-")
			val = os.Args[i+1]
			i++
		} else {
			continue
		}
		switch key {
		case "socket":
			socket = val
		case "timeout":
			timeout, _ = strconv.Atoi(val)
		case "interval":
			interval, _ = strconv.Atoi(val)
		}
	}
	return
}

func main() {
	socket, timeout, interval := parseArgs()

	if socket == "" {
		log.Fatal("--socket flag is required")
	}

	if timeout < 10 {
		timeout = 10
	}

	// Retry connection to osquery socket — it may not be ready immediately
	var server *osquery.ExtensionManagerServer
	var err error
	deadline := time.Now().Add(time.Duration(timeout) * time.Second)
	for {
		server, err = osquery.NewExtensionManagerServer(
			"cgroup",
			socket,
			osquery.ServerTimeout(time.Duration(timeout)*time.Second),
			osquery.ServerPingInterval(time.Duration(interval)*time.Second),
		)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("Error creating extension manager: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}

	server.RegisterPlugin(
		table.NewPlugin("cgroup_memory", tables.MemoryColumns(), tables.MemoryGenerate),
		table.NewPlugin("cgroup_cpu", tables.CPUColumns(), tables.CPUGenerate),
		table.NewPlugin("cgroup_io", tables.IOColumns(), tables.IOGenerate),
		table.NewPlugin("cgroup_pressure", tables.PressureColumns(), tables.PressureGenerate),
		table.NewPlugin("cgroup_pids", tables.PIDsColumns(), tables.PIDsGenerate),
	)

	if err := server.Run(); err != nil {
		log.Fatalf("Error running extension: %v", err)
	}
}
