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

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const DefaultCgroupRoot = "/sys/fs/cgroup"

// ReadFile reads a cgroup virtual file and returns its trimmed content.
func ReadFile(cgroupPath, filename string) (string, error) {
	data, err := os.ReadFile(filepath.Join(cgroupPath, filename))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// ReadInt reads a cgroup file and parses it as int64.
// Returns -1 if the content is "max".
func ReadInt(cgroupPath, filename string) (int64, error) {
	s, err := ReadFile(cgroupPath, filename)
	if err != nil {
		return 0, err
	}
	if s == "max" {
		return -1, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

// ReadKV reads a cgroup file with "key value" lines and returns a map.
// Used for cpu.stat, memory.stat, etc.
func ReadKV(cgroupPath, filename string) (map[string]int64, error) {
	s, err := ReadFile(cgroupPath, filename)
	if err != nil {
		return nil, err
	}
	result := make(map[string]int64)
	for _, line := range strings.Split(s, "\n") {
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		val, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		result[parts[0]] = val
	}
	return result, nil
}

// ParsePressureLine parses a PSI line like:
// "some avg10=0.00 avg60=0.01 avg300=0.00 total=609442977"
func ParsePressureLine(line string) (avg10, avg60, avg300 float64, total int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 5 {
		return 0, 0, 0, 0, fmt.Errorf("unexpected pressure format: %s", line)
	}
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "avg10":
			avg10, err = strconv.ParseFloat(kv[1], 64)
		case "avg60":
			avg60, err = strconv.ParseFloat(kv[1], 64)
		case "avg300":
			avg300, err = strconv.ParseFloat(kv[1], 64)
		case "total":
			total, err = strconv.ParseInt(kv[1], 10, 64)
		}
		if err != nil {
			return
		}
	}
	return
}

// ParseIOStatLine parses an io.stat line like:
// "259:6 rbytes=693116620800 wbytes=0 rios=18852056 wios=0 dbytes=0 dios=0"
func ParseIOStatLine(line string) (major, minor int64, stats map[string]int64, err error) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return 0, 0, nil, fmt.Errorf("unexpected io.stat format: %s", line)
	}
	devParts := strings.SplitN(parts[0], ":", 2)
	if len(devParts) != 2 {
		return 0, 0, nil, fmt.Errorf("unexpected device format: %s", parts[0])
	}
	major, err = strconv.ParseInt(devParts[0], 10, 64)
	if err != nil {
		return
	}
	minor, err = strconv.ParseInt(devParts[1], 10, 64)
	if err != nil {
		return
	}
	stats = make(map[string]int64)
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		stats[kv[0]], err = strconv.ParseInt(kv[1], 10, 64)
		if err != nil {
			return
		}
	}
	return
}

// DiscoverCgroups finds cgroup directories under the given root.
// It looks for directories that contain cgroup controller files.
func DiscoverCgroups(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		full := filepath.Join(root, entry.Name())
		// Check if this looks like a cgroup directory
		if _, err := os.Stat(filepath.Join(full, "cgroup.controllers")); err == nil {
			paths = append(paths, full)
			// Also check one level deeper (e.g. /sys/fs/cgroup/lxc/106)
			subEntries, err := os.ReadDir(full)
			if err != nil {
				continue
			}
			for _, sub := range subEntries {
				if !sub.IsDir() {
					continue
				}
				subFull := filepath.Join(full, sub.Name())
				if _, err := os.Stat(filepath.Join(subFull, "cgroup.controllers")); err == nil {
					paths = append(paths, subFull)
				}
			}
		}
	}
	return paths, nil
}

// CgroupName returns the last path component of a cgroup path.
func CgroupName(cgroupPath string) string {
	return filepath.Base(cgroupPath)
}
