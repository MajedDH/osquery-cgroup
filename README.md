# osquery-cgroup

An osquery extension that exposes cgroup v2 metrics as SQL tables. Works with any cgroup v2 hierarchy: LXC containers, Docker, systemd services.

## Tables

| Table | Source Files | Description |
|---|---|---|
| `cgroup_memory` | `memory.current`, `memory.max`, `memory.peak`, `memory.swap.*` | Memory usage, limits, swap |
| `cgroup_cpu` | `cpu.stat`, `cpu.max`, `cpuset.cpus.effective` | CPU usage, throttling, assigned cores |
| `cgroup_io` | `io.stat` | Per-device IO bytes and operations |
| `cgroup_pressure` | `cpu.pressure`, `memory.pressure`, `io.pressure` | PSI (Pressure Stall Information) metrics |
| `cgroup_pids` | `pids.current`, `pids.max`, `pids.peak` | Process count and limits |

## Build

```bash
make build
```

Produces `osquery-cgroup.ext` (Linux amd64).

## Install

```bash
make install
```

This copies the binary to `/opt/osquery/extensions/` with proper ownership.

Add to `/etc/osquery/extensions.load`:
```
/opt/osquery/extensions/osquery-cgroup.ext
```

Add to `/etc/osquery/osquery.flags`:
```
--extensions_autoload=/etc/osquery/extensions.load
--extensions_timeout=10
--extensions_require=cgroup
--disable_extensions=false
```

## Usage

### Query all LXC containers

```sql
SELECT * FROM cgroup_memory WHERE path LIKE '/sys/fs/cgroup/lxc/%';
```

### Single cgroup

```sql
SELECT * FROM cgroup_cpu WHERE path = '/sys/fs/cgroup/lxc/106';
```

### PSI pressure for a specific resource

```sql
SELECT * FROM cgroup_pressure
WHERE path LIKE '/sys/fs/cgroup/lxc/%' AND resource = 'cpu';
```

### Combined overview (memory + CPU + PIDs)

```sql
SELECT
  m.cgroup_name AS vmid,
  m.memory_current, m.memory_max, m.memory_usage_pct,
  m.swap_current,
  c.usage_usec, c.user_usec, c.system_usec,
  c.cpus_effective,
  p.pids_current
FROM cgroup_memory m
JOIN cgroup_cpu c ON m.path = c.path
JOIN cgroup_pids p ON m.path = p.path
WHERE m.path LIKE '/sys/fs/cgroup/lxc/%';
```

### Docker containers (systemd-managed)

```sql
SELECT * FROM cgroup_memory
WHERE path LIKE '/sys/fs/cgroup/system.slice/docker-%';
```

## Path constraints

Each table accepts a `path` column in the WHERE clause:

- `path = '/sys/fs/cgroup/lxc/106'` -- single cgroup
- `path LIKE '/sys/fs/cgroup/lxc/%'` -- all children of a directory
- No constraint -- discovers all cgroups under `/sys/fs/cgroup` (one level deep)

## Testing with osqueryi

```bash
osqueryi \
  --extension /opt/osquery/extensions/osquery-cgroup.ext \
  --extensions_timeout 10 \
  --extensions_require cgroup
```

The `--extensions_require` flag is essential -- it makes osquery wait for the extension to register before executing queries.

## Column Reference

### cgroup_memory

| Column | Type | Description |
|---|---|---|
| path | TEXT | Full cgroup path |
| cgroup_name | TEXT | Last path component (e.g. `106`) |
| memory_current | BIGINT | Current memory usage (bytes) |
| memory_max | BIGINT | Memory limit (-1 if unlimited) |
| memory_peak | BIGINT | Peak memory usage (bytes) |
| swap_current | BIGINT | Current swap usage (bytes) |
| swap_max | BIGINT | Swap limit (-1 if unlimited) |
| memory_usage_pct | TEXT | Usage ratio (0-1, e.g. `0.4783`) |

### cgroup_cpu

| Column | Type | Description |
|---|---|---|
| path | TEXT | Full cgroup path |
| cgroup_name | TEXT | Last path component |
| usage_usec | BIGINT | Total CPU time (microseconds) |
| user_usec | BIGINT | User CPU time |
| system_usec | BIGINT | System CPU time |
| nr_throttled | BIGINT | Number of throttled periods |
| throttled_usec | BIGINT | Total throttle time |
| cpu_max_quota | BIGINT | CPU quota in usec (-1 if unlimited) |
| cpu_max_period | BIGINT | CPU period in usec |
| cpus_effective | TEXT | Assigned CPUs (e.g. `0-15`) |

### cgroup_io

| Column | Type | Description |
|---|---|---|
| path | TEXT | Full cgroup path |
| cgroup_name | TEXT | Last path component |
| device_major | BIGINT | Block device major number |
| device_minor | BIGINT | Block device minor number |
| rbytes | BIGINT | Bytes read |
| wbytes | BIGINT | Bytes written |
| rios | BIGINT | Read IO operations |
| wios | BIGINT | Write IO operations |
| dbytes | BIGINT | Discard bytes |
| dios | BIGINT | Discard operations |

### cgroup_pressure

| Column | Type | Description |
|---|---|---|
| path | TEXT | Full cgroup path |
| cgroup_name | TEXT | Last path component |
| resource | TEXT | `cpu`, `memory`, or `io` |
| some_avg10 | TEXT | Some pressure avg 10s |
| some_avg60 | TEXT | Some pressure avg 60s |
| some_avg300 | TEXT | Some pressure avg 300s |
| some_total | BIGINT | Some total stall time (usec) |
| full_avg10 | TEXT | Full pressure avg 10s |
| full_avg60 | TEXT | Full pressure avg 60s |
| full_avg300 | TEXT | Full pressure avg 300s |
| full_total | BIGINT | Full total stall time (usec) |

### cgroup_pids

| Column | Type | Description |
|---|---|---|
| path | TEXT | Full cgroup path |
| cgroup_name | TEXT | Last path component |
| pids_current | BIGINT | Current number of PIDs |
| pids_max | BIGINT | PID limit (-1 if unlimited) |
| pids_peak | BIGINT | Peak PID count |

## License

Apache 2.0
