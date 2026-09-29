package main

// docker.py with the official Docker Engine client (github.com/moby/moby/client),
// the dependency a real Go port would take. Same contract: {"containers": {}}
// is a genuinely empty host, nil (JSON null) is a collection failure the
// server never prunes on, and a partial container map never ships.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	cerrdefs "github.com/containerd/errdefs"
	"github.com/moby/moby/client"
)

const (
	dockerClientTimeout   = 10 * time.Second
	dockerCollectDeadline = 25 * time.Second
	dockerMaxContainers   = 500
	dockerZeroTimestamp   = "0001-01-01T00:00:00Z"
)

var (
	dockerMu        sync.Mutex
	dockerCli       *client.Client
	dockerCliHost   string
	dockerPrevStats = map[string]map[string]any{}
)

func dockerClient(socketURL string) (*client.Client, error) {
	if dockerCli != nil && dockerCliHost == socketURL {
		return dockerCli, nil
	}
	invalidateDockerClient()
	opts := []client.Opt{client.WithTimeout(dockerClientTimeout), client.WithAPIVersionNegotiation()}
	if socketURL != "" {
		opts = append(opts, client.WithHost(socketURL))
	} else {
		opts = append(opts, client.FromEnv)
	}
	c, err := client.New(opts...)
	if err != nil {
		return nil, err
	}
	dockerCli, dockerCliHost = c, socketURL
	return c, nil
}

func invalidateDockerClient() {
	if dockerCli != nil {
		dockerCli.Close()
	}
	dockerCli, dockerCliHost = nil, ""
}

// dataError is a container whose stats the daemon served but that cannot be
// used (a missing key): docker.py's generic `except Exception` -> skip it.
// Every OTHER error from a Docker call is a collection failure (null):
// docker-py's APIError subclasses requests' RequestException, so a 500 on
// one container lands in the "transport" branch too and ships None, never
// a partial map. Only a 404 (the container vanished) is skipped.
type dataError struct{ error }

// ---- stats as a raw map: Python passes pids_stats / throttling_data /
// networks through verbatim, so they are decoded untyped, with json.Number
// so system_cpu_usage (~4e16, past 2**53) keeps every digit.

func dig(m map[string]any, path ...string) (any, bool) {
	var cur any = m
	for _, k := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[k]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// mustInt is a Python KeyError: a missing key fails this container's entry.
func mustInt(m map[string]any, path ...string) (int64, error) {
	v, ok := dig(m, path...)
	if !ok {
		return 0, dataError{fmt.Errorf("stats: missing %s", strings.Join(path, "."))}
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, dataError{fmt.Errorf("stats: %s is not a number", strings.Join(path, "."))}
	}
	return n.Int64()
}

// getInt is dict.get(key, 0).
func getInt(m map[string]any, path ...string) int64 {
	if v, ok := dig(m, path...); ok {
		if n, ok := v.(json.Number); ok {
			i, _ := n.Int64()
			return i
		}
	}
	return 0
}

func getOr(m map[string]any, def any, path ...string) any {
	if v, ok := dig(m, path...); ok {
		return v
	}
	return def
}

func cpuUsagePercent(stats, prev map[string]any, key string) (float64, error) {
	cpuDelta := getInt(stats, "cpu_stats", "cpu_usage", key) - getInt(prev, "cpu_stats", "cpu_usage", key)
	sysNow, err := mustInt(stats, "cpu_stats", "system_cpu_usage")
	if err != nil {
		return 0, err
	}
	sysPrev, err := mustInt(prev, "cpu_stats", "system_cpu_usage")
	if err != nil {
		return 0, err
	}
	if sysDelta := sysNow - sysPrev; sysDelta > 0 && cpuDelta > 0 {
		return float64(cpuDelta) / float64(sysDelta) * 100, nil
	}
	return 0, nil
}

// calculate_memory_usage / calculate_memory_percent: usage minus the page
// cache (total_inactive_file on cgroup v1, inactive_file on v2), if non-zero.
func memoryUsage(stats map[string]any) (int64, error) {
	usage, err := mustInt(stats, "memory_stats", "usage")
	if err != nil {
		return 0, err
	}
	if _, ok := dig(stats, "memory_stats", "stats"); !ok {
		return 0, dataError{errors.New("stats: missing memory_stats.stats")}
	}
	for _, k := range []string{"total_inactive_file", "inactive_file"} {
		if v := getInt(stats, "memory_stats", "stats", k); v != 0 {
			return usage - v, nil
		}
	}
	return usage, nil
}

func blockIO(stats map[string]any) (int64, int64, bool) {
	entries, _ := getOr(stats, nil, "blkio_stats", "io_service_bytes_recursive").([]any)
	if len(entries) == 0 {
		return 0, 0, false
	}
	var read, write int64
	for _, e := range entries {
		item, _ := e.(map[string]any)
		op, _ := item["op"].(string)
		switch strings.ToLower(op) {
		case "read":
			read += getInt(item, "value")
		case "write":
			write += getInt(item, "value")
		}
	}
	return read, write, true
}

func truthyJSON(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	}
	return true
}

func computedStats(stats, prev map[string]any) (map[string]any, error) {
	cpuPct, err := cpuUsagePercent(stats, prev, "total_usage")
	if err != nil {
		return nil, err
	}
	kernelPct, _ := cpuUsagePercent(stats, prev, "usage_in_kernelmode")
	userPct, _ := cpuUsagePercent(stats, prev, "usage_in_usermode")
	usage, err := memoryUsage(stats)
	if err != nil {
		return nil, err
	}
	limit, err := mustInt(stats, "memory_stats", "limit")
	if err != nil {
		return nil, err
	}
	out := map[string]any{
		"cpu_percent":            cpuPct,
		"memory_percent":         float64(usage) / float64(limit) * 100,
		"memory_usage":           usage,
		"memory_limit":           getOr(stats, nil, "memory_stats", "limit"),
		"pids_stats":             getOr(stats, map[string]any{}, "pids_stats"),
		"cpu_throttling":         getOr(stats, map[string]any{}, "cpu_stats", "throttling_data"),
		"online_cpus":            getOr(stats, nil, "cpu_stats", "online_cpus"),
		"cpu_kernelmode_percent": kernelPct,
		"cpu_usermode_percent":   userPct,
	}
	if r, w, ok := blockIO(stats); ok {
		out["block_read_bytes"], out["block_write_bytes"] = r, w
	}
	if nets := getOr(stats, nil, "networks"); truthyJSON(nets) {
		out["networks"] = nets
	}
	return out, nil
}

func fetchStats(ctx context.Context, c *client.Client, id string) (map[string]any, error) {
	res, err := c.ContainerStats(ctx, id, client.ContainerStatsOptions{Stream: false, IncludePreviousSample: false})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	dec := json.NewDecoder(res.Body)
	dec.UseNumber()
	var stats map[string]any
	if err := dec.Decode(&stats); err != nil {
		return nil, fmt.Errorf("decoding stats: %w", err)
	}
	return stats, nil
}

type imageMeta struct {
	tags, digests []string
}

func imageTagsAndDigests(ctx context.Context, c *client.Client, imageID string, cache map[string]imageMeta) imageMeta {
	if m, ok := cache[imageID]; ok {
		return m
	}
	m := imageMeta{tags: []string{}, digests: []string{}}
	img, err := c.ImageInspect(ctx, imageID)
	if err != nil {
		logf("error", "Error fetching Docker image metadata for %s: %v", imageID, err)
	} else {
		// docker-py's Image.tags drops the "<none>:<none>" placeholder.
		for _, t := range img.RepoTags {
			if t != "<none>:<none>" {
				m.tags = append(m.tags, t)
			}
		}
		if img.RepoDigests != nil {
			m.digests = img.RepoDigests
		}
	}
	cache[imageID] = m
	return m
}

func normalizeTimestamp(v string) any {
	if v == "" || v == dockerZeroTimestamp {
		return nil
	}
	return v
}

func buildEntry(ctx context.Context, c *client.Client, id string, cache map[string]imageMeta) (map[string]any, error) {
	res, err := c.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return nil, err
	}
	attrs := res.Container
	var name any
	if attrs.Name != "" {
		name = strings.TrimLeft(attrs.Name, "/")
	}
	image := attrs.Image
	if attrs.Config != nil && attrs.Config.Image != "" {
		image = attrs.Config.Image
	}
	meta := imageTagsAndDigests(ctx, c, attrs.Image, cache)
	entry := map[string]any{
		"name": name, "image": image, "image_id": attrs.Image,
		"image_tags": meta.tags, "image_repo_digests": meta.digests,
		"status": nil, "exit_code": 0, "oom_killed": false,
		"restart_count": attrs.RestartCount, "started_at": nil, "finished_at": nil, "health": nil,
	}
	if s := attrs.State; s != nil {
		entry["status"] = string(s.Status)
		entry["exit_code"] = s.ExitCode
		entry["oom_killed"] = s.OOMKilled
		entry["started_at"] = normalizeTimestamp(s.StartedAt)
		entry["finished_at"] = normalizeTimestamp(s.FinishedAt)
		if s.Health != nil {
			entry["health"] = string(s.Health.Status)
		}
		if s.Status == "running" {
			stats, err := fetchStats(ctx, c, id)
			if err != nil {
				return nil, err
			}
			if prev, ok := dockerPrevStats[id]; ok {
				computed, err := computedStats(stats, prev)
				if err != nil {
					return nil, err
				}
				for k, v := range computed {
					entry[k] = v
				}
			}
			dockerPrevStats[id] = stats
		}
	}
	return entry, nil
}

func dockerMetrics(cfg any) (any, error) {
	socketURL := ""
	if m, ok := cfg.(map[string]any); ok {
		socketURL, _ = m["socket_url"].(string)
	}
	dockerMu.Lock()
	defer dockerMu.Unlock()

	c, err := dockerClient(socketURL)
	if err != nil {
		logf("error", "Error connecting to Docker daemon: %v", err)
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dockerCollectDeadline)
	defer cancel()

	list, err := c.ContainerList(ctx, client.ContainerListOptions{All: true})
	if err != nil {
		logf("error", "Error listing Docker containers: %v", err)
		invalidateDockerClient()
		return nil, nil
	}
	containers := list.Items
	if len(containers) > dockerMaxContainers {
		// Running first, then the newest others.
		sort.SliceStable(containers, func(i, j int) bool {
			ri, rj := containers[i].State == "running", containers[j].State == "running"
			if ri != rj {
				return ri
			}
			return !ri && containers[i].Created > containers[j].Created
		})
		containers = containers[:dockerMaxContainers]
	}

	entries := map[string]any{}
	cache := map[string]imageMeta{}
	for _, summary := range containers {
		if ctx.Err() != nil {
			logf("error", "Docker collection exceeded %s budget after %d of %d containers; reporting collection failure",
				dockerCollectDeadline, len(entries), len(containers))
			return nil, nil
		}
		entry, err := buildEntry(ctx, c, summary.ID, cache)
		var bad dataError
		switch {
		case err == nil:
			entries[summary.ID] = entry
		case cerrdefs.IsNotFound(err):
			logf("debug", "Docker container %s vanished during collection, skipping", summary.ID)
		case errors.As(err, &bad):
			logf("error", "Error collecting Docker container %s: %v", summary.ID, err)
		default:
			logf("error", "Docker error on container %s: %v; reporting collection failure", summary.ID, err)
			invalidateDockerClient()
			return nil, nil
		}
	}
	for id := range dockerPrevStats {
		if _, seen := entries[id]; !seen {
			delete(dockerPrevStats, id)
		}
	}
	return map[string]any{"containers": entries}, nil
}
