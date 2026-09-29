package main

import "github.com/shirou/gopsutil/v4/host"

func uname() map[string]string {
	info, err := host.Info()
	if err != nil {
		return nil
	}
	return map[string]string{
		"system": "Windows", "node": info.Hostname, "release": info.PlatformVersion,
		"version": info.KernelVersion, "machine": info.KernelArch, "processor": info.KernelArch,
	}
}
