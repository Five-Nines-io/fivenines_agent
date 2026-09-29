//go:build !windows

package main

import "golang.org/x/sys/unix"

// platform.uname(). processor is NOT the machine: Python reads it from
// `uname -p`, which prints "unknown" on Debian/Ubuntu (-> "") and the
// architecture on RHEL. The prototype hardcodes the Debian answer.
func uname() map[string]string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return nil
	}
	machine := unix.ByteSliceToString(u.Machine[:])
	return map[string]string{
		"system": "Linux", "node": unix.ByteSliceToString(u.Nodename[:]), "release": unix.ByteSliceToString(u.Release[:]),
		"version": unix.ByteSliceToString(u.Version[:]), "machine": machine, "processor": "",
	}
}
