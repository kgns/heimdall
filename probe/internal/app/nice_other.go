//go:build !linux

package app

func renice(int) error { return nil }
