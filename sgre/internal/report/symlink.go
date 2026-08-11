package report

import (
	"fmt"
	"os"
	"path/filepath"
)

const latestTmpFmt = ".latest.tmp.%d"

// UpdateLatest atomically creates or updates a "latest" symlink in scansDir
// pointing to the scanID directory. The symlink target is relative (scanID
// directory name only) so the project root remains relocatable.
//
// On filesystems that do not support symbolic links, it falls back to writing
// a "latest.txt" regular file containing the scanID string.
//
// Preconditions: scansDir exists; a directory named scanID exists within scansDir.
// Postconditions: scansDir/latest is a symlink -> scanID (POSIX), or
// scansDir/latest.txt contains scanID (fallback).
//
// Concurrency: safe — uses a PID-suffixed temp symlink + atomic rename.
// Callers MUST treat any returned error as warning-only (non-fatal).
func UpdateLatest(scansDir string, scanID string) error {
	target := scanID
	tmpName := fmt.Sprintf(latestTmpFmt, os.Getpid())
	tmpPath := filepath.Join(scansDir, tmpName)

	if _, err := os.Lstat(tmpPath); err == nil {
		os.Remove(tmpPath)
	}

	if err := os.Symlink(target, tmpPath); err != nil {
		return writeLatestTxt(scansDir, scanID)
	}

	latestPath := filepath.Join(scansDir, LatestName)
	if err := os.Rename(tmpPath, latestPath); err != nil {
		if _, statErr := os.Stat(latestPath); statErr == nil {
			os.Remove(latestPath)
			if err2 := os.Rename(tmpPath, latestPath); err2 != nil {
				os.Remove(tmpPath)
				return fmt.Errorf("atomic rename: %w", err2)
			}
		} else {
			os.Remove(tmpPath)
			return fmt.Errorf("atomic rename: %w", err)
		}
	}

	latestTxtPath := filepath.Join(scansDir, LatestTxtName)
	os.Remove(latestTxtPath)

	return nil
}

func writeLatestTxt(scansDir string, scanID string) error {
	txtTmpName := fmt.Sprintf(".latest.txt.tmp.%d", os.Getpid())
	txtTmpPath := filepath.Join(scansDir, txtTmpName)

	if err := os.WriteFile(txtTmpPath, []byte(scanID), 0644); err != nil {
		return fmt.Errorf("write latest.txt fallback: %w", err)
	}

	latestTxtPath := filepath.Join(scansDir, LatestTxtName)
	if err := os.Rename(txtTmpPath, latestTxtPath); err != nil {
		os.Remove(txtTmpPath)
		return fmt.Errorf("atomic rename latest.txt: %w", err)
	}

	latestPath := filepath.Join(scansDir, LatestName)
	os.Remove(latestPath)

	return nil
}
