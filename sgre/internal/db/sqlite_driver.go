//go:build !nosqlite

package db

import (
	_ "modernc.org/sqlite"
)
