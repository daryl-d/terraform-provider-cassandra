package main

import (
	"crypto/sha256"
	"encoding/hex"
)

// taken from here - http://techblog.d2-si.eu/2018/02/23/my-first-terraform-provider.html
func hash(s string) string {
	sha := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sha[:])
}
