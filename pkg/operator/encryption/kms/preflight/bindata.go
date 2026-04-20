package preflight

import (
	"embed"
)

//go:embed assets/*
var f embed.FS

func mustAsset(name string) []byte {
	data, err := f.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return data
}
