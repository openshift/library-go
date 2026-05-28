package main

import (
	"bytes"
	"embed"
	"path/filepath"
	"text/template"
)

//go:embed assets
var assetsFS embed.FS

type yamlTemplateData struct {
	Namespace string
}

func readAsset(assetName string) ([]byte, error) {
	content, err := assetsFS.ReadFile(filepath.Join("assets", assetName))
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New(assetName).Parse(string(content))
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, yamlTemplateData{Namespace: "default"}); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
