package pluginlifecycle

import (
	"encoding/json"

	"k8s.io/klog/v2"

	kyaml "k8s.io/apimachinery/pkg/util/yaml"
)

type unsupportedKMSConfig struct {
	Encryption struct {
		KMS struct {
			Vault struct {
				LogLevel string `json:"logLevel"`
			} `json:"vault"`
		} `json:"kms"`
	} `json:"encryption"`
}

func parseUnsupportedKMSConfig(raw []byte) (unsupportedKMSConfig, error) {
	if len(raw) == 0 {
		return unsupportedKMSConfig{}, nil
	}

	jsonRaw, err := kyaml.ToJSON(raw)
	if err != nil {
		klog.Warning(err)
		return unsupportedKMSConfig{}, err
	}

	config := unsupportedKMSConfig{}
	if err := json.Unmarshal(jsonRaw, &config); err != nil {
		return unsupportedKMSConfig{}, nil
	}

	return config, nil
}
