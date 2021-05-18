package buildutil

import (
	"fmt"
	"path/filepath"
	"testing"
)

func TestNameForBuildVolume(t *testing.T) {
	type args struct {
		objName string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Secret One",
			args: args{objName: "secret-one"},
			want: fmt.Sprintf("secret-one-%s", buildVolumeSuffix),
		},
		{
			name: "ConfigMap One",
			args: args{objName: "configmap-one"},
			want: fmt.Sprintf("configmap-one-%s", buildVolumeSuffix),
		},
		{
			name: "Greater than 47 characters",
			args: args{objName: "build-volume-larger-than-47-characters-but-less-than-63"},
			want: fmt.Sprintf("build-volume-larger-than-47-characte-8c2b6813-%s", buildVolumeSuffix),
		},
		{
			name: "Should convert to lowercase",
			args: args{objName: "Secret-One"},
			want: fmt.Sprintf("secret-one-%s", buildVolumeSuffix),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NameForBuildVolume(tt.args.objName); got != tt.want {
				t.Errorf("NameForBuildVolume() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPathForBuildVolume(t *testing.T) {
	type args struct {
		objName string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Secret One",
			args: args{"secret-one"},
			want: filepath.Join(buildVolumeMountPath, fmt.Sprintf("secret-one-%s", buildVolumeSuffix)),
		},
		{
			name: "ConfigMap One",
			args: args{"configmap-one"},
			want: filepath.Join(buildVolumeMountPath, fmt.Sprintf("configmap-one-%s", buildVolumeSuffix)),
		},
		{
			name: "Greater than 47 characters",
			args: args{objName: "build-volume-larger-than-47-characters-but-less-than-63"},
			want: filepath.Join(buildVolumeMountPath, fmt.Sprintf("build-volume-larger-than-47-characte-8c2b6813-%s", buildVolumeSuffix)),
		},
		{
			name: "Should convert to lowercase",
			args: args{"Secret-One"},
			want: filepath.Join(buildVolumeMountPath, fmt.Sprintf("secret-one-%s", buildVolumeSuffix)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PathForBuildVolume(tt.args.objName); got != tt.want {
				t.Errorf("PathForBuildVolume() = %v, want %v", got, tt.want)
			}
		})
	}
}
