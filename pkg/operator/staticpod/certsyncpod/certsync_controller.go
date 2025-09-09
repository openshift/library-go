package certsyncpod

import (
	"context"
	"os"
	"path/filepath"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1interface "k8s.io/client-go/kubernetes/typed/core/v1"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/klog/v2"

	"github.com/openshift/library-go/pkg/controller/factory"
	"github.com/openshift/library-go/pkg/operator/events"
	"github.com/openshift/library-go/pkg/operator/staticpod"
	"github.com/openshift/library-go/pkg/operator/staticpod/controller/installer"
)

type CertSyncController struct {
	destinationDir string
	namespace      string
	configMaps     []installer.UnrevisionedResource
	secrets        []installer.UnrevisionedResource

	configmapGetter corev1interface.ConfigMapInterface
	configMapLister v1.ConfigMapLister
	secretGetter    corev1interface.SecretInterface
	secretLister    v1.SecretLister
	eventRecorder   events.Recorder
}

func NewCertSyncController(targetDir, targetNamespace string, configmaps, secrets []installer.UnrevisionedResource, kubeClient kubernetes.Interface, informers informers.SharedInformerFactory, eventRecorder events.Recorder) factory.Controller {
	c := &CertSyncController{
		destinationDir: targetDir,
		namespace:      targetNamespace,
		configMaps:     configmaps,
		secrets:        secrets,
		eventRecorder:  eventRecorder.WithComponentSuffix("cert-sync-controller"),

		configmapGetter: kubeClient.CoreV1().ConfigMaps(targetNamespace),
		configMapLister: informers.Core().V1().ConfigMaps().Lister(),
		secretLister:    informers.Core().V1().Secrets().Lister(),
		secretGetter:    kubeClient.CoreV1().Secrets(targetNamespace),
	}

	return factory.New().
		WithInformers(
			informers.Core().V1().ConfigMaps().Informer(),
			informers.Core().V1().Secrets().Informer(),
		).
		WithSync(c.sync).
		ToController(
			"CertSyncController", // don't change what is passed here unless you also remove the old FooDegraded condition
			eventRecorder,
		)
}

func getConfigMapDir(targetDir, configMapName string) string {
	return filepath.Join(targetDir, "configmaps", configMapName)
}

func getSecretDir(targetDir, secretName string) string {
	return filepath.Join(targetDir, "secrets", secretName)
}

func (c *CertSyncController) sync(ctx context.Context, syncCtx factory.SyncContext) error {
	errors := []error{}

	klog.Infof("Syncing configmaps: %v", c.configMaps)
	for _, cm := range c.configMaps {
		configMap, err := c.configMapLister.ConfigMaps(c.namespace).Get(cm.Name)
		switch {
		case apierrors.IsNotFound(err) && !cm.Optional:
			errors = append(errors, err)
			continue

		case apierrors.IsNotFound(err) && cm.Optional:
			configMapFile := getConfigMapDir(c.destinationDir, cm.Name)
			if _, err := os.Stat(configMapFile); os.IsNotExist(err) {
				// if the configmap file does not exist, there is no work to do, so skip making any live check and just return.
				// if the configmap actually exists in the API, we'll eventually see it on the watch.
				continue
			}

			// Check with the live call it is really missing
			configMap, err = c.configmapGetter.Get(ctx, cm.Name, metav1.GetOptions{})
			if err == nil {
				klog.Infof("Caches are stale. They don't see configmap '%s/%s', yet it is present", configMap.Namespace, configMap.Name)
				// We will get re-queued when we observe the change
				continue
			}
			if !apierrors.IsNotFound(err) {
				errors = append(errors, err)
				continue
			}

			// remove missing content
			if err := os.RemoveAll(configMapFile); err != nil {
				c.eventRecorder.Warningf("CertificateUpdateFailed", "Failed removing file for configmap: %s/%s: %v", c.namespace, cm.Name, err)
				errors = append(errors, err)
			}
			c.eventRecorder.Eventf("CertificateRemoved", "Removed file for configmap: %s/%s", c.namespace, cm.Name)
			continue

		case err != nil:
			c.eventRecorder.Warningf("CertificateUpdateFailed", "Failed getting configmap: %s/%s: %v", c.namespace, cm.Name, err)
			errors = append(errors, err)
			continue
		}

		contentDir := getConfigMapDir(c.destinationDir, cm.Name)

		data := make(map[string]string, len(configMap.Data))
		for filename := range configMap.Data {
			fullFilename := filepath.Join(contentDir, filename)

			existingContent, err := os.ReadFile(fullFilename)
			if err != nil {
				if !os.IsNotExist(err) {
					klog.Error(err)
				}
				continue
			}

			data[filename] = string(existingContent)
		}

		// Check if cached configmap differs
		if reflect.DeepEqual(configMap.Data, data) {
			continue
		}

		klog.V(2).Infof("Syncing updated configmap '%s/%s'.", configMap.Namespace, configMap.Name)

		// We need to do a live get here so we don't overwrite a newer file with one from a stale cache
		configMap, err = c.configmapGetter.Get(ctx, configMap.Name, metav1.GetOptions{})
		if err != nil {
			// Even if the error is not exists we will act on it when caches catch up
			c.eventRecorder.Warningf("CertificateUpdateFailed", "Failed getting configmap: %s/%s: %v", c.namespace, cm.Name, err)
			errors = append(errors, err)
			continue
		}

		// Check if the live configmap differs
		if reflect.DeepEqual(configMap.Data, data) {
			klog.Infof("Caches are stale. The live configmap '%s/%s' is reflected on filesystem, but cached one differs", configMap.Namespace, configMap.Name)
			continue
		}

		errors = append(errors, writeFiles(&realFS, c.eventRecorder, configMap.Namespace, configMap.Name, "configmap", contentDir, data, 0644)...)
	}

	klog.Infof("Syncing secrets: %v", c.secrets)
	for _, s := range c.secrets {
		secret, err := c.secretLister.Secrets(c.namespace).Get(s.Name)
		switch {
		case apierrors.IsNotFound(err) && !s.Optional:
			errors = append(errors, err)
			continue

		case apierrors.IsNotFound(err) && s.Optional:
			secretFile := getSecretDir(c.destinationDir, s.Name)
			if _, err := os.Stat(secretFile); os.IsNotExist(err) {
				// if the secret file does not exist, there is no work to do, so skip making any live check and just return.
				// if the secret actually exists in the API, we'll eventually see it on the watch.
				continue
			}

			// Check with the live call it is really missing
			secret, err = c.secretGetter.Get(ctx, s.Name, metav1.GetOptions{})
			if err == nil {
				klog.Infof("Caches are stale. They don't see secret '%s/%s', yet it is present", secret.Namespace, secret.Name)
				// We will get re-queued when we observe the change
				continue
			}
			if !apierrors.IsNotFound(err) {
				errors = append(errors, err)
				continue
			}

			// remove missing content
			if err := os.RemoveAll(secretFile); err != nil {
				c.eventRecorder.Warningf("CertificateUpdateFailed", "Failed removing file for missing secret: %s/%s: %v", c.namespace, s.Name, err)
				errors = append(errors, err)
				continue
			}
			c.eventRecorder.Warningf("CertificateRemoved", "Removed file for missing secret: %s/%s", c.namespace, s.Name)
			continue

		case err != nil:
			c.eventRecorder.Warningf("CertificateUpdateFailed", "Failed getting secret: %s/%s: %v", c.namespace, s.Name, err)
			errors = append(errors, err)
			continue
		}

		contentDir := getSecretDir(c.destinationDir, s.Name)

		data := make(map[string][]byte, len(secret.Data))
		for filename := range secret.Data {
			fullFilename := filepath.Join(contentDir, filename)

			existingContent, err := os.ReadFile(fullFilename)
			if err != nil {
				if !os.IsNotExist(err) {
					klog.Error(err)
				}
				continue
			}

			data[filename] = existingContent
		}

		// Check if cached secret differs
		if reflect.DeepEqual(secret.Data, data) {
			continue
		}

		klog.V(2).Infof("Syncing updated secret '%s/%s'.", secret.Namespace, secret.Name)

		// We need to do a live get here so we don't overwrite a newer file with one from a stale cache
		secret, err = c.secretGetter.Get(ctx, secret.Name, metav1.GetOptions{})
		if err != nil {
			// Even if the error is not exists we will act on it when caches catch up
			c.eventRecorder.Warningf("CertificateUpdateFailed", "Failed getting secret: %s/%s: %v", c.namespace, s.Name, err)
			errors = append(errors, err)
			continue
		}

		// Check if the live secret differs
		if reflect.DeepEqual(secret.Data, data) {
			klog.Infof("Caches are stale. The live secret '%s/%s' is reflected on filesystem, but cached one differs", secret.Namespace, secret.Name)
			continue
		}

		errors = append(errors, writeFiles(&realFS, c.eventRecorder, secret.Namespace, secret.Name, "secret", contentDir, data, 0600)...)
	}

	return utilerrors.NewAggregate(errors)
}

type fileSystem struct {
	MkdirAll              func(path string, perm os.FileMode) error
	MkdirTemp             func(dir, pattern string) (string, error)
	RemoveAll             func(path string) error
	WriteFile             func(name string, data []byte, perm os.FileMode) error
	SwapDirectoriesAtomic func(dirA, dirB string) error
}

var realFS = fileSystem{
	MkdirAll:              os.MkdirAll,
	MkdirTemp:             os.MkdirTemp,
	RemoveAll:             os.RemoveAll,
	WriteFile:             os.WriteFile,
	SwapDirectoriesAtomic: staticpod.SwapDirectoriesAtomic,
}

func writeFiles[C string | []byte](
	fs *fileSystem, eventRecorder events.Recorder,
	objectNamespace, objectName, kind string,
	contentDir string, files map[string]C, filePerm os.FileMode,
) []error {
	var errors []error

	// We are going to atomically swap the new data directory for the old one.
	// In case the target directory does not exist, create it so that the directory not existing is not a special case.
	klog.Infof("Ensuring directory %q exists ...", contentDir)
	if err := fs.MkdirAll(contentDir, 0755); err != nil && !os.IsExist(err) {
		eventRecorder.Warningf("CertificateUpdateFailed",
			"Failed creating content directory for %s: %s/%s: %v", kind, objectNamespace, objectName, err)
		errors = append(errors, err)
		return errors
	}

	// Create a tmp source directory to be swapped.
	srcDir, err := fs.MkdirTemp(filepath.Dir(contentDir), filepath.Base(contentDir)+"-*")
	if err != nil {
		eventRecorder.Warningf("CertificateUpdateFailed",
			"Failed to create source %s directory for %s/%s: %v", kind, objectNamespace, objectName, err)
		errors = append(errors, err)
		return errors
	}
	defer fs.RemoveAll(srcDir)

	// Populate the tmp directory with files.
	for filename, content := range files {
		fullFilename := filepath.Join(srcDir, filename)
		klog.Infof("Writing %s manifest %q ...", kind, fullFilename)

		if err := fs.WriteFile(fullFilename, []byte(content), filePerm); err != nil {
			eventRecorder.Warningf("CertificateUpdateFailed",
				"Failed writing file for %s: %s/%s: %v", kind, objectNamespace, objectName, err)
			errors = append(errors, err)
			continue
		}
	}
	if len(errors) > 0 {
		return errors
	}

	// Swap directories atomically.
	if err := fs.SwapDirectoriesAtomic(contentDir, srcDir); err != nil {
		eventRecorder.Warningf("CertificateUpdateFailed",
			"Failed to enable new %s directory for %s/%s: %v", kind, objectNamespace, objectName, err)
		errors = append(errors, err)
		return errors
	}

	eventRecorder.Eventf("CertificateUpdated",
		"Wrote updated %s: %s/%s", kind, objectNamespace, objectName)
	return nil
}
