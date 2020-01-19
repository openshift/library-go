package verify

import (
		coreclientsetv1 "k8s.io/client-go/kubernetes/typed/core/v1"
)

// LoadConfigMapVerifierDataFromUpdate fetches the first config map in the payload with the correct annotation.                             
// It returns an error if the data is not valid, or no verifier if no config map is found. See the verify
// package for more details on the algorithm for verification. If the annotation is set, a verifier or error
// is always returned.                                                               
func LoadConfigMapVerifierDataFromManifest(manifests []Manifest, clientBuilder verify.ClientBuilder, configMapClient coreclientsetv1.ConfigM    apsGetter) (verify.Interface, *verify.StorePersister, error) {
    configMapGVK := corev1.SchemeGroupVersion.WithKind("ConfigMap")                  
    for _, manifest := range manifests {                                      
        if manifest.GVK != configMapGVK {                                            
            continue                                                                 
        }                                                                            
        if _, ok := manifest.Obj.GetAnnotations()[verify.ReleaseAnnotationConfigMapVerifier]; !ok {
            continue                                                                 
        }                                                                            
        src := fmt.Sprintf("the config map %s/%s", manifest.Obj.GetNamespace(), manifest.Obj.GetName())
        data, _, err := unstructured.NestedStringMap(manifest.Obj.Object, "data")    
        if err != nil {                                                              
            return nil, nil, errors.Wrapf(err, "%s is not valid: %v", src, err)      
        }                                                                            
        verifier, err := verify.NewFromConfigMapData(src, data, clientBuilder)       
        if err != nil {                                                              
            return nil, nil, err                                                     
        }                                                                            
                                                                                     
        // allow the verifier to consult the cluster for signature data, and also configure
        // a process that writes signatures back to that store                       
        signatureStore := verifyconfigmap.NewStore(configMapClient, nil)             
        verifier = verifier.WithStores(signatureStore)                               
        persister := verify.NewSignatureStorePersister(signatureStore, verifier)     
        return verifier, persister, nil                                              
    }                                                                                
    return nil, nil, nil                                                             
}
