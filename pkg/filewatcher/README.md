# General

Filewatcher watches a file for changes within a pod. If the file contents have changed, the pod this function is running 
within will be restarted. 

Filewatcher was initially created during development of HyperShift's managed Azure service. Due to the Azure Cloud API 
authentication type used by this service, client certificate, whenever the certificate rotates, the pod needs to 
reauthenticate with Azure since Azure SDK for Go currently does not support re-authenticating with Azure with the new 
certificate. 