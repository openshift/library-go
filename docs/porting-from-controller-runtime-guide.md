
# A guide to porting an operator from controller-runtime to library-go

This uses the experience of migrating the cluster-baremetal-operator to library-go.


## Replace controller-runtime client.Client

Instead use native clients. If you have your own CRD and use the controller-runtime client
to update status/finilizers then either use the k8s.io/client-go/discovery client or generate
your client using client-gen.

see: https://www.openshift.com/blog/kubernetes-deep-dive-code-generation-customresources


## Replace usage of reconcile.Scheme with "k8s.io/client-go/kubernetes/scheme"


## Convert the SetupWithManager() function

Doing this early helps knowing what you need in the initialization.

Example: change the following

```
func (r *ProvisioningReconciler) SetupWithManager(mgr ctrl.Manager) error {
    return ctrl.NewControllerManagedBy(mgr).
        For(&metal3iov1alpha1.Provisioning{}).
        Owns(&corev1.Secret{}).
        Owns(&appsv1.Deployment{}).
        Owns(&corev1.Service{}).
        Owns(&appsv1.DaemonSet{}).
        Owns(&osconfigv1.ClusterOperator{}).
        Owns(&osconfigv1.Proxy{}).
        Complete(r)
```
to
```
// this fakes out a function called HasSyned, so return true when we don't
// want to visit an object.
func filterOutNotOwned(obj interface{}) bool {
    object := obj.(metav1.Object)
    for _, owner := range object.GetOwnerReferences() {
        aGV, err := schema.ParseGroupVersion(a.APIVersion)
        if err != nil {
            return false
        }
        return aGV.Group == metal3iov1alpha1.GroupVersion.Group &&
            a.Kind == metal3iov1alpha1.ProvisioningKindSingular &&
            a.Name == metal3iov1alpha1.ProvisioningSingletonName
    }
    return true
}

func NewProvisioningController(
    client metal3ioClient.Interface,
    kubeClient kubernetes.Interface,
    osClient osclientset.Interface,
    kubeInformersForNamespace informers.SharedInformerFactory,
    metal3Informers metal3externalinformers.SharedInformerFactory,
    configInformer configinformers.SharedInformerFactory,
    eventRecorder events.Recorder,
) factory.Controller {
    c := &ProvisioningController{
        client:         client,
        kubeClient:     kubeClient,
        osClient:       osClient,
    }

    return factory.New().WithInformers(
        metal3Informers.Metal3().V1alpha1().Provisionings().Informer(),
        configInformer.Config().V1().Proxies().Informer(),
    ).WithFilteredEventsInformers(filterOutNotOwned,
        kubeInformersForNamespace.Core().V1().Secrets().Informer(),
        kubeInformersForNamespace.Core().V1().Services().Informer(),
        kubeInformersForNamespace.Apps().V1().Deployments().Informer(),
        kubeInformersForNamespace.Apps().V1().DaemonSets().Informer(),
        configInformer.Config().V1().ClusterOperators().Informer(),
    ).WithSync(c.Reconcile).ToController("ProvisioningController", eventRecorder.WithComponentSuffix(ComponentName))
 }
```

## change the signature of your Reconcile function

from
```
func (r *ProvisioningReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
```
to
```
func (r *ProvisioningController) Reconcile(ctx context.Context, controllerContext factory.SyncContext) error {
```
Then update the return to just include an error.
Note if you want polling, then adjust your factory.New() to include
```
    return factory.New().ResyncEvery(5*time.Minute).WithInformers(
```

## additions to rbac

Add the following to +kubebuilder:rbac section. It is required by library-go to determine the namespace

```
// +kubebuilder:rbac:groups="",resources=pods,verbs=watch;list;get
```

## Convert your main function

The first thing is you are going to need the controller command flags

```
func main() {
    pflag.CommandLine.SetNormalizeFunc(utilflag.WordSepNormalizeFunc)
    pflag.CommandLine.AddGoFlagSet(goflag.CommandLine)

    ccc := controllercmd.NewControllerCommandConfig("cluster-baremetal-operator", version.Get(), run)
    ccc.DisableLeaderElection = true // remove if you need leaderElection

    cmd := ccc.NewCommand()
    cmd.Use = "cluster-baremetal-operator"
    cmd.Short = "Start the Cluster Baremetal Operator"
    if err := cmd.Execute(); err != nil {
        fmt.Fprintf(os.Stderr, "%v\n", err)
         os.Exit(1)
     }
}
```

This calls 'run()' when called

```
func run(ctx context.Context, controllerContext *controllercmd.ControllerContext) error {
    // here you will have a bunch of client and informer initializations to fullfil your NewController()
    kubeClient, err := kubernetes.NewForConfig(controllerContext.KubeConfig)
    if err != nil {
        return err
     }
    kubeInformersForNamespace := informers.NewSharedInformerFactoryWithOptions(kubeClient, 10*time.Minute, informers.WithNamespace(ns))

    // ... other client/informers here..

    // then construct your controller (this replaces ctrl.NewManager())
    provisioningController := controllers.NewProvisioningController(
        kubeClient,
        kubeInformersForNamespace,
        // etc..
    )
    // start your informers
    kubeInformersForNamespace.Start(ctx.Done())

    // run your controllers
    go provisioningController.Run(ctx, 1)

    <-ctx.Done()
    return nil
}
```

## Use https://github.com/openshift/generic-admission-server for Webhooks
