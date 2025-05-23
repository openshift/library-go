// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	v1alpha1 "github.com/openshift/api/operator/v1alpha1"
	operatorv1alpha1 "github.com/openshift/client-go/operator/applyconfigurations/operator/v1alpha1"
	typedoperatorv1alpha1 "github.com/openshift/client-go/operator/clientset/versioned/typed/operator/v1alpha1"
	gentype "k8s.io/client-go/gentype"
)

// fakeEtcdBackups implements EtcdBackupInterface
type fakeEtcdBackups struct {
	*gentype.FakeClientWithListAndApply[*v1alpha1.EtcdBackup, *v1alpha1.EtcdBackupList, *operatorv1alpha1.EtcdBackupApplyConfiguration]
	Fake *FakeOperatorV1alpha1
}

func newFakeEtcdBackups(fake *FakeOperatorV1alpha1) typedoperatorv1alpha1.EtcdBackupInterface {
	return &fakeEtcdBackups{
		gentype.NewFakeClientWithListAndApply[*v1alpha1.EtcdBackup, *v1alpha1.EtcdBackupList, *operatorv1alpha1.EtcdBackupApplyConfiguration](
			fake.Fake,
			"",
			v1alpha1.SchemeGroupVersion.WithResource("etcdbackups"),
			v1alpha1.SchemeGroupVersion.WithKind("EtcdBackup"),
			func() *v1alpha1.EtcdBackup { return &v1alpha1.EtcdBackup{} },
			func() *v1alpha1.EtcdBackupList { return &v1alpha1.EtcdBackupList{} },
			func(dst, src *v1alpha1.EtcdBackupList) { dst.ListMeta = src.ListMeta },
			func(list *v1alpha1.EtcdBackupList) []*v1alpha1.EtcdBackup { return gentype.ToPointerSlice(list.Items) },
			func(list *v1alpha1.EtcdBackupList, items []*v1alpha1.EtcdBackup) {
				list.Items = gentype.FromPointerSlice(items)
			},
		),
		fake,
	}
}
