package accesspolicy

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/labels"
	sshv1 "xiaoshiai.cn/kube-ssh/apis/ssh/v1"
	sshv1listers "xiaoshiai.cn/kube-ssh/pkg/generated/listers/ssh/v1"
)

type InformerStore struct {
	lister    sshv1listers.AccessLister
	namespace string
}

func NewInformerStore(lister sshv1listers.AccessLister, namespace string) *InformerStore {
	return &InformerStore{lister: lister, namespace: namespace}
}

func (s *InformerStore) Get(_ context.Context, namespace, name string) (*sshv1.Access, error) {
	if s == nil || s.lister == nil {
		return nil, fmt.Errorf("access informer store requires a lister")
	}
	if s.namespace != "" && namespace != s.namespace {
		return nil, fmt.Errorf("access %s/%s outside configured namespace %s", namespace, name, s.namespace)
	}
	access, err := s.lister.Accesses(namespace).Get(name)
	if err != nil {
		return nil, err
	}
	return access.DeepCopy(), nil
}

func (s *InformerStore) List(context.Context) ([]*sshv1.Access, error) {
	if s == nil || s.lister == nil {
		return nil, fmt.Errorf("access informer store requires a lister")
	}
	var (
		accesses []*sshv1.Access
		err      error
	)
	if s.namespace == "" {
		accesses, err = s.lister.List(labels.Everything())
	} else {
		accesses, err = s.lister.Accesses(s.namespace).List(labels.Everything())
	}
	if err != nil {
		return nil, err
	}
	out := make([]*sshv1.Access, 0, len(accesses))
	for _, access := range accesses {
		out = append(out, access.DeepCopy())
	}
	sortAccesses(out)
	return out, nil
}
