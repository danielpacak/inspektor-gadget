// Copyright 2023 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package common

import (
	"fmt"
	"sync"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	listersv1 "k8s.io/client-go/listers/core/v1"
	k8scache "k8s.io/client-go/tools/cache"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/k8sutil"
)

// K8sInventoryCache is a cache of Kubernetes resources such as pods and services
// that can be used by operators to enrich events.
type K8sInventoryCache struct {
	factory informers.SharedInformerFactory

	pods    listersv1.PodLister
	podByIp k8scache.Indexer
	svcs    listersv1.ServiceLister
	svcByIp k8scache.Indexer

	exit chan struct{}

	useCount      int
	useCountMutex sync.Mutex
}

var (
	cache *K8sInventoryCache
	err   error
	once  sync.Once
)

func GetK8sInventoryCache() (*K8sInventoryCache, error) {
	once.Do(func() {
		cache, err = newCache(10 * time.Minute)
	})
	return cache, err
}

func newCache(defaultResync time.Duration) (*K8sInventoryCache, error) {
	clientset, err := k8sutil.NewClientset("")
	if err != nil {
		return nil, fmt.Errorf("creating new k8s clientset: %w", err)
	}
	factory := informers.NewSharedInformerFactory(clientset, defaultResync)
	podsInformer := factory.Core().V1().Pods()
	svcsInformer := factory.Core().V1().Services()

	podsInformer.Informer().AddIndexers(map[string]k8scache.IndexFunc{
		// Index by pod ip
		"podip": func(obj interface{}) ([]string, error) {
			pod, ok := obj.(*v1.Pod)
			if !ok {
				return nil, fmt.Errorf("expected pod, got %T", obj)
			}
			return []string{pod.Status.PodIP}, nil
		},
	})
	svcsInformer.Informer().AddIndexers(map[string]k8scache.IndexFunc{
		// Index svc by cluster ip
		"svcip": func(obj interface{}) ([]string, error) {
			svc, ok := obj.(*v1.Service)
			if !ok {
				return nil, fmt.Errorf("expected svc, got %T", obj)
			}
			return []string{svc.Spec.ClusterIP}, nil
		},
	})

	return &K8sInventoryCache{
		factory: factory,
		pods:    podsInformer.Lister(),
		podByIp: podsInformer.Informer().GetIndexer(),
		svcs:    svcsInformer.Lister(),
		svcByIp: svcsInformer.Informer().GetIndexer(),
	}, nil
}

func (cache *K8sInventoryCache) Close() {
	if cache.exit != nil {
		close(cache.exit)
		cache.exit = nil
	}
}

func (cache *K8sInventoryCache) Start() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// No uses before us, we are the first one
	if cache.useCount == 0 {
		cache.exit = make(chan struct{})
		cache.factory.Start(cache.exit)
		cache.factory.WaitForCacheSync(cache.exit)
	}
	cache.useCount++
}

func (cache *K8sInventoryCache) Stop() {
	cache.useCountMutex.Lock()
	defer cache.useCountMutex.Unlock()

	// We are the last user, stop everything
	if cache.useCount == 1 {
		cache.Close()
	}
	cache.useCount--
}

func (cache *K8sInventoryCache) GetPods() ([]*v1.Pod, error) {
	return cache.pods.List(labels.Everything())
}

func (cache *K8sInventoryCache) GetPodByIP(addr string) (*v1.Pod, error) {
	pods, err := cache.podByIp.ByIndex("podip", addr)
	if err != nil {
		return nil, err
	}
	if len(pods) == 0 {
		return nil, nil
	}
	if len(pods) > 1 {
		return nil, fmt.Errorf("multiple pods found")
	}
	return pods[0].(*v1.Pod), nil
}

func (cache *K8sInventoryCache) GetSvcs() ([]*v1.Service, error) {
	return cache.svcs.List(labels.Everything())
}

func (cache *K8sInventoryCache) GetSvcByIP(addr string) (*v1.Service, error) {
	svcs, err := cache.svcByIp.ByIndex("svcip", addr)
	if err != nil {
		return nil, err
	}
	if len(svcs) == 0 {
		return nil, nil
	}
	if len(svcs) > 1 {
		return nil, fmt.Errorf("multiple svcs found")
	}
	return svcs[0].(*v1.Service), nil
}
