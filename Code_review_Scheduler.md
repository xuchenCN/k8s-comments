## 观察kube-scheduler的工作流程

Scheduler入口
[k8s.io/kubernetes/plugin/cmd/kube-scheduler/scheduler.go](k8s.io/kubernetes/plugin/cmd/kube-scheduler/scheduler.go)

···
//初始化 SchedulerServer继承了KubeSchedulerConfiguration
s := options.NewSchedulerServer()
···
随后设置参数后到app.Run
首先实例化kubeclient
```
kubecli, err := createClient(s)
```
随后初始化recorder后开始实例化scheduler
```
informerFactory := informers.NewSharedInformerFactory(kubecli, 0)

	sched, err := createScheduler(
		s,
		kubecli,
		informerFactory.Core().V1().Nodes(),
		informerFactory.Core().V1().PersistentVolumes(),
		informerFactory.Core().V1().PersistentVolumeClaims(),
		informerFactory.Core().V1().ReplicationControllers(),
		informerFactory.Extensions().V1beta1().ReplicaSets(),
		informerFactory.Apps().V1beta1().StatefulSets(),
		informerFactory.Core().V1().Services(),
		recorder,
	)
```

第一步构建 configurator

```
configurator := factory.NewConfigFactory(
		s.SchedulerName,
		kubecli,
		nodeInformer,
		pvInformer,
		pvcInformer,
		replicationControllerInformer,
		replicaSetInformer,
		statefulSetInformer,
		serviceInformer,
		s.HardPodAffinitySymmetricWeight,
	)
```

实例化 configurator的第一步实例化了一个cache

```
type schedulerCache struct {
	stop   <-chan struct{}
	ttl    time.Duration //默认30秒
	period time.Duration //默认1秒

	// This mutex guards all fields within this cache struct.
	mu sync.Mutex
	// a set of assumed pod keys.
	// The key could further be used to get an entry in podStates.
	assumedPods map[string]bool
	// a map from pod key to podState.
	podStates map[string]*podState
	nodes     map[string]*NodeInfo
}
```
随后 cache.run()启动一个协成来清理pod数据
```
cleanupAssumedPods()
```
然后初始化 ConfigFactory

```
c := &ConfigFactory{
		client:                         client,
		podLister:                      schedulerCache, //刚刚实例化的cache用来做podLister
		podQueue:                       cache.NewFIFO(cache.MetaNamespaceKeyFunc), //FIFO队列
		pVLister:                       pvInformer.Lister(),
		pVCLister:                      pvcInformer.Lister(),
		serviceLister:                  serviceInformer.Lister(),
		controllerLister:               replicationControllerInformer.Lister(),
		replicaSetLister:               replicaSetInformer.Lister(),
		statefulSetLister:              statefulSetInformer.Lister(),
		schedulerCache:                 schedulerCache,
		StopEverything:                 stopEverything,
		schedulerName:                  schedulerName,
		hardPodAffinitySymmetricWeight: hardPodAffinitySymmetricWeight,
	}
```

为scheduledPod初始化了一个Lister,添加一些EventHandler

```
//这里注释说要在 scheduledPods add/delete的时候去remove assumed pods
var scheduledPodIndexer cache.Indexer
	scheduledPodIndexer, c.scheduledPodPopulator = cache.NewIndexerInformer(
		c.createAssignedNonTerminatedPodLW(),//所以这里用的LW是已经被分配但是没有关闭的pod
		&v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addPodToCache,
			UpdateFunc: c.updatePodInCache,
			DeleteFunc: c.deletePodFromCache,
		},
		cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc},
	)
	c.scheduledPodLister = corelisters.NewPodLister(scheduledPodIndexer)
```

LW创建过程

```
func (factory *ConfigFactory) createAssignedNonTerminatedPodLW() *cache.ListWatch {
	selector := fields.ParseSelectorOrDie("spec.nodeName!=" + "" + ",status.phase!=" + string(v1.PodSucceeded) + ",status.phase!=" + string(v1.PodFailed))
	return cache.NewListWatchFromClient(factory.client.Core().RESTClient(), "pods", metav1.NamespaceAll, selector)
}
```
NewIndexerInformer 方法会返回一个Indexer和Controller

Indexer初始化
```
clientState := NewIndexer(DeletionHandlingMetaNamespaceKeyFunc, indexers)
```
初始化一个fifo队列用在watch上

```
fifo := NewDeltaFIFO(MetaNamespaceKeyFunc, nil, clientState)
```
随后初始化一个config 然后初始化controller

```
cfg := &Config{
		Queue:            fifo,
		ListerWatcher:    lw,
		ObjectType:       objType,
		FullResyncPeriod: resyncPeriod,
		RetryOnError:     false,

		Process: func(obj interface{}) error {
			// from oldest to newest
			for _, d := range obj.(Deltas) {
				switch d.Type {
				case Sync, Added, Updated:
					if old, exists, err := clientState.Get(d.Object); err == nil && exists {
						if err := clientState.Update(d.Object); err != nil {
							return err
						}
						h.OnUpdate(old, d.Object)
					} else {
						if err := clientState.Add(d.Object); err != nil {
							return err
						}
						h.OnAdd(d.Object)
					}
				case Deleted:
					if err := clientState.Delete(d.Object); err != nil {
						return err
					}
					h.OnDelete(d.Object)
				}
			}
			return nil
		},
	}
	return clientState, New(cfg)
```
这个controller.Run()
会启动Reflector.RunUntil 随后会启动```wait.Until(c.processLoop, time.Second, stopCh)```
实际去调用这个config的Process方法
至此完成了scheduledPod的监听缓存等处理对应到了schedulerCache的assumePod与PodState

随后开始初始化node缓存

```
// Only nodes in the "Ready" condition with status == "True" are schedulable
	nodeInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.addNodeToCache,
			UpdateFunc: c.updateNodeInCache,
			DeleteFunc: c.deleteNodeFromCache,
		},
		0,
	)
	c.nodeLister = nodeInformer.Lister()
```



