## 观察 Replicaset 的工作流程

首先是初始化工作 func NewReplicaSetController() 
这里会设置一些Replicaset需要的组件

```

// NewReplicaSetController configures a replica set controller with the specified event recorder
func NewReplicaSetController(rsInformer extensionsinformers.ReplicaSetInformer, podInformer coreinformers.PodInformer, kubeClient clientset.Interface, burstReplicas int) *ReplicaSetController {
  // 首先是Client
  if kubeClient != nil && kubeClient.Core().RESTClient().GetRateLimiter() != nil {
		metrics.RegisterMetricAndTrackRateLimiterUsage("replicaset_controller", kubeClient.Core().RESTClient().GetRateLimiter())
	}
  
  	// 这里初始化EventBroadcaster
	eventBroadcaster := record.NewBroadcaster()
	eventBroadcaster.StartLogging(glog.Infof)
	eventBroadcaster.StartRecordingToSink(&v1core.EventSinkImpl{Interface: v1core.New(kubeClient.Core().RESTClient()).Events("")})

	// 初始化Controller对象
	rsc := &ReplicaSetController{
		kubeClient: kubeClient,
		podControl: controller.RealPodControl{
			KubeClient: kubeClient,
			Recorder:   eventBroadcaster.NewRecorder(api.Scheme, clientv1.EventSource{Component: "replicaset-controller"}),
		},
		burstReplicas: burstReplicas,
		expectations:  controller.NewUIDTrackingControllerExpectations(controller.NewControllerExpectations()),
		queue:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "replicaset"),
	}
	
	// 设置Handler
	rsInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    rsc.enqueueReplicaSet,
		UpdateFunc: rsc.updateRS,
		// This will enter the sync loop and no-op, because the replica set has been deleted from the store.
		// Note that deleting a replica set immediately after scaling it to 0 will not work. The recommended
		// way of achieving this is by performing a `stop` operation on the replica set.
		DeleteFunc: rsc.enqueueReplicaSet,
	})
	rsc.rsLister = rsInformer.Lister()
	rsc.rsListerSynced = rsInformer.Informer().HasSynced
        
        // 设置对Pod的Handler
	podInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: rsc.addPod,
		// This invokes the ReplicaSet for every pod change, eg: host assignment. Though this might seem like
		// overkill the most frequent pod update is status, and the associated ReplicaSet will only list from
		// local storage, so it should be ok.
		UpdateFunc: rsc.updatePod,
		DeleteFunc: rsc.deletePod,
	})
	rsc.podLister = podInformer.Lister()
	rsc.podListerSynced = podInformer.Informer().HasSynced

        // 这里设置同步方法，这个方法里具体操作pod
	rsc.syncHandler = rsc.syncReplicaSet

	return rsc
}

```

在看看实际运行的操作

```
// Run begins watching and syncing.
func (rsc *ReplicaSetController) Run(workers int, stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	defer rsc.queue.ShutDown()

	glog.Infof("Starting ReplicaSet controller")

	if !cache.WaitForCacheSync(stopCh, rsc.podListerSynced, rsc.rsListerSynced) {
		utilruntime.HandleError(fmt.Errorf("timed out waiting for caches to sync"))
		return
	}
        // 这里实际的去消费队列里的数据
	for i := 0; i < workers; i++ {
		go wait.Until(rsc.worker, time.Second, stopCh)
	}

	<-stopCh
	glog.Infof("Shutting down ReplicaSet Controller")
}
```

消费的操作

```
// worker runs a worker thread that just dequeues items, processes them, and marks them done.
// It enforces that the syncHandler is never invoked concurrently with the same key.
func (rsc *ReplicaSetController) worker() {
	for rsc.processNextWorkItem() {
	}
}

func (rsc *ReplicaSetController) processNextWorkItem() bool {
	key, quit := rsc.queue.Get()
	if quit {
		return false
	}
	defer rsc.queue.Done(key)
        
        // 这里会实际的处理
	err := rsc.syncHandler(key.(string))
	if err == nil {
		rsc.queue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("Sync %q failed with %v", key, err))
	rsc.queue.AddRateLimited(key)

	return true
}
```

在初始化的时候看到 RS的Handler都是直接进队列的，UpdateFunc也是处理后进队列，对于pod的Handler是用一个计数器来做操作

看一下增加Pod的操作

```
// When a pod is created, enqueue the replica set that manages it and update its expectations.
func (rsc *ReplicaSetController) addPod(obj interface{}) {
	pod := obj.(*v1.Pod)
	// 首先判断Pod是否已经被删除了
	if pod.DeletionTimestamp != nil {
		// on a restart of the controller manager, it's possible a new pod shows up in a state that
		// is already pending deletion. Prevent the pod from being a creation observation.
		rsc.deletePod(pod)
		return
	}
	
	// 
	// If it has a ControllerRef, that's all that matters.
	if controllerRef := controller.GetControllerOf(pod); controllerRef != nil {
		rs := rsc.resolveControllerRef(pod.Namespace, controllerRef)
		if rs == nil {
			return
		}
		rsKey, err := controller.KeyFunc(rs)
		if err != nil {
			return
		}
		glog.V(4).Infof("Pod %s created: %#v.", pod.Name, pod)
		rsc.expectations.CreationObserved(rsKey)
		rsc.enqueueReplicaSet(rs)
		return
	}

	// Otherwise, it's an orphan. Get a list of all matching ReplicaSets and sync
	// them to see if anyone wants to adopt it.
	// DO NOT observe creation because no controller should be waiting for an
	// orphan.
	rss := rsc.getPodReplicaSets(pod)
	if len(rss) == 0 {
		return
	}
	glog.V(4).Infof("Orphan Pod %s created: %#v.", pod.Name, pod)
	for _, rs := range rss {
		rsc.enqueueReplicaSet(rs)
	}
}
```
