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
	
	// 这里会获得当前pod的ControllerRef 并且判断是否属于ReplicaSet
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
		// 这里有一个计数器，用atomic的原子操作以及etcd的存储将一些数据存下来
		// 具体记录了 add,del,key,timestamp信息
		// 这里Add操作会decreament add数量
		rsc.expectations.CreationObserved(rsKey)
		rsc.enqueueReplicaSet(rs)
		return
	}

	// Otherwise, it's an orphan. Get a list of all matching ReplicaSets and sync
	// them to see if anyone wants to adopt it.
	// DO NOT observe creation because no controller should be waiting for an
	// orphan.
	
	// 当这个Pod没找到ControllerRef会找到所有符合条件的ReplicaSet，并且看哪个能接收这个Pod
	
	// 寻找所有符合条件的ReplicaSet
	rss := rsc.getPodReplicaSets(pod)
	if len(rss) == 0 {
		return
	}
	glog.V(4).Infof("Orphan Pod %s created: %#v.", pod.Name, pod)
	// 实际上在查找的时候对于ReplicaSet做了处理 大于1就报错了
	for _, rs := range rss {
		// 将这个ReplicaSet放进队列中处理
		rsc.enqueueReplicaSet(rs)
	}
}
```

实际的重头戏方法是这个,从队列里拿出来的ReplicaSet都会过这个方法一遍

```
// syncReplicaSet will sync the ReplicaSet with the given key if it has had its expectations fulfilled,
// meaning it did not expect to see any more of its pods created or deleted. This function is not meant to be
// invoked concurrently with the same key.
func (rsc *ReplicaSetController) syncReplicaSet(key string) error {
...
	
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return err
	}
	// 先从缓存里拿出这个对象
	rs, err := rsc.rsLister.ReplicaSets(namespace).Get(name)
	if errors.IsNotFound(err) {
		glog.V(4).Infof("ReplicaSet has been deleted %v", key)
		rsc.expectations.DeleteExpectations(key)
		return nil
	}
	if err != nil {
		return err
	}
	
	// 这里是刚才那个计数器的判断逻辑，如果add,del都<=0则返回false
	rsNeedsSync := rsc.expectations.SatisfiedExpectations(key)
	
	// 获得 selector 对象
	selector, err := metav1.LabelSelectorAsSelector(rs.Spec.Selector)
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("Error converting pod selector to selector: %v", err))
		return nil
	}
	
	// Fetch出namespace中所有Pod
	allPods, err := rsc.podLister.Pods(rs.Namespace).List(labels.Everything())
	
	// Ignore inactive pods.
	// 先做了一层过滤，过滤掉没用的Pod
	var filteredPods []*v1.Pod
	for _, pod := range allPods {
		if controller.IsPodActive(pod) {
			filteredPods = append(filteredPods, pod)
		}
	}
	
	// 定义canAdopt方法
	canAdoptFunc := controller.RecheckDeletionTimestamp(func() (metav1.Object, error) {
		fresh, err := rsc.kubeClient.ExtensionsV1beta1().ReplicaSets(rs.Namespace).Get(rs.Name, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}
		if fresh.UID != rs.UID {
			return nil, fmt.Errorf("original ReplicaSet %v/%v is gone: got uid %v, wanted %v", rs.Namespace, rs.Name, fresh.UID, rs.UID)
		}
		return fresh, nil
	})
	// 初始化cm对象用来做pod的具体操作
	cm := controller.NewPodControllerRefManager(rsc.podControl, rs, selector, controllerKind, canAdoptFunc)

	// 这个方法会对Pod进行校验，如果需要adopt的话就会Patch这个pod
	// 如果这个Pod的Selector已经不match了则会把ControllerRef给delete
	filteredPods, err = cm.ClaimPods(filteredPods)
```

这里具体看一下ClaimPods的实现

```
// ClaimPods tries to take ownership of a list of Pods.
//
// It will reconcile the following:
//   * Adopt orphans if the selector matches.
//   * Release owned objects if the selector no longer matches.
//
// Optional: If one or more filters are specified, a Pod will only be claimed if
// all filters return true.
//
// A non-nil error is returned if some form of reconciliation was attemped and
// failed. Usually, controllers should try again later in case reconciliation
// is still needed.
//
// If the error is nil, either the reconciliation succeeded, or no
// reconciliation was necessary. The list of Pods that you now own is returned.
func (m *PodControllerRefManager) ClaimPods(pods []*v1.Pod, filters ...func(*v1.Pod) bool) ([]*v1.Pod, error) {
	var claimed []*v1.Pod
	var errlist []error

	// 定义match方法
	match := func(obj metav1.Object) bool {
		pod := obj.(*v1.Pod)
		// Check selector first so filters only run on potentially matching Pods.
		if !m.selector.Matches(labels.Set(pod.Labels)) {
			return false
		}
		for _, filter := range filters {
			if !filter(pod) {
				return false
			}
		}
		return true
	}
	
	// adopt方法
	adopt := func(obj metav1.Object) error {
		return m.AdoptPod(obj.(*v1.Pod))
	}
	
	// release方法用来删除Ref
	release := func(obj metav1.Object) error {
		return m.ReleasePod(obj.(*v1.Pod))
	}

	for _, pod := range pods {
		// 开始操作具体看下边相机展开
		ok, err := m.claimObject(pod, match, adopt, release)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}
		if ok {
			// 过滤好的加到list里
			claimed = append(claimed, pod)
		}
	}
	return claimed, utilerrors.NewAggregate(errlist)
}
```

看看这句 ``` ok, err := m.claimObject(pod, match, adopt, release) ```

```
func (m *baseControllerRefManager) claimObject(obj metav1.Object, match func(metav1.Object) bool, adopt, release func(metav1.Object) error) (bool, error) {
	controllerRef := GetControllerOf(obj)
	if controllerRef != nil {
		// 首先判断是否属于这个controllerRef
		if controllerRef.UID != m.controller.GetUID() {
			// Owned by someone else. Ignore.
			return false, nil
		}
		
		// 刚才定义的match主要还是看Selector
		if match(obj) {
			// We already own it and the selector matches.
			// Return true (successfully claimed) before checking deletion timestamp.
			// We're still allowed to claim things we already own while being deleted
			// because doing so requires taking no actions.
			return true, nil
		}
		// Owned by us but selector doesn't match.
		// Try to release, unless we're being deleted.
		// 到这里就是Pod不match但是Ref是一样的
		
		if m.controller.GetDeletionTimestamp() != nil {
			return false, nil
		}
		if err := release(obj); err != nil {
			// If the pod no longer exists, ignore the error.
			if errors.IsNotFound(err) {
				return false, nil
			}
			// Either someone else released it, or there was a transient error.
			// The controller should requeue and try again if it's still stale.
			return false, err
		}
		// Successfully released.
		return false, nil
	}

	// It's an orphan.
	if m.controller.GetDeletionTimestamp() != nil || !match(obj) {
		// Ignore if we're being deleted or selector doesn't match.
		return false, nil
	}
	// Selector matches. Try to adopt.
	if err := adopt(obj); err != nil {
		// If the pod no longer exists, ignore the error.
		if errors.IsNotFound(err) {
			return false, nil
		}
		// Either someone else claimed it first, or there was a transient error.
		// The controller should requeue and try again if it's still orphaned.
		return false, err
	}
	// Successfully adopted.
	return true, nil
}
```





