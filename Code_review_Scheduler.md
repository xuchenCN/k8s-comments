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

回头继续看createScheduler()
完成了这个configurator的创建

构建一个schedulerConfigurator对象

```
// Rebuild the configurator with a default Create(...) method.
	configurator = &schedulerConfigurator{
		configurator,
		s.PolicyConfigFile,
		s.AlgorithmProvider}
```

正式构建scheduler

```
scheduler.NewFromConfigurator(configurator, func(cfg *scheduler.Config) {
		cfg.Recorder = recorder
	})
```

创建

```

// NewFromConfigurator returns a new scheduler that is created entirely by the Configurator.  Assumes Create() is implemented.
// Supports intermediate Config mutation for now if you provide modifier functions which will run after Config is created.
func NewFromConfigurator(c Configurator, modifiers ...func(c *Config)) (*Scheduler, error) {
	cfg, err := c.Create()
	if err != nil {
		return nil, err
	}
	// Mutate it if any functions were provided, changes might be required for certain types of tests (i.e. change the recorder).
	for _, modifier := range modifiers {
		modifier(cfg)
	}
	// From this point on the config is immutable to the outside.
	s := &Scheduler{
		config: cfg,
	}
	metrics.Register()
	return s, nil
}
```

c.Create()

```
if _, err := os.Stat(sc.policyFile); err != nil {
		if sc.Configurator != nil {
			return sc.Configurator.CreateFromProvider(sc.algorithmProvider)
		}
		return nil, fmt.Errorf("Configurator was nil")
	}
```

默认启动会调用```sc.Configurator.CreateFromProvider(sc.algorithmProvider)```

这个sc.algorithmProvider要回头看看main()里边的```NewSchedulerServer()```

```
// NewSchedulerServer creates a new SchedulerServer with default parameters
func NewSchedulerServer() *SchedulerServer {
	versioned := &v1alpha1.KubeSchedulerConfiguration{}
	api.Scheme.Default(versioned) //这里会设置default值
	....
}
```

每个API包里的schema都会有SchemaBuilder 例如

```
var (
	SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes, addDefaultingFuncs)
	AddToScheme   = SchemeBuilder.AddToScheme
)
```

这个```addDefaultingFuncs``` 会设置一些默认属性
k8s.io/kubernetes/pkg/apis/componentconfig/v1alpha1/defaults.go 这个文件里设置了```KubeSchedulerConfiguration```

```
func SetDefaults_KubeSchedulerConfiguration(obj *KubeSchedulerConfiguration) {
	if obj.Port == 0 {
		obj.Port = ports.SchedulerPort
	}
	if obj.Address == "" {
		obj.Address = "0.0.0.0"
	}
	if obj.AlgorithmProvider == "" {
		obj.AlgorithmProvider = "DefaultProvider"
	}
	if obj.ContentType == "" {
		obj.ContentType = "application/vnd.kubernetes.protobuf"
	}
	if obj.KubeAPIQPS == 0 {
		obj.KubeAPIQPS = 50.0
	}
	if obj.KubeAPIBurst == 0 {
		obj.KubeAPIBurst = 100
	}
	if obj.SchedulerName == "" {
		obj.SchedulerName = api.DefaultSchedulerName
	}
	if obj.HardPodAffinitySymmetricWeight == 0 {
		obj.HardPodAffinitySymmetricWeight = api.DefaultHardPodAffinitySymmetricWeight
	}
	if obj.FailureDomains == "" {
		obj.FailureDomains = api.DefaultFailureDomains
	}
}
```

所以加载的应该是 ```DefaultProvider```

随后加载这个provider

```
// GetAlgorithmProvider should not be used to modify providers. It is publicly visible for testing.
func GetAlgorithmProvider(name string) (*AlgorithmProviderConfig, error) {
	schedulerFactoryMutex.Lock()
	defer schedulerFactoryMutex.Unlock()

	provider, ok := algorithmProviderMap[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q has not been registered", name)
	}

	return &provider, nil
}
```

这里寻找```algorithmProviderMap["DefaultProvider"]``` 

回头看 k8s.io/kubernetes/plugin/pkg/scheduler/algorithmprovider/defaults/defaults.go这里的init()方法

首先注册 metadata

```
// Register functions that extract metadata used by predicates and priorities computations.
	factory.RegisterPredicateMetadataProducerFactory(
		func(args factory.PluginFactoryArgs) algorithm.MetadataProducer {
			return predicates.NewPredicateMetadataFactory(args.PodLister)
		})
	factory.RegisterPriorityMetadataProducerFactory(
		func(args factory.PluginFactoryArgs) algorithm.MetadataProducer {
			return priorities.PriorityMetadata
		})
```

先看 PredicateMetadata

```
// GetMetadata returns the predicateMetadata used which will be used by various predicates.
func (pfactory *PredicateMetadataFactory) GetMetadata(pod *v1.Pod, nodeNameToInfoMap map[string]*schedulercache.NodeInfo) interface{} {
	// If we cannot compute metadata, just return nil
	if pod == nil {
		return nil
	}
	matchingTerms, err := getMatchingAntiAffinityTerms(pod, nodeNameToInfoMap) //获得AntiAffinity的Node与Term的列表 
	if err != nil {
		return nil
	}
	predicateMetadata := &predicateMetadata{
		pod:                       pod,
		podBestEffort:             isPodBestEffort(pod),
		podRequest:                GetResourceRequest(pod),
		podPorts:                  GetUsedPorts(pod),
		matchingAntiAffinityTerms: matchingTerms,
	}
	//这里的predicatePrecomputations,如果没有自定义应该是没有的
	for predicateName, precomputeFunc := range predicatePrecomputations { 
		glog.V(10).Info("Precompute: %v", predicateName)
		precomputeFunc(predicateMetadata)
	}
	return predicateMetadata
}

```

所以就是这个predicateMeatadata就是这些关键数据
```
pod:                       pod,
podBestEffort:             isPodBestEffort(pod),
podRequest:                GetResourceRequest(pod),
podPorts:                  GetUsedPorts(pod),
matchingAntiAffinityTerms: matchingTerms,
```

看看 PriorityMetadata

```
// priorityMetadata is a type that is passed as metadata for priority functions
type priorityMetadata struct {
	nonZeroRequest *schedulercache.Resource
	podTolerations []v1.Toleration
	affinity       *v1.Affinity
}

// PriorityMetadata is a MetadataProducer.  Node info can be nil.
func PriorityMetadata(pod *v1.Pod, nodeNameToInfo map[string]*schedulercache.NodeInfo) interface{} {
	// If we cannot compute metadata, just return nil
	if pod == nil {
		return nil
	}
	//这里会获得所有 len(toleration.Effect) == 0 || toleration.Effect == v1.TaintEffectPreferNoSchedule 的 toleration
	tolerations, err := getTolerationListFromPod(pod) 
	if err != nil {
		return nil
	}
	return &priorityMetadata{
		//NonZeroRequest是如果没有请求cpu和memory资源的话给予默认的资源量
		//默认DefaultMilliCpuRequest=0.1 
		//默认DefaultMemoryRequest= 200 * 1024 * 1024 //200M
		nonZeroRequest: getNonZeroRequests(pod),
		podTolerations: tolerations,
		//这里是将AffinityInAnootations的Affinity与自带的融合一下
		affinity:       schedulercache.ReconcileAffinity(pod),
	}
}
```

至此Predicate,Priority的两个Metadata组织完毕，接下来就是注册对应Provider的算法，默认使用的是DefaultProvider

```
// Registers algorithm providers. By default we use 'DefaultProvider', but user can specify one to be used
// by specifying flag.
factory.RegisterAlgorithmProvider(factory.DefaultProvider, defaultPredicates(), defaultPriorities())
```

首先看看默认的Predicates

```

func defaultPredicates() sets.String {
	return sets.NewString(
		// Fit is determined by volume zone requirements.
		factory.RegisterFitPredicateFactory(
			"NoVolumeZoneConflict",
			func(args factory.PluginFactoryArgs) algorithm.FitPredicate {
				return predicates.NewVolumeZonePredicate(args.PVInfo, args.PVCInfo)
			},
		),
		// Fit is determined by whether or not there would be too many AWS EBS volumes attached to the node
		factory.RegisterFitPredicateFactory(
			"MaxEBSVolumeCount",
			func(args factory.PluginFactoryArgs) algorithm.FitPredicate {
				// TODO: allow for generically parameterized scheduler predicates, because this is a bit ugly
				maxVols := getMaxVols(aws.DefaultMaxEBSVolumes)
				return predicates.NewMaxPDVolumeCountPredicate(predicates.EBSVolumeFilter, maxVols, args.PVInfo, args.PVCInfo)
			},
		),
		// Fit is determined by whether or not there would be too many GCE PD volumes attached to the node
		factory.RegisterFitPredicateFactory(
			"MaxGCEPDVolumeCount",
			func(args factory.PluginFactoryArgs) algorithm.FitPredicate {
				// TODO: allow for generically parameterized scheduler predicates, because this is a bit ugly
				maxVols := getMaxVols(DefaultMaxGCEPDVolumes)
				return predicates.NewMaxPDVolumeCountPredicate(predicates.GCEPDVolumeFilter, maxVols, args.PVInfo, args.PVCInfo)
			},
		),
		// Fit is determined by whether or not there would be too many Azure Disk volumes attached to the node
		factory.RegisterFitPredicateFactory(
			"MaxAzureDiskVolumeCount",
			func(args factory.PluginFactoryArgs) algorithm.FitPredicate {
				// TODO: allow for generically parameterized scheduler predicates, because this is a bit ugly
				maxVols := getMaxVols(DefaultMaxAzureDiskVolumes)
				return predicates.NewMaxPDVolumeCountPredicate(predicates.AzureDiskVolumeFilter, maxVols, args.PVInfo, args.PVCInfo)
			},
		),
		// Fit is determined by inter-pod affinity.
		factory.RegisterFitPredicateFactory(
			"MatchInterPodAffinity",
			func(args factory.PluginFactoryArgs) algorithm.FitPredicate {
				return predicates.NewPodAffinityPredicate(args.NodeInfo, args.PodLister)
			},
		),

		// Fit is determined by non-conflicting disk volumes.
		factory.RegisterFitPredicate("NoDiskConflict", predicates.NoDiskConflict),

		// GeneralPredicates are the predicates that are enforced by all Kubernetes components
		// (e.g. kubelet and all schedulers)
		factory.RegisterFitPredicate("GeneralPredicates", predicates.GeneralPredicates),

		// Fit is determined based on whether a pod can tolerate all of the node's taints
		factory.RegisterFitPredicate("PodToleratesNodeTaints", predicates.PodToleratesNodeTaints),

		// Fit is determined by node memory pressure condition.
		factory.RegisterFitPredicate("CheckNodeMemoryPressure", predicates.CheckNodeMemoryPressurePredicate),

		// Fit is determined by node disk pressure condition.
		factory.RegisterFitPredicate("CheckNodeDiskPressure", predicates.CheckNodeDiskPressurePredicate),
	)
}
```

注册方法是这样的

```
// RegisterFitPredicate registers a fit predicate with the algorithm
// registry. Returns the name with which the predicate was registered.
func RegisterFitPredicate(name string, predicate algorithm.FitPredicate) string {
	return RegisterFitPredicateFactory(name, func(PluginFactoryArgs) algorithm.FitPredicate { return predicate })
}

// RegisterFitPredicateFactory registers a fit predicate factory with the
// algorithm registry. Returns the name with which the predicate was registered.
func RegisterFitPredicateFactory(name string, predicateFactory FitPredicateFactory) string {
	schedulerFactoryMutex.Lock()
	defer schedulerFactoryMutex.Unlock()
	validateAlgorithmNameOrDie(name)
	fitPredicateMap[name] = predicateFactory
	return name
}
```

其中两个关键的参数是 

```
// PluginFactoryArgs are passed to all plugin factory functions.
type PluginFactoryArgs struct {
	PodLister                      algorithm.PodLister
	ServiceLister                  algorithm.ServiceLister
	ControllerLister               algorithm.ControllerLister
	ReplicaSetLister               algorithm.ReplicaSetLister
	StatefulSetLister              algorithm.StatefulSetLister
	NodeLister                     algorithm.NodeLister
	NodeInfo                       predicates.NodeInfo
	PVInfo                         predicates.PersistentVolumeInfo
	PVCInfo                        predicates.PersistentVolumeClaimInfo
	HardPodAffinitySymmetricWeight int
}

// FitPredicate is a function that indicates if a pod fits into an existing node.
// The failure information is given by the error.
// TODO: Change interface{} to a specific type.
type FitPredicate func(pod *v1.Pod, meta interface{}, nodeInfo *schedulercache.NodeInfo) (bool, []PredicateFailureReason, error)

```

所以 defaultPredicates 是返回了一个Sets 里边有注册好的 FitPredicateFactory，对应了

```
NoVolumeZoneConflict
MaxEBSVolumeCount
MaxGCEPDVolumeCount
MatchInterPodAffinity
NoDiskConflict
GeneralPredicates
PodToleratesNodeTaints
CheckNodeMemoryPressure
CheckNodeDiskPressure
```

再看看 defaultPriorities()

```
// spreads pods by minimizing the number of pods (belonging to the same service or replication controller) on the same node.
		factory.RegisterPriorityConfigFactory(
			"SelectorSpreadPriority",
			factory.PriorityConfigFactory{
				Function: func(args factory.PluginFactoryArgs) algorithm.PriorityFunction {
					return priorities.NewSelectorSpreadPriority(args.ServiceLister, args.ControllerLister, args.ReplicaSetLister, args.StatefulSetLister)
				},
				Weight: 1,
			},
		),
```

Priority目前已经转向Map-Reduce的打分方式了

```
// DEPRECATED
// Use Map-Reduce pattern for priority functions.
// A PriorityFunctionFactory produces a PriorityConfig from the given args.
// 这个是之前老的函数，传入一个pod,nodes进行打分
type PriorityFunctionFactory func(PluginFactoryArgs) algorithm.PriorityFunction

// A PriorityFunctionFactory produces map & reduce priority functions
// from a given args.
// FIXME: Rename to PriorityFunctionFactory.
// 这个是新的方法用MapFunction 和 ReduceFunction来打分提高性能也更可控
type PriorityFunctionFactory2 func(PluginFactoryArgs) (algorithm.PriorityMapFunction, algorithm.PriorityReduceFunction)

// A PriorityConfigFactory produces a PriorityConfig from the given function and weight
type PriorityConfigFactory struct {
	Function          PriorityFunctionFactory
	MapReduceFunction PriorityFunctionFactory2
	//这个是权重值，不同的Priority有不同的值
	Weight            int
}

// PriorityMapFunction is a function that computes per-node results for a given node.
// TODO: Figure out the exact API of this method.
// TODO: Change interface{} to a specific type.
// 这里跟之前的很像不过是一个pod与node一对一打分，可以并行执行。
type PriorityMapFunction func(pod *v1.Pod, meta interface{}, nodeInfo *schedulercache.NodeInfo) (schedulerapi.HostPriority, error)

// PriorityReduceFunction is a function that aggregated per-node results and computes
// final scores for all nodes.
// TODO: Figure out the exact API of this method.
// TODO: Change interface{} to a specific type.
// 这里是Reduce方法，将这个Pod对于node所打的分汇总
type PriorityReduceFunction func(pod *v1.Pod, meta interface{}, nodeNameToInfo map[string]*schedulercache.NodeInfo, result schedulerapi.HostPriorityList) error

```

所以defaultPriorities()方法注册了如下 priority 的操作

```
SelectorSpreadPriority
InterPodAffinityPriority
LeastRequestedPriority
BalancedResourceAllocation
NodePreferAvoidPodsPriority
NodeAffinityPriority
TaintTolerationPriority
```

对于 ClusterAutoscalerProver

```
// Cluster autoscaler friendly scheduling algorithm.
	factory.RegisterAlgorithmProvider(ClusterAutoscalerProvider, defaultPredicates(),
		copyAndReplace(defaultPriorities(), "LeastRequestedPriority", "MostRequestedPriority"))
```

随后注册了一些默认Predicate里没有的

```
	// Registers predicates and priorities that are not enabled by default, but user can pick when creating his
	// own set of priorities/predicates.

	// PodFitsPorts has been replaced by PodFitsHostPorts for better user understanding.
	// For backwards compatibility with 1.0, PodFitsPorts is registered as well.
	factory.RegisterFitPredicate("PodFitsPorts", predicates.PodFitsHostPorts)
	// Fit is defined based on the absence of port conflicts.
	// This predicate is actually a default predicate, because it is invoked from
	// predicates.GeneralPredicates()
	factory.RegisterFitPredicate("PodFitsHostPorts", predicates.PodFitsHostPorts)
	// Fit is determined by resource availability.
	// This predicate is actually a default predicate, because it is invoked from
	// predicates.GeneralPredicates()
	factory.RegisterFitPredicate("PodFitsResources", predicates.PodFitsResources)
	// Fit is determined by the presence of the Host parameter and a string match
	// This predicate is actually a default predicate, because it is invoked from
	// predicates.GeneralPredicates()
	factory.RegisterFitPredicate("HostName", predicates.PodFitsHost)
	// Fit is determined by node selector query.
	factory.RegisterFitPredicate("MatchNodeSelector", predicates.PodSelectorMatches)
```

这个暂时不知道用来做什么，只是获得了一个Pod里边包含另一个Pod的Controller

```
// Use equivalence class to speed up predicates & priorities
	factory.RegisterGetEquivalencePodFunction(GetEquivalencePod)
```

还有一些Priority的算法

```
// ServiceSpreadingPriority is a priority config factory that spreads pods by minimizing
	// the number of pods (belonging to the same service) on the same node.
	// Register the factory so that it's available, but do not include it as part of the default priorities
	// Largely replaced by "SelectorSpreadPriority", but registered for backward compatibility with 1.0
	factory.RegisterPriorityConfigFactory(
		"ServiceSpreadingPriority",
		factory.PriorityConfigFactory{
			Function: func(args factory.PluginFactoryArgs) algorithm.PriorityFunction {
				return priorities.NewSelectorSpreadPriority(args.ServiceLister, algorithm.EmptyControllerLister{}, algorithm.EmptyReplicaSetLister{}, algorithm.EmptyStatefulSetLister{})
			},
			Weight: 1,
		},
	)

	// EqualPriority is a prioritizer function that gives an equal weight of one to all nodes
	// Register the priority function so that its available
	// but do not include it as part of the default priorities
	factory.RegisterPriorityFunction2("EqualPriority", core.EqualPriorityMap, nil, 1)
	// ImageLocalityPriority prioritizes nodes based on locality of images requested by a pod. Nodes with larger size
	// of already-installed packages required by the pod will be preferred over nodes with no already-installed
	// packages required by the pod or a small total size of already-installed packages required by the pod.
	factory.RegisterPriorityFunction2("ImageLocalityPriority", priorities.ImageLocalityPriorityMap, nil, 1)
	// Optional, cluster-autoscaler friendly priority function - give used nodes higher priority.
	factory.RegisterPriorityFunction2("MostRequestedPriority", priorities.MostRequestedPriorityMap, nil, 1)
```

至此貌似所有的算法都注册完成了

回到之前的地方

```
type AlgorithmProviderConfig struct {
	FitPredicateKeys     sets.String
	PriorityFunctionKeys sets.String
}
// 这里的 provider 是AlgorithmProviderConfig
provider, ok := algorithmProviderMap[name]
```

随后看看最后创建scheduler.Config的过程

```
return f.CreateFromKeys(provider.FitPredicateKeys, provider.PriorityFunctionKeys, []algorithm.SchedulerExtender{})
```

```

// Creates a scheduler from a set of registered fit predicate keys and priority keys.
func (f *ConfigFactory) CreateFromKeys(predicateKeys, priorityKeys sets.String, extenders []algorithm.SchedulerExtender) (*scheduler.Config, error) {
	glog.V(2).Infof("Creating scheduler with fit predicates '%v' and priority functions '%v", predicateKeys, priorityKeys)

	if f.GetHardPodAffinitySymmetricWeight() < 0 || f.GetHardPodAffinitySymmetricWeight() > 100 {
		return nil, fmt.Errorf("invalid hardPodAffinitySymmetricWeight: %d, must be in the range 0-100", f.GetHardPodAffinitySymmetricWeight())
	}
	// 这里会返回 map[string]algorithm.FitPredicate
	predicateFuncs, err := f.GetPredicates(predicateKeys)
	if err != nil {
		return nil, err
	}
	// 这里返回 []algorithm.PriorityConfig
	priorityConfigs, err := f.GetPriorityFunctionConfigs(priorityKeys)
	if err != nil {
		return nil, err
	}
	
	// 返回priorityMetadata
	priorityMetaProducer, err := f.GetPriorityMetadataProducer()
	if err != nil {
		return nil, err
	}
	
	// 返回predicateMetadata
	predicateMetaProducer, err := f.GetPredicateMetadataProducer()
	if err != nil {
		return nil, err
	}
	
	// 这里启动会开始向队列里推送pod
	f.Run()
	
	// 这里正是创建Scheduler对象
	algo := core.NewGenericScheduler(f.schedulerCache, predicateFuncs, predicateMetaProducer, priorityConfigs, priorityMetaProducer, extenders)
	podBackoff := util.CreateDefaultPodBackoff()
	return &scheduler.Config{
		SchedulerCache: f.schedulerCache,
		// The scheduler only needs to consider schedulable nodes.
		NodeLister:          &nodePredicateLister{f.nodeLister},
		Algorithm:           algo,
		Binder:              &binder{f.client},
		PodConditionUpdater: &podConditionUpdater{f.client},
		NextPod: func() *v1.Pod {
			return f.getNextPod()
		},
		Error:          f.MakeDefaultErrorFunc(podBackoff, f.podQueue),
		StopEverything: f.StopEverything,
	}, nil
}
```

f.Run()

```
func (f *ConfigFactory) Run() {
	// Watch and queue pods that need scheduling.
	cache.NewReflector(f.createUnassignedNonTerminatedPodLW(), &v1.Pod{}, f.podQueue, 0).RunUntil(f.StopEverything)

	// Begin populating scheduled pods.
	go f.scheduledPodPopulator.Run(f.StopEverything)
}
```

algo := core.NewGenericScheduler(f.schedulerCache, predicateFuncs, predicateMetaProducer, priorityConfigs, priorityMetaProducer, extenders)

```
func NewGenericScheduler(
	cache schedulercache.Cache,
	predicates map[string]algorithm.FitPredicate,
	predicateMetaProducer algorithm.MetadataProducer,
	prioritizers []algorithm.PriorityConfig,
	priorityMetaProducer algorithm.MetadataProducer,
	extenders []algorithm.SchedulerExtender) algorithm.ScheduleAlgorithm {
	return &genericScheduler{
		cache:                 cache,
		predicates:            predicates,
		predicateMetaProducer: predicateMetaProducer,
		prioritizers:          prioritizers,
		priorityMetaProducer:  priorityMetaProducer,
		extenders:             extenders,
		cachedNodeInfoMap:     make(map[string]*schedulercache.NodeInfo),
	}
}
```

完成了一系列的创建设置最后返回了一个 scheduler.Config

```
&scheduler.Config{
		SchedulerCache: f.schedulerCache,
		// The scheduler only needs to consider schedulable nodes.
		NodeLister:          &nodePredicateLister{f.nodeLister},
		Algorithm:           algo,
		Binder:              &binder{f.client},
		PodConditionUpdater: &podConditionUpdater{f.client},
		NextPod: func() *v1.Pod {
			return f.getNextPod()
		},
		Error:          f.MakeDefaultErrorFunc(podBackoff, f.podQueue),
		StopEverything: f.StopEverything,
	}
```

scheduler.Config 结构体

```
// TODO over time we should make this struct a hidden implementation detail of the scheduler.
type Config struct {
	// It is expected that changes made via SchedulerCache will be observed
	// by NodeLister and Algorithm.
	SchedulerCache schedulercache.Cache
	NodeLister     algorithm.NodeLister
	Algorithm      algorithm.ScheduleAlgorithm
	Binder         Binder
	// PodConditionUpdater is used only in case of scheduling errors. If we succeed
	// with scheduling, PodScheduled condition will be updated in apiserver in /bind
	// handler so that binding and setting PodCondition it is atomic.
	PodConditionUpdater PodConditionUpdater

	// NextPod should be a function that blocks until the next pod
	// is available. We don't use a channel for this, because scheduling
	// a pod may take some amount of time and we don't want pods to get
	// stale while they sit in a channel.
	NextPod func() *v1.Pod

	// Error is called if there is an error. It is passed the pod in
	// question, and the error
	Error func(*v1.Pod, error)

	// Recorder is the EventRecorder to use
	Recorder record.EventRecorder

	// Close this to shut down the scheduler.
	StopEverything chan struct{}
}
```

回头看 c.Create()

```
// NewFromConfigurator returns a new scheduler that is created entirely by the Configurator.  Assumes Create() is implemented.
// Supports intermediate Config mutation for now if you provide modifier functions which will run after Config is created.
func NewFromConfigurator(c Configurator, modifiers ...func(c *Config)) (*Scheduler, error) {
	cfg, err := c.Create()
	if err != nil {
		return nil, err
	}
	// Mutate it if any functions were provided, changes might be required for certain types of tests (i.e. change the recorder).
	for _, modifier := range modifiers {
		modifier(cfg)
	}
	// From this point on the config is immutable to the outside.
	s := &Scheduler{
		config: cfg,
	}
	metrics.Register()
	return s, nil
}
```

注册 metrics

```
var registerMetrics sync.Once

// Register all metrics.
func Register() {
	// Register the metrics.
	registerMetrics.Do(func() {
		prometheus.MustRegister(E2eSchedulingLatency)
		prometheus.MustRegister(SchedulingAlgorithmLatency)
		prometheus.MustRegister(BindingLatency)
	})
}
```

scheduler 初始化完成

```
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

随后是启动Http的一些服务

```
func startHTTP(s *options.SchedulerServer) {
	mux := http.NewServeMux()
	healthz.InstallHandler(mux)
	if s.EnableProfiling {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
		if s.EnableContentionProfiling {
			goruntime.SetBlockProfileRate(1)
		}
	}
	if c, err := configz.New("componentconfig"); err == nil {
		c.Set(s.KubeSchedulerConfiguration)
	} else {
		glog.Errorf("unable to register configz: %s", err)
	}
	configz.InstallHandler(mux)
	mux.Handle("/metrics", prometheus.Handler())

	server := &http.Server{
		Addr:    net.JoinHostPort(s.Address, strconv.Itoa(int(s.Port))),
		Handler: mux,
	}
	glog.Fatal(server.ListenAndServe())
}
```

随后是启动和选举动作

```
	stop := make(chan struct{})
	defer close(stop)
	// 启动informer
	informerFactory.Start(stop)
	// 定义了 run 方法后续会运行scheduler.run
	run := func(_ <-chan struct{}) {
		sched.Run()
		select {}
	}
	// 如果没开启选举，直接运行
	if !s.LeaderElection.LeaderElect {
		run(nil)
		panic("unreachable")
	}
	// 获得hostname用于选举
	id, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("unable to get hostname: %v", err)
	}
	
	// 创建了一个 EndpointLock
	// TODO: enable other lock types
	rl := &resourcelock.EndpointsLock{
		EndpointsMeta: metav1.ObjectMeta{
			Namespace: "kube-system",
			Name:      "kube-scheduler",
		},
		Client: kubecli,
		LockConfig: resourcelock.ResourceLockConfig{
			Identity:      id,
			EventRecorder: recorder,
		},
	}
	
	// 开始选举
	leaderelection.RunOrDie(leaderelection.LeaderElectionConfig{
		Lock:          rl,
		LeaseDuration: s.LeaderElection.LeaseDuration.Duration,
		RenewDeadline: s.LeaderElection.RenewDeadline.Duration,
		RetryPeriod:   s.LeaderElection.RetryPeriod.Duration,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: run,
			OnStoppedLeading: func() {
				glog.Fatalf("lost master")
			},
		},
	})

	panic("unreachable")
```

执行 scheduler

```
// Run begins watching and scheduling. It starts a goroutine and returns immediately.
func (s *Scheduler) Run() {
	go wait.Until(s.scheduleOne, 0, s.config.StopEverything)
}
```

func (s *Scheduler) scheduleOne() 正式开始调度pod

```
// 从FIFO队列中获得一个未分配且未关闭的Pod
pod := s.config.NextPod()

// 如果这个Pod已经标记为删除状态则不会进行调度
if pod.DeletionTimestamp != nil {
		s.config.Recorder.Eventf(pod, v1.EventTypeWarning, "FailedScheduling", "skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
		glog.V(3).Infof("Skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
		return
	}
	
// 开始调度，默认使用的是 genericScheduler
dest, err := s.config.Algorithm.Schedule(pod, s.config.NodeLister)
```

查看 Scheduler() 

```
func (g *genericScheduler) Schedule(pod *v1.Pod, nodeLister algorithm.NodeLister) (string, error) 
...
// 首先将cache里最新的[]nodeInfo 都导入到 cachedNodeInfoMap map[string]*schedulercache.NodeInfo 中
// 当cache中没有的删除cachedNodeInfoMap中的数据
err = g.cache.UpdateNodeNameToInfoMap(g.cachedNodeInfoMap)

// 正式开始计算 predicate 
filteredNodes, failedPredicateMap, err := findNodesThatFit(pod, g.cachedNodeInfoMap, nodes, g.predicates, g.extenders, g.predicateMetaProducer)

```

查看 findNodesThatFit

```
var filtered []*v1.Node
	failedPredicateMap := FailedPredicateMap{}

	if len(predicateFuncs) == 0 {
		filtered = nodes
	} else {
		// Create filtered list with enough space to avoid growing it
		// and allow assigning.
		filtered = make([]*v1.Node, len(nodes))
		errs := []error{}
		var predicateResultLock sync.Mutex
		var filteredLen int32

		// We can use the same metadata producer for all nodes.
		// 创建meta
		meta := metadataProducer(pod, nodeNameToInfo)
		// chechNode方法
		checkNode := func(i int) {
			nodeName := nodes[i].Name
			// 这里会走一遍所有的predicate方法并记录被过滤掉的原因
			fits, failedPredicates, err := podFitsOnNode(pod, meta, nodeNameToInfo[nodeName], predicateFuncs)
			if err != nil {
				predicateResultLock.Lock()
				errs = append(errs, err)
				predicateResultLock.Unlock()
				return
			}
			if fits {
				// Node可以fit 自增 filteredLen 随后记录 filtered
				filtered[atomic.AddInt32(&filteredLen, 1)-1] = nodes[i]
			} else {
				// Node 无法fit 记录原因
				predicateResultLock.Lock()
				failedPredicateMap[nodeName] = failedPredicates
				predicateResultLock.Unlock()
			}
		}
		// 并行处理 chechNode
		workqueue.Parallelize(16, len(nodes), checkNode)
		// 获得最终 filtered 数据
		filtered = filtered[:filteredLen]
		// 处理错误
		if len(errs) > 0 {
			return []*v1.Node{}, FailedPredicateMap{}, errors.NewAggregate(errs)
		}
	}
	
	// 当有extender的filter时进行扩展的filter方法
	if len(filtered) > 0 && len(extenders) != 0 {
		for _, extender := range extenders {
			filteredList, failedMap, err := extender.Filter(pod, filtered, nodeNameToInfo)
			if err != nil {
				return []*v1.Node{}, FailedPredicateMap{}, err
			}

			for failedNodeName, failedMsg := range failedMap {
				if _, found := failedPredicateMap[failedNodeName]; !found {
					failedPredicateMap[failedNodeName] = []algorithm.PredicateFailureReason{}
				}
				failedPredicateMap[failedNodeName] = append(failedPredicateMap[failedNodeName], predicates.NewFailureReason(failedMsg))
			}
			filtered = filteredList
			if len(filtered) == 0 {
				break
			}
		}
	}
	return filtered, failedPredicateMap, nil
```

至此完成了 predicate 操作，过滤掉了pod不能放置的Node,随后看看priority的动作

```
// 先构建 Metadata
metaPrioritiesInterface := g.priorityMetaProducer(pod, g.cachedNodeInfoMap)
// 开始打分
priorityList, err := PrioritizeNodes(pod, g.cachedNodeInfoMap, metaPrioritiesInterface, g.prioritizers, filteredNodes, g.extenders)
```

查看具体过程

```
// Prioritizes the nodes by running the individual priority functions in parallel.
// Each priority function is expected to set a score of 0-10
// 0 is the lowest priority score (least preferred node) and 10 is the highest
// Each priority function can also have its own weight
// The node scores returned by the priority function are multiplied by the weights to get weighted scores
// All scores are finally combined (added) to get the total weighted scores of all nodes
func PrioritizeNodes(
	pod *v1.Pod,
	nodeNameToInfo map[string]*schedulercache.NodeInfo,
	meta interface{},
	priorityConfigs []algorithm.PriorityConfig,
	nodes []*v1.Node,
	extenders []algorithm.SchedulerExtender,
) (schedulerapi.HostPriorityList, error) {
	// If no priority configs are provided, then the EqualPriority function is applied
	// This is required to generate the priority list in the required format
	
	// 先做一次校验，如果没有priorityConfigs和extenders那就全部打1分
	if len(priorityConfigs) == 0 && len(extenders) == 0 {
		result := make(schedulerapi.HostPriorityList, 0, len(nodes))
		for i := range nodes {
			hostPriority, err := EqualPriorityMap(pod, meta, nodeNameToInfo[nodes[i].Name])
			if err != nil {
				return nil, err
			}
			result = append(result, hostPriority)
		}
		return result, nil
	}

	var (
		mu   = sync.Mutex{}
		wg   = sync.WaitGroup{}
		errs []error
	)
	appendError := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		errs = append(errs, err)
	}
	
	// 构建results先把所有元素初始化为nil
	results := make([]schedulerapi.HostPriorityList, 0, len(priorityConfigs))
	for range priorityConfigs {
		results = append(results, nil)
	}
	// 首先是判断是否用的老的Function方式，这种方式使用waitgroup来进行
	for i, priorityConfig := range priorityConfigs {
		if priorityConfig.Function != nil {
			// DEPRECATED
			wg.Add(1)
			go func(index int, config algorithm.PriorityConfig) {
				defer wg.Done()
				var err error
				results[index], err = config.Function(pod, nodeNameToInfo, nodes)
				if err != nil {
					appendError(err)
				}
			}(i, priorityConfig)
		} else {
			// 如果用的map-reduce方法则先构建 result[i] 对应的 []HostPriorityList
			results[i] = make(schedulerapi.HostPriorityList, len(nodes))
		}
	}
	// 这个就是Map方法了
	processNode := func(index int) {
		nodeInfo := nodeNameToInfo[nodes[index].Name]
		var err error
		for i := range priorityConfigs {
                        // 如果有Function说明用的是老的方案，则跳过
			if priorityConfigs[i].Function != nil {
				continue
			}
                        // 调用priorityConfigs.Map方法
			results[i][index], err = priorityConfigs[i].Map(pod, meta, nodeInfo)
			if err != nil {
				appendError(err)
				return
			}
		}
	}
	// 并行处理 Map
	workqueue.Parallelize(16, len(nodes), processNode)
	
	// 开始进行Reducle
	for i, priorityConfig := range priorityConfigs {
		if priorityConfig.Reduce == nil {
			continue
		}
		// 这里用的wg是雨Function为同一个，因为要做到串行处理
		wg.Add(1)
		go func(index int, config algorithm.PriorityConfig) {
			defer wg.Done()
			if err := config.Reduce(pod, meta, nodeNameToInfo, results[index]); err != nil {
				appendError(err)
			}
		}(i, priorityConfig)
	}
	// Wait for all computations to be finished.
	wg.Wait()
	if len(errs) != 0 {
		return schedulerapi.HostPriorityList{}, errors.NewAggregate(errs)
	}

	// Summarize all scores.
	result := make(schedulerapi.HostPriorityList, 0, len(nodes))
	// TODO: Consider parallelizing it.
	for i := range nodes {
		result = append(result, schedulerapi.HostPriority{Host: nodes[i].Name, Score: 0})
		for j := range priorityConfigs {
			result[i].Score += results[j][i].Score * priorityConfigs[j].Weight
		}
	}

	if len(extenders) != 0 && nodes != nil {
		combinedScores := make(map[string]int, len(nodeNameToInfo))
		for _, extender := range extenders {
			wg.Add(1)
			go func(ext algorithm.SchedulerExtender) {
				defer wg.Done()
				prioritizedList, weight, err := ext.Prioritize(pod, nodes)
				if err != nil {
					// Prioritization errors from extender can be ignored, let k8s/other extenders determine the priorities
					return
				}
				mu.Lock()
				for i := range *prioritizedList {
					host, score := (*prioritizedList)[i].Host, (*prioritizedList)[i].Score
					combinedScores[host] += score * weight
				}
				mu.Unlock()
			}(extender)
		}
		// wait for all go routines to finish
		wg.Wait()
		for i := range result {
			result[i].Score += combinedScores[result[i].Host]
		}
	}

	if glog.V(10) {
		for i := range result {
			glog.V(10).Infof("Host %s => Score %d", result[i].Host, result[i].Score)
		}
	}
	return result, nil
}
```
