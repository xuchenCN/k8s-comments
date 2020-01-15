## 观察kube-scheduler的工作流程，该版本基于1.17.rc.2
由于新的调度器增加了extenderpoints功能，一些调度的关键环节支持插件式的工作模式，具体参考文档
https://github.com/kubernetes/enhancements/blob/master/keps/sig-scheduling/20180409-scheduling-framework.md
![scheduler-framework](https://github.com/kubernetes/enhancements/raw/master/keps/sig-scheduling/20180409-scheduling-framework-extensions.png)

首先还是入口文件 k8s.io/kubernetes/cmd/kube-scheduler/scheduler.go
在初始化的时候

```
// NewSchedulerCommand creates a *cobra.Command object with default parameters and registryOptions
func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {
	opts, err := options.NewOptions()
```

这个NewOptions() 展开来看

```
func newDefaultComponentConfig() (*kubeschedulerconfig.KubeSchedulerConfiguration, error) {
	cfgv1alpha1 := kubeschedulerconfigv1alpha1.KubeSchedulerConfiguration{}
	kubeschedulerscheme.Scheme.Default(&cfgv1alpha1)
	cfg := kubeschedulerconfig.KubeSchedulerConfiguration{}
	if err := kubeschedulerscheme.Scheme.Convert(&cfgv1alpha1, &cfg, nil); err != nil {
		return nil, err
	}
	return &cfg, nil
}
```

依然是通过Scheme来初始化默认的config实际调用的是
src/k8s.io/kubernetes/pkg/scheduler/apis/config/v1alpha1/defaults.go

SetDefaults_KubeSchedulerConfiguration()

设置好默认的kubeschedulerconfig回国头来看func NewOptions() (*Options, error) 

```
// NewOptions returns default scheduler app options.
func NewOptions() (*Options, error) {
        // 初始化了默认的configu
	cfg, err := newDefaultComponentConfig()
	if err != nil {
		return nil, err
	}

	hhost, hport, err := splitHostIntPort(cfg.HealthzBindAddress)
	if err != nil {
		return nil, err
	}
        // 这里初始化了一些与服务相关的属性，用到了apiserver的一些验证机制，为/healthz提供服务，后续展开
	o := &Options{
		ComponentConfig: *cfg,
		SecureServing:   apiserveroptions.NewSecureServingOptions().WithLoopback(),
		CombinedInsecureServing: &CombinedInsecureServingOptions{
			Healthz: (&apiserveroptions.DeprecatedInsecureServingOptions{
				BindNetwork: "tcp",
			}).WithLoopback(),
			Metrics: (&apiserveroptions.DeprecatedInsecureServingOptions{
				BindNetwork: "tcp",
			}).WithLoopback(),
			BindPort:    hport,
			BindAddress: hhost,
		},
		Authentication: apiserveroptions.NewDelegatingAuthenticationOptions(),
		Authorization:  apiserveroptions.NewDelegatingAuthorizationOptions(),
		Deprecated: &DeprecatedOptions{
			UseLegacyPolicyConfig:    false,
			PolicyConfigMapNamespace: metav1.NamespaceSystem,
		},
	}

	o.Authentication.TolerateInClusterLookupFailure = true
	o.Authentication.RemoteKubeConfigFileOptional = true
	o.Authorization.RemoteKubeConfigFileOptional = true
	o.Authorization.AlwaysAllowPaths = []string{"/healthz"}

	// Set the PairName but leave certificate directory blank to generate in-memory by default
	o.SecureServing.ServerCert.CertDirectory = ""
	o.SecureServing.ServerCert.PairName = "kube-scheduler"
	o.SecureServing.BindPort = ports.KubeSchedulerPort

	return o, nil
}
```

回到 NewSchedulerCommand()，初始化好了option随后就是各种设置flags

这里把不同组件的flags放到flagset中去设置

```
// NewSchedulerCommand creates a *cobra.Command object with default parameters and registryOptions
func NewSchedulerCommand(registryOptions ...Option) *cobra.Command {
        //初始化的option
	opts, err := options.NewOptions()
	if err != nil {
		klog.Fatalf("unable to initialize command options: %v", err)
	}
        // 设置cmd
	cmd := &cobra.Command{
		Use: "kube-scheduler",
		Long: `.....`,
                // 实际的Run方法
		Run: func(cmd *cobra.Command, args []string) {
			if err := runCommand(cmd, args, opts, registryOptions...); err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				os.Exit(1)
			}
		},
	}
        // 获得flags
	fs := cmd.Flags()
        // 这里会初始化一个name->FlagSet的结构
        // 并且将option里的flags设置上其中包括
        // 一些misc,SecureServing,CombinedInsecureServing,Authentication,Authorization,leaderelection还有featuregate
	namedFlagSets := opts.Flags()
        // version
	verflag.AddFlags(namedFlagSets.FlagSet("global"))
        // 一些global的flag
	globalflag.AddGlobalFlags(namedFlagSets.FlagSet("global"), cmd.Name())
        // 放到cmd.flags上
	for _, f := range namedFlagSets.FlagSets {
		fs.AddFlagSet(f)
	}

	usageFmt := "Usage:\n  %s\n"
	cols, _, _ := term.TerminalSize(cmd.OutOrStdout())

        // 后续就是cmd相关的设置
	cmd.SetUsageFunc(func(cmd *cobra.Command) error {
		fmt.Fprintf(cmd.OutOrStderr(), usageFmt, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStderr(), namedFlagSets, cols)
		return nil
	})
	cmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\n\n"+usageFmt, cmd.Long, cmd.UseLine())
		cliflag.PrintSections(cmd.OutOrStdout(), namedFlagSets, cols)
	})
	cmd.MarkFlagFilename("config", "yaml", "yml", "json")

	return cmd
}
```

至此呢就是设置了相关的选项，开始正式运行```runCommand()```

首先查看是否是打了version,随后输出flags

```
verflag.PrintAndExitIfRequested()
utilflag.PrintFlags(cmd.Flags())
```

对opts进行验证

```
if errs := opts.Validate(); len(errs) > 0 {
	return utilerrors.NewAggregate(errs)
}
```

如果有opts.WriteConfigTo则把配置文件写入到指定的文件夹中


```
if len(opts.WriteConfigTo) > 0 {
	c := &schedulerserverconfig.Config{}
	if err := opts.ApplyTo(c); err != nil {
		return err
	}
	if err := options.WriteConfigFile(opts.WriteConfigTo, &c.ComponentConfig); err != nil {
		return err
	}
	klog.Infof("Wrote configuration to: %s\n", opts.WriteConfigTo)
	return nil
}

```

随后生成Config

```
c, err := opts.Config()
```

该方法展开 

```
// Config return a scheduler config object
func (o *Options) Config() (*schedulerappconfig.Config, error) {
	// 查看是否需要进行自签名证书生成
	if o.SecureServing != nil {
		if err := o.SecureServing.MaybeDefaultWithSelfSignedCerts("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
			return nil, fmt.Errorf("error creating self-signed certificates: %v", err)
		}
	}
	
	c := &schedulerappconfig.Config{}
	// 设置kubeschedulerconfig, SecureServing(authentication, authorization), Insecureserving最好不要用了这里不讲了
	if err := o.ApplyTo(c); err != nil {
		return nil, err
	}

	// Prepare kube clients.
	// 这里返回了与apiserver交互的client, 选举用client, 还有eventClient
	client, leaderElectionClient, eventClient, err := createClients(c.ComponentConfig.ClientConnection, o.Master, c.ComponentConfig.LeaderElection.RenewDeadline.Duration)
	if err != nil {
		return nil, err
	}

	// 生成coreBroadcaster
	coreBroadcaster := record.NewBroadcaster()
	coreRecorder := coreBroadcaster.NewRecorder(scheme.Scheme, corev1.EventSource{Component: c.ComponentConfig.SchedulerName})

	// Set up leader election if enabled.
	// 设置leader election
	var leaderElectionConfig *leaderelection.LeaderElectionConfig
	if c.ComponentConfig.LeaderElection.LeaderElect {
		leaderElectionConfig, err = makeLeaderElectionConfig(c.ComponentConfig.LeaderElection, leaderElectionClient, coreRecorder)
		if err != nil {
			return nil, err
		}
	}
	
	// 设置信息
	c.Client = client
	c.InformerFactory = informers.NewSharedInformerFactory(client, 0)
	// 这里的Informer会选择 status.phase!=v1.PodSucceeded,status.phase!=v1.PodFailed
	// 就是还没完成的Pod
	c.PodInformer = scheduler.NewPodInformer(client, 0)
	c.EventClient = eventClient.EventsV1beta1()
	c.CoreEventClient = eventClient.CoreV1()
	c.CoreBroadcaster = coreBroadcaster
	c.LeaderElection = leaderElectionConfig

	return c, nil
}

```

回到 runCommand 生成config之后会进行补全操作

```
// Get the completed config
// 具体Complete()
/**
cc := completedConfig{c}

if c.InsecureServing != nil {
	c.InsecureServing.Name = "healthz"
}
if c.InsecureMetricsServing != nil {
	c.InsecureMetricsServing.Name = "metrics"
}

apiserver.AuthorizeClientBearerToken(c.LoopbackClientConfig, &c.Authentication, &c.Authorization)

return CompletedConfig{&cc}
*/

cc := c.Complete()

```

通过FeatureGates设置的一些predicate和prioirity

```
// Apply algorithms based on feature gates.
// TODO: make configurable?
algorithmprovider.ApplyFeatureGates()

```

这里初始化了一个提供 url /configz 访问的一个结构，将当前的Config设置上去，后续会安装Http Handler 在访问 /configz时输出当前配置

```
// Configz registration.
if cz, err := configz.New("componentconfig"); err == nil {
	cz.Set(cc.ComponentConfig)
} else {
	return fmt.Errorf("unable to register configz: %s", err)
}

```

最后是设置context 然后Run()

```
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

return Run(ctx, cc, registryOptions...)

```

这里设置了Framework相关的操作

```
outOfTreeRegistry := make(framework.Registry)
for _, option := range outOfTreeRegistryOptions {
	if err := option(outOfTreeRegistry); err != nil {
		return err
	}
}

// Prepare event clients.
// 设置Event client 首先用Discovery的方法，如果不行则使用古老的办法
if _, err := cc.Client.Discovery().ServerResourcesForGroupVersion(eventsv1beta1.SchemeGroupVersion.String()); err == nil {
	cc.Broadcaster = events.NewBroadcaster(&events.EventSinkImpl{Interface: cc.EventClient.Events("")})
	cc.Recorder = cc.Broadcaster.NewRecorder(scheme.Scheme, cc.ComponentConfig.SchedulerName)
} else {
	recorder := cc.CoreBroadcaster.NewRecorder(scheme.Scheme, v1.EventSource{Component: cc.ComponentConfig.SchedulerName})
	cc.Recorder = record.NewEventRecorderAdapter(recorder)
}

//正式创建调度器
scheduler.New()
```

展开看


```
// New returns a Scheduler
func New(client clientset.Interface,
	informerFactory informers.SharedInformerFactory,
	podInformer coreinformers.PodInformer,
	recorder events.EventRecorder,
	stopCh <-chan struct{},
	opts ...Option) (*Scheduler, error) {

	// 先初始化管道
	stopEverything := stopCh
	if stopEverything == nil {
		stopEverything = wait.NeverStop
	}

	// 在default的options上增加了一些设置操作，具体看scheduler.New()
	options := defaultSchedulerOptions
	for _, opt := range opts {
		opt(&options)
	}

	// 初始化一个Cache
	schedulerCache := internalcache.New(30*time.Second, stopEverything)

	// volumeBinder
	volumeBinder := volumebinder.NewVolumeBinder(
		client,
		informerFactory.Core().V1().Nodes(),
		informerFactory.Storage().V1().CSINodes(),
		informerFactory.Core().V1().PersistentVolumeClaims(),
		informerFactory.Core().V1().PersistentVolumes(),
		informerFactory.Storage().V1().StorageClasses(),
		time.Duration(options.bindTimeoutSeconds)*time.Second,
	)
	
	// 这里是Scheduler的Framework相关的操作了，frameworkplugins.NewDefaultRegistry()， 会注册所有相关的Plugin
	// 全部遵循新设计的Plugin的接口
	registry := options.frameworkDefaultRegistry
	if registry == nil {
		registry = frameworkplugins.NewDefaultRegistry(&frameworkplugins.RegistryArgs{
			VolumeBinder: volumeBinder,
		})
	}
	// 将用户自定义的Plugin加载进来
	registry.Merge(options.frameworkOutOfTreeRegistry)

	snapshot := nodeinfosnapshot.NewEmptySnapshot()

	// 初始化Configurator这个类可以用来创建Scheduler
	configurator := &Configurator{
		client:                         client,
		informerFactory:                informerFactory,
		podInformer:                    podInformer,
		volumeBinder:                   volumeBinder,
		schedulerCache:                 schedulerCache,
		StopEverything:                 stopEverything,
		hardPodAffinitySymmetricWeight: options.hardPodAffinitySymmetricWeight,
		disablePreemption:              options.disablePreemption,
		percentageOfNodesToScore:       options.percentageOfNodesToScore,
		bindTimeoutSeconds:             options.bindTimeoutSeconds,
		podInitialBackoffSeconds:       options.podInitialBackoffSeconds,
		podMaxBackoffSeconds:           options.podMaxBackoffSeconds,
		enableNonPreempting:            utilfeature.DefaultFeatureGate.Enabled(kubefeatures.NonPreemptingPriority),
		registry:                       registry,
		plugins:                        options.frameworkPlugins,
		pluginConfig:                   options.frameworkPluginConfig,
		pluginConfigProducerRegistry:   options.frameworkConfigProducerRegistry,
		nodeInfoSnapshot:               snapshot,
		algorithmFactoryArgs: AlgorithmFactoryArgs{
			SharedLister:                   snapshot,
			InformerFactory:                informerFactory,
			VolumeBinder:                   volumeBinder,
			HardPodAffinitySymmetricWeight: options.hardPodAffinitySymmetricWeight,
		},
		configProducerArgs: &frameworkplugins.ConfigProducerArgs{},
	}

	var sched *Scheduler
	source := options.schedulerAlgorithmSource
	switch {
	case source.Provider != nil:
		// Create the config from a named algorithm provider.
		// 这里正是的去创建Scheduler source.Provider 应该是默认的DefaultProvider
		// 之前需要先去看一些init() 在 k8s.io/kubernetes/pkg/scheduler/algorithmprovider/ 文件夹下
		sc, err := configurator.CreateFromProvider(*source.Provider)
		if err != nil {
			return nil, fmt.Errorf("couldn't create scheduler using provider %q: %v", *source.Provider, err)
		}
		sched = sc
	case source.Policy != nil:
		// Create the config from a user specified policy source.
		policy := &schedulerapi.Policy{}
		switch {
		case source.Policy.File != nil:
			if err := initPolicyFromFile(source.Policy.File.Path, policy); err != nil {
				return nil, err
			}
		case source.Policy.ConfigMap != nil:
			if err := initPolicyFromConfigMap(client, source.Policy.ConfigMap, policy); err != nil {
				return nil, err
			}
		}
		sc, err := configurator.CreateFromConfig(*policy)
		if err != nil {
			return nil, fmt.Errorf("couldn't create scheduler from policy: %v", err)
		}
		sched = sc
	default:
		return nil, fmt.Errorf("unsupported algorithm source: %v", source)
	}

	// 注册Prometheus相关
	metrics.Register()
	// Additional tweaks to the config produced by the configurator.
	sched.Recorder = recorder
	sched.DisablePreemption = options.disablePreemption
	sched.StopEverything = stopEverything
	sched.podConditionUpdater = &podConditionUpdaterImpl{client}
	sched.podPreemptor = &podPreemptorImpl{client}
	sched.scheduledPodsHasSynced = podInformer.Informer().HasSynced
	
	// 这里添加所有handler下边具体展开
	AddAllEventHandlers(sched, options.schedulerName, informerFactory, podInformer)
	return sched, nil
}

```

首先看 configurator.CreateFromProvider

```
// CreateFromProvider creates a scheduler from the name of a registered algorithm provider.
func (c *Configurator) CreateFromProvider(providerName string) (*Scheduler, error) {
	klog.V(2).Infof("Creating scheduler from algorithm provider '%v'", providerName)
	provider, err := GetAlgorithmProvider(providerName)
	if err != nil {
		return nil, err
	}
	return c.CreateFromKeys(provider.FitPredicateKeys, provider.PriorityFunctionKeys, []algorithm.SchedulerExtender{})
}

```

展开看 

```
// 首先是获得Predicate相关策略
predicateFuncs, pluginsForPredicates, pluginConfigForPredicates, err := c.getPredicateConfigs(predicateKeys)

```

c.getPredicateConfigs(predicateKeys)

```
// getPredicateConfigs returns predicates configuration: ones that will run as fitPredicates and ones that will run
// as framework plugins. Specifically, a predicate will run as a framework plugin if a plugin config producer was
// registered for that predicate.
// Note that the framework executes plugins according to their order in the Plugins list, and so predicates run as plugins
// are added to the Plugins list according to the order specified in predicates.Ordering().
func (c *Configurator) getPredicateConfigs(predicateKeys sets.String) (map[string]predicates.FitPredicate, *schedulerapi.Plugins, []schedulerapi.PluginConfig, error) {
	// 首先是获得所有注册过的FitPredicates, 这个看之前 algorithmprovider包下边的Init()
	allFitPredicates, err := getFitPredicateFunctions(predicateKeys, c.algorithmFactoryArgs)
	if err != nil {
		return nil, nil, nil, err
	}
	
	// 如果没有plugin注册就直接返回了
	if c.pluginConfigProducerRegistry == nil {
		return allFitPredicates, nil, nil, nil
	}

	// 下边开始framework相关的操作
	asPlugins := sets.NewString()
	asFitPredicates := make(map[string]predicates.FitPredicate)
	frameworkConfigProducers := c.pluginConfigProducerRegistry.PredicateToConfigProducer

	// First, identify the predicates that will run as actual fit predicates, and ones
	// that will run as framework plugins.
	// 这里看这些是直接设置的FitPredicates名字还是用PluginProducer来实例化Plugin
	for predicateKey := range allFitPredicates {
		if _, exist := frameworkConfigProducers[predicateKey]; exist {
			asPlugins.Insert(predicateKey)
		} else {
			asFitPredicates[predicateKey] = allFitPredicates[predicateKey]
		}
	}

	// Second, create the framework plugin configurations, and place them in the order
	// that the corresponding predicates were supposed to run.
	// 开始添加Plugin
	var plugins schedulerapi.Plugins
	var pluginConfig []schedulerapi.PluginConfig

	// 这里添加的都是内置的一些Predictes
	for _, predicateKey := range predicates.Ordering() {
		// 如果是Producer的话直接创建Plugin并且append到 plugins里
		if asPlugins.Has(predicateKey) {
			producer := frameworkConfigProducers[predicateKey]
			p, pc := producer(*c.configProducerArgs)
			plugins.Append(&p)
			pluginConfig = append(pluginConfig, pc...)
			asPlugins.Delete(predicateKey)
		}
	}

	// 这里添加的都是非内置的Predicates
	// Third, add the rest in no specific order.
	for predicateKey := range asPlugins {
		producer := frameworkConfigProducers[predicateKey]
		p, pc := producer(*c.configProducerArgs)
		plugins.Append(&p)
		pluginConfig = append(pluginConfig, pc...)
	}

	//最后返回数据
	return asFitPredicates, &plugins, pluginConfig, nil
}

```

诉后就是Prioity的操作 c.getPriorityConfigs(priorityKeys)


```
// getPriorityConfigs returns priorities configuration: ones that will run as priorities and ones that will run
// as framework plugins. Specifically, a priority will run as a framework plugin if a plugin config producer was
// registered for that priority.
func (c *Configurator) getPriorityConfigs(priorityKeys sets.String) ([]priorities.PriorityConfig, *schedulerapi.Plugins, []schedulerapi.PluginConfig, error) {
	// 这里会返回所有内置的PrioityConfigs，具体的还是需要去看algorithmprovider包下的init()都设置了哪些
	// 返回的Config里包含了Name,Map,Reduce,Weight
	allPriorityConfigs, err := getPriorityFunctionConfigs(priorityKeys, c.algorithmFactoryArgs)
	if err != nil {
		return nil, nil, nil, err
	}

	// 如果没有Plugin相关直接返回
	if c.pluginConfigProducerRegistry == nil {
		return allPriorityConfigs, nil, nil, nil
	}

	var priorityConfigs []priorities.PriorityConfig
	var plugins schedulerapi.Plugins
	var pluginConfig []schedulerapi.PluginConfig
	frameworkConfigProducers := c.pluginConfigProducerRegistry.PriorityToConfigProducer
	for _, p := range allPriorityConfigs {
		// 如果是plugin则添加到plugins并添加到pluginConfig
		if producer, exist := frameworkConfigProducers[p.Name]; exist {
			args := *c.configProducerArgs
			args.Weight = int32(p.Weight)
			pl, pc := producer(args)
			plugins.Append(&pl)
			pluginConfig = append(pluginConfig, pc...)
		} else {
			// 如果没找到这添加设置好的Prioity
			priorityConfigs = append(priorityConfigs, p)
		}
	}
	// 最后返回所有PriorityConfigs, plugins, pluginConfig
	return priorityConfigs, &plugins, pluginConfig, nil
}

```


随后是组织predicateMeta和 priorityMeta

```
priorityMetaProducer, err := getPriorityMetadataProducer(c.algorithmFactoryArgs)
if err != nil {
	return nil, err
}

predicateMetaProducer, err := getPredicateMetadataProducer(c.algorithmFactoryArgs)
if err != nil {
	return nil, err
}

```

将所有的Plugin和PluginConfig合并


```
// Combine all framework configurations. If this results in any duplication, framework
// instantiation should fail.
var plugins schedulerapi.Plugins
plugins.Append(pluginsForPredicates)
plugins.Append(pluginsForPriorities)
plugins.Append(c.plugins)
var pluginConfig []schedulerapi.PluginConfig
pluginConfig = append(pluginConfig, pluginConfigForPredicates...)
pluginConfig = append(pluginConfig, pluginConfigForPriorities...)
pluginConfig = append(pluginConfig, c.pluginConfig...)

framework, err := framework.NewFramework(
	c.registry,
	&plugins,
	pluginConfig,
	framework.WithClientSet(c.client),
	framework.WithInformerFactory(c.informerFactory),
	framework.WithSnapshotSharedLister(c.nodeInfoSnapshot),
)


```

展开查看 NewFramework 

```
// NewFramework initializes plugins given the configuration and the registry.
func NewFramework(r Registry, plugins *config.Plugins, args []config.PluginConfig, opts ...Option) (Framework, error) {
	//  defaultFrameworkOptions里包含了一个metricRecorder
	options := defaultFrameworkOptions
	for _, opt := range opts {
		opt(&options)
	}

	// 初始化Framework
	f := &framework{
		registry:              r,
		snapshotSharedLister:  options.snapshotSharedLister,
		pluginNameToWeightMap: make(map[string]int),
		waitingPods:           newWaitingPodsMap(),
		clientSet:             options.clientSet,
		informerFactory:       options.informerFactory,
		metricsRecorder:       options.metricsRecorder,
	}
	if plugins == nil {
		return f, nil
	}
	
	// 这里会把Enabled生成一个列表
	// get needed plugins from config
	pg := f.pluginsNeeded(plugins)
	if len(pg) == 0 {
		return f, nil
	}

	pluginConfig := make(map[string]*runtime.Unknown, 0)
	for i := range args {
		pluginConfig[args[i].Name] = &args[i].Args
	}

	// 设置pluginsMap
	pluginsMap := make(map[string]Plugin)
	for name, factory := range r {
		// initialize only needed plugins.
		if _, ok := pg[name]; !ok {
			continue
		}

		p, err := factory(pluginConfig[name], f)
		if err != nil {
			return nil, fmt.Errorf("error initializing plugin %q: %v", name, err)
		}
		pluginsMap[name] = p

		// a weight of zero is not permitted, plugins can be disabled explicitly
		// when configured.
		f.pluginNameToWeightMap[name] = int(pg[name].Weight)
		if f.pluginNameToWeightMap[name] == 0 {
			f.pluginNameToWeightMap[name] = 1
		}
	}

	// 这里会把每个ExtendsPoint的Plugin加进去
	for _, e := range f.getExtensionPoints(plugins) {
		if err := updatePluginList(e.slicePtr, e.plugins, pluginsMap); err != nil {
			return nil, err
		}
	}

	// Verifying the score weights again since Plugin.Name() could return a different
	// value from the one used in the configuration.
	// 验证score是否正确
	for _, scorePlugin := range f.scorePlugins {
		if f.pluginNameToWeightMap[scorePlugin.Name()] == 0 {
			return nil, fmt.Errorf("score plugin %q is not configured with weight", scorePlugin.Name())
		}
	}

	// f.queueSortPlugins 只能有一个
	if len(f.queueSortPlugins) > 1 {
		return nil, fmt.Errorf("only one queue sort plugin can be enabled")
	}

	return f, nil
}

```

回到 CreateFromKeys()

```
	// 初始化了SchedulingQueue , 这里默认用PrioirtyQueue 这里是调度核心队列，后续需要展开详细介绍	podQueue := internalqueue.NewSchedulingQueue(
	c.StopEverything,
	framework,
	internalqueue.WithPodInitialBackoffDuration(time.Duration(c.podInitialBackoffSeconds)*time.Second),
	internalqueue.WithPodMaxBackoffDuration(time.Duration(c.podMaxBackoffSeconds)*time.Second),
)


// Setup cache debugger.
// 这个是debug的Handler
debugger := cachedebugger.New(
	c.informerFactory.Core().V1().Nodes().Lister(),
	c.podInformer.Lister(),
	c.schedulerCache,
	podQueue,
)
debugger.ListenForSignal(c.StopEverything)

// 初始化调度算法类
algo := core.NewGenericScheduler(
	c.schedulerCache,
	podQueue,
	predicateFuncs,
	predicateMetaProducer,
	priorityConfigs,
	priorityMetaProducer,
	c.nodeInfoSnapshot,
	framework,
	extenders,
	c.volumeBinder,
	c.informerFactory.Core().V1().PersistentVolumeClaims().Lister(),
	GetPodDisruptionBudgetLister(c.informerFactory),
	c.alwaysCheckAllPredicates,
	c.disablePreemption,
	c.percentageOfNodesToScore,
	c.enableNonPreempting,
)

// 这里正是生成Scheduler

return &Scheduler{
	SchedulerCache:  c.schedulerCache,
	Algorithm:       algo,
	GetBinder:       getBinderFunc(c.client, extenders), // 这里要针对不同的Pod返回不同的binder用于扩展的Binder
	Framework:       framework,
	NextPod:         internalqueue.MakeNextPodFunc(podQueue), // 获得Pod的方法，在scheduleOne调用
	Error:           MakeDefaultErrorFunc(c.client, podQueue, c.schedulerCache),
	StopEverything:  c.StopEverything,
	VolumeBinder:    c.volumeBinder,
	SchedulingQueue: podQueue,
	Plugins:         plugins,
	PluginConfig:    pluginConfig,
}, nil

```

至此Scheduler初始化完成，有两个点需要展开描述，首先是PriorityQueue

```
podQueue := internalqueue.NewSchedulingQueue(
	c.StopEverything,
	framework,
	internalqueue.WithPodInitialBackoffDuration(time.Duration(c.podInitialBackoffSeconds)*time.Second),
	internalqueue.WithPodMaxBackoffDuration(time.Duration(c.podMaxBackoffSeconds)*time.Second),
)

->

// NewSchedulingQueue initializes a priority queue as a new scheduling queue.
func NewSchedulingQueue(stop <-chan struct{}, fwk framework.Framework, opts ...Option) SchedulingQueue {
	return NewPriorityQueue(stop, fwk, opts...)
}

->
// NewPriorityQueue creates a PriorityQueue object.
func NewPriorityQueue(
	stop <-chan struct{},
	fwk framework.Framework,
	opts ...Option,
) *PriorityQueue {
	
	// 这里初始化了一些默认值和一个时钟
	options := defaultPriorityQueueOptions
	for _, opt := range opts {
		opt(&options)
	}
	
	// 对于 activeQ 的一个排序函数，通过的是framework的是QueueSortFunc
	comp := activeQComp
	if fwk != nil {
		if queueSortFunc := fwk.QueueSortFunc(); queueSortFunc != nil {
			comp = func(podInfo1, podInfo2 interface{}) bool {
				pInfo1 := podInfo1.(*framework.PodInfo)
				pInfo2 := podInfo2.(*framework.PodInfo)

				return queueSortFunc(pInfo1, pInfo2)
			}
		}
	}

	// 这里初始化PriorityQueue
	pq := &PriorityQueue{
		clock:            options.clock, // opts里默认初始化的一个util.RealColck{}
		stop:             stop,
		// 初始化了PodBackOff结构，用来存储没有获得调度权的Pod,PriorityQueue会从这里挑选一些Pod进入到ActiveQ		podBackoff:       NewPodBackoffMap(options.podInitialBackoffDuration, options.podMaxBackoffDuration),
		// ActiveQ 这里用的是一个堆排序算法，对比方法就是刚才的的comp
		activeQ:          heap.NewWithRecorder(podInfoKeyFunc, comp, metrics.NewActivePodsRecorder()),
		// 这个是 unschedulableQ 那些暂时无法调度的Pod就放到这里
		unschedulableQ:   newUnschedulablePodsMap(metrics.NewUnschedulablePodsRecorder()),
		// 这个结构保存了已经nominated的Pod以及Pod所对应的Node
		nominatedPods:    newNominatedPodMap(),
		// 这个计数器在请求Pod在active 队列pop时自增
		moveRequestCycle: -1,
	}
	// sync.Cond类，来实现同步
	pq.cond.L = &pq.lock
	// backOff队列，也是用堆排序
	pq.podBackoffQ = heap.NewWithRecorder(podInfoKeyFunc, pq.podsCompareBackoffCompleted, metrics.NewBackoffPodsRecorder())

	pq.run()

	return pq
}

->
// 开启两个goroutine将backoff和unschedule两个队列里符合条件的Pod刷新到active队列中去调度
// run starts the goroutine to pump from podBackoffQ to activeQ
func (p *PriorityQueue) run() {
	
	go wait.Until(p.flushBackoffQCompleted, 1.0*time.Second, p.stop)
	go wait.Until(p.flushUnschedulableQLeftover, 30*time.Second, p.stop)
}

```

至此整个的PriorityQueue初始化完成，可以看到有三个主要队列
activeQ ： 活动队列，nextPod会从这个里pop出一个Item来进行调度
backoffQ ：这里的Pod进来后会被标记一个duration，等待这个duration结束后会被重新加入activeQ中
unscheduleQ ：等待后续查看作用

回到scheduler.go -> New() 看看最后的Handler是怎么处理的

```
AddAllEventHandlers(sched, options.schedulerName, informerFactory, podInformer)

->

// 首先是已调度完成的Pod
// scheduled pod cache
podInformer.Informer().AddEventHandler(
	cache.FilteringResourceEventHandler{
		// 过滤函数，用来判断pod有nodeName return len(pod.Spec.NodeName) != 0
		FilterFunc: func(obj interface{}) bool {
			switch t := obj.(type) {
			case *v1.Pod:
				return assignedPod(t)
			case cache.DeletedFinalStateUnknown:
				if pod, ok := t.Obj.(*v1.Pod); ok {
					return assignedPod(pod)
				}
				utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
				return false
			default:
				utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
				return false
			}
		},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    sched.addPodToCache,
			UpdateFunc: sched.updatePodInCache,
			DeleteFunc: sched.deletePodFromCache,
		},
	},
)

-> 
// 首先是添加动作 sched.addPodToCache

func (sched *Scheduler) addPodToCache(obj interface{}) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		klog.Errorf("cannot convert to *v1.Pod: %v", obj)
		return
	}

	// 先添加到schedulercache中
	if err := sched.SchedulerCache.AddPod(pod); err != nil {
		klog.Errorf("scheduler cache AddPod failed: %v", err)
	}
	// 出发队列中的方法
	sched.SchedulingQueue.AssignedPodAdded(pod)
}

->

// 当有assignedPod添加进来时，会查找在unscheduleQ中有Affinity的Pod进入active或者backoff队列中
// AssignedPodAdded is called when a bound pod is added. Creation of this pod
// may make pending pods with matching affinity terms schedulable.
func (p *PriorityQueue) AssignedPodAdded(pod *v1.Pod) {
	p.lock.Lock()
	p.movePodsToActiveOrBackoffQueue(p.getUnschedulablePodsWithMatchingAffinityTerm(pod), AssignedPodAdd)
	p.lock.Unlock()
}

->
// 更新动作 sched.updatePodInCache,

func (sched *Scheduler) updatePodInCache(oldObj, newObj interface{}) {
	oldPod, ok := oldObj.(*v1.Pod)
	if !ok {
		klog.Errorf("cannot convert oldObj to *v1.Pod: %v", oldObj)
		return
	}
	newPod, ok := newObj.(*v1.Pod)
	if !ok {
		klog.Errorf("cannot convert newObj to *v1.Pod: %v", newObj)
		return
	}

	// NOTE: Updates must be written to scheduler cache before invalidating
	// equivalence cache, because we could snapshot equivalence cache after the
	// invalidation and then snapshot the cache itself. If the cache is
	// snapshotted before updates are written, we would update equivalence
	// cache with stale information which is based on snapshot of old cache.
	if err := sched.SchedulerCache.UpdatePod(oldPod, newPod); err != nil {
		klog.Errorf("scheduler cache UpdatePod failed: %v", err)
	}
	// 这里与add一样都是看Affinity然后去分配Pod去active或者backoff
	sched.SchedulingQueue.AssignedPodUpdated(newPod)
}

// 删除动作 

->

func (sched *Scheduler) deletePodFromCache(obj interface{}) {
	var pod *v1.Pod
	switch t := obj.(type) {
	case *v1.Pod:
		pod = t
	case cache.DeletedFinalStateUnknown:
		var ok bool
		pod, ok = t.Obj.(*v1.Pod)
		if !ok {
			klog.Errorf("cannot convert to *v1.Pod: %v", t.Obj)
			return
		}
	default:
		klog.Errorf("cannot convert to *v1.Pod: %v", t)
		return
	}
	// NOTE: Updates must be written to scheduler cache before invalidating
	// equivalence cache, because we could snapshot equivalence cache after the
	// invalidation and then snapshot the cache itself. If the cache is
	// snapshotted before updates are written, we would update equivalence
	// cache with stale information which is based on snapshot of old cache.
	if err := sched.SchedulerCache.RemovePod(pod); err != nil {
		klog.Errorf("scheduler cache RemovePod failed: %v", err)
	}
	// 会重新把unscheduleQ里的item再次进行分发到activeQ或者backoffQ
	sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.AssignedPodDelete)
}


```

调度完成的Pod事件完成，主要是针对以有nodeName的Pod进行操作，更新cache，并且根据Affinity信息来调度unassignedPod

下面看看unscheduledPod的处理

```
// unscheduled pod queue
podInformer.Informer().AddEventHandler(
	cache.FilteringResourceEventHandler{
		FilterFunc: func(obj interface{}) bool {
			switch t := obj.(type) {
			case *v1.Pod:
				return !assignedPod(t) && responsibleForPod(t, schedulerName)
			case cache.DeletedFinalStateUnknown:
				if pod, ok := t.Obj.(*v1.Pod); ok {
					return !assignedPod(pod) && responsibleForPod(pod, schedulerName)
				}
				utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
				return false
			default:
				utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
				return false
			}
		},
		Handler: cache.ResourceEventHandlerFuncs{
			AddFunc:    sched.addPodToSchedulingQueue,
			UpdateFunc: sched.updatePodInSchedulingQueue,
			DeleteFunc: sched.deletePodFromSchedulingQueue,
		},
	},
)

sched.addPodToSchedulingQueue

->
// 直接扔进activeQ中
func (sched *Scheduler) addPodToSchedulingQueue(obj interface{}) {
	if err := sched.SchedulingQueue.Add(obj.(*v1.Pod)); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to queue %T: %v", obj, err))
	}
}

sched.updatePodInSchedulingQueue

->
func (sched *Scheduler) updatePodInSchedulingQueue(oldObj, newObj interface{}) {
	pod := newObj.(*v1.Pod)
	//先要判断是否需要update
	//判断依据是
 //   - The pod has already been assumed, AND
//   - The pod has only its ResourceVersion, Spec.NodeName and/or Annotations
//     updated.

	if sched.skipPodUpdate(pod) {
		return
	}
	// 最后这里的Update操作会针对不同队列进行，如果是在backoff,unschedule队列中会将更新的Pod放到active队列中
	if err := sched.SchedulingQueue.Update(oldObj.(*v1.Pod), pod); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to update %T: %v", newObj, err))
	}
}

sched.deletePodFromSchedulingQueue

->


func (sched *Scheduler) deletePodFromSchedulingQueue(obj interface{}) {
	var pod *v1.Pod
	switch t := obj.(type) {
	case *v1.Pod:
		pod = obj.(*v1.Pod)
	case cache.DeletedFinalStateUnknown:
		var ok bool
		pod, ok = t.Obj.(*v1.Pod)
		if !ok {
			utilruntime.HandleError(fmt.Errorf("unable to convert object %T to *v1.Pod in %T", obj, sched))
			return
		}
	default:
		utilruntime.HandleError(fmt.Errorf("unable to handle object in %T: %T", sched, obj))
		return
	}
	// 这里会调用一系列清理操作
	if err := sched.SchedulingQueue.Delete(pod); err != nil {
		utilruntime.HandleError(fmt.Errorf("unable to dequeue %T: %v", obj, err))
	}
	if sched.VolumeBinder != nil {
		// Volume binder only wants to keep unassigned pods
		sched.VolumeBinder.DeletePodBindings(pod)
	}
	// Framework相关，因为有wait接口了，所以要停止wait
	sched.Framework.RejectWaitingPod(pod.UID)
}

// 随后查看 Node 相关

 sched.addNodeToCache
->
func (sched *Scheduler) addNodeToCache(obj interface{}) {
	node, ok := obj.(*v1.Node)
	if !ok {
		klog.Errorf("cannot convert to *v1.Node: %v", obj)
		return
	}
	// 这会添加Node，并且将新的Node放置在node链表的顶端
	if err := sched.SchedulerCache.AddNode(node); err != nil {
		klog.Errorf("scheduler cache AddNode failed: %v", err)
	}

	// 会触发一次将所有unscheduleQ里的Pod调动一次去active或者backoff
	sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.NodeAdd)
}


sched.updateNodeInCache
->
func (sched *Scheduler) updateNodeInCache(oldObj, newObj interface{}) {
	oldNode, ok := oldObj.(*v1.Node)
	if !ok {
		klog.Errorf("cannot convert oldObj to *v1.Node: %v", oldObj)
		return
	}
	newNode, ok := newObj.(*v1.Node)
	if !ok {
		klog.Errorf("cannot convert newObj to *v1.Node: %v", newObj)
		return
	}
	// 在cache中更新node,同样新的Node也会去链表顶端
	if err := sched.SchedulerCache.UpdateNode(oldNode, newNode); err != nil {
		klog.Errorf("scheduler cache UpdateNode failed: %v", err)
	}

	// Only activate unschedulable pods if the node became more schedulable.
	// We skip the node property comparison when there is no unschedulable pods in the queue
	// to save processing cycles. We still trigger a move to active queue to cover the case
	// that a pod being processed by the scheduler is determined unschedulable. We want this
	// pod to be reevaluated when a change in the cluster happens.
	if sched.SchedulingQueue.NumUnschedulablePods() == 0 {
		sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(queue.Unknown)
	} else if event := nodeSchedulingPropertiesChange(newNode, oldNode); event != "" {
		sched.SchedulingQueue.MoveAllToActiveOrBackoffQueue(event)
	}
}

sched.deleteNodeFromCache
->

func (sched *Scheduler) deleteNodeFromCache(obj interface{}) {
	var node *v1.Node
	switch t := obj.(type) {
	case *v1.Node:
		node = t
	case cache.DeletedFinalStateUnknown:
		var ok bool
		node, ok = t.Obj.(*v1.Node)
		if !ok {
			klog.Errorf("cannot convert to *v1.Node: %v", t.Obj)
			return
		}
	default:
		klog.Errorf("cannot convert to *v1.Node: %v", t)
		return
	}
	// NOTE: Updates must be written to scheduler cache before invalidating
	// equivalence cache, because we could snapshot equivalence cache after the
	// invalidation and then snapshot the cache itself. If the cache is
	// snapshotted before updates are written, we would update equivalence
	// cache with stale information which is based on snapshot of old cache.
	
	// 这里删除Node的操作并不是直接删掉了，考虑到可能有Pod的情况
	if err := sched.SchedulerCache.RemoveNode(node); err != nil {
		klog.Errorf("scheduler cache RemoveNode failed: %v", err)
	}
}

```

后边这些Handler都是调动队列中的Pod去active或者backoff了

```

if utilfeature.DefaultFeatureGate.Enabled(features.CSINodeInfo) {
	informerFactory.Storage().V1().CSINodes().Informer().AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc:    sched.onCSINodeAdd,
			UpdateFunc: sched.onCSINodeUpdate,
		},
	)
}

// On add and delete of PVs, it will affect equivalence cache items
// related to persistent volume
informerFactory.Core().V1().PersistentVolumes().Informer().AddEventHandler(
	cache.ResourceEventHandlerFuncs{
		// MaxPDVolumeCountPredicate: since it relies on the counts of PV.
		AddFunc:    sched.onPvAdd,
		UpdateFunc: sched.onPvUpdate,
	},
)

// This is for MaxPDVolumeCountPredicate: add/delete PVC will affect counts of PV when it is bound.
informerFactory.Core().V1().PersistentVolumeClaims().Informer().AddEventHandler(
	cache.ResourceEventHandlerFuncs{
		AddFunc:    sched.onPvcAdd,
		UpdateFunc: sched.onPvcUpdate,
	},
)

// This is for ServiceAffinity: affected by the selector of the service is updated.
// Also, if new service is added, equivalence cache will also become invalid since
// existing pods may be "captured" by this service and change this predicate result.
informerFactory.Core().V1().Services().Informer().AddEventHandler(
	cache.ResourceEventHandlerFuncs{
		AddFunc:    sched.onServiceAdd,
		UpdateFunc: sched.onServiceUpdate,
		DeleteFunc: sched.onServiceDelete,
	},
)

informerFactory.Storage().V1().StorageClasses().Informer().AddEventHandler(
	cache.ResourceEventHandlerFuncs{
		AddFunc: sched.onStorageClassAdd,
	},
)

```

至此scheduler对象正式初始化完成

查看后续动作

```

// Prepare the event broadcaster.
// 事件相关
if cc.Broadcaster != nil && cc.EventClient != nil {
	cc.Broadcaster.StartRecordingToSink(ctx.Done())
}
if cc.CoreBroadcaster != nil && cc.CoreEventClient != nil {
	cc.CoreBroadcaster.StartRecordingToSink(&corev1.EventSinkImpl{Interface: cc.CoreEventClient.Events("")})
}
// Setup healthz checks.
// health check相关，这里是判断leaderelector的超时问题
var checks []healthz.HealthChecker
if cc.ComponentConfig.LeaderElection.LeaderElect {
	checks = append(checks, cc.LeaderElection.WatchDog)
}

// Start up the healthz server.
// 启动相关http的服务
if cc.InsecureServing != nil {
	separateMetrics := cc.InsecureMetricsServing != nil
	handler := buildHandlerChain(newHealthzHandler(&cc.ComponentConfig, separateMetrics, checks...), nil, nil)
	if err := cc.InsecureServing.Serve(handler, 0, ctx.Done()); err != nil {
		return fmt.Errorf("failed to start healthz server: %v", err)
	}
}
if cc.InsecureMetricsServing != nil {
	handler := buildHandlerChain(newMetricsHandler(&cc.ComponentConfig), nil, nil)
	if err := cc.InsecureMetricsServing.Serve(handler, 0, ctx.Done()); err != nil {
		return fmt.Errorf("failed to start metrics server: %v", err)
	}
}
if cc.SecureServing != nil {
	handler := buildHandlerChain(newHealthzHandler(&cc.ComponentConfig, false, checks...), cc.Authentication.Authenticator, cc.Authorization.Authorizer)
	// TODO: handle stoppedCh returned by c.SecureServing.Serve
	if _, err := cc.SecureServing.Serve(handler, 0, ctx.Done()); err != nil {
		// fail early for secure handlers, removing the old error loop from above
		return fmt.Errorf("failed to start secure server: %v", err)
	}
}

// Start all informers.
// 开启所有informers
go cc.PodInformer.Informer().Run(ctx.Done())
cc.InformerFactory.Start(ctx.Done())

// Wait for all caches to sync before scheduling.
// 等待加载完成
cc.InformerFactory.WaitForCacheSync(ctx.Done())

// If leader election is enabled, runCommand via LeaderElector until done and exit.
// 如果开启了leaderelection 开启选举流程
if cc.LeaderElection != nil {
	cc.LeaderElection.Callbacks = leaderelection.LeaderCallbacks{
		OnStartedLeading: sched.Run, // 实际运行的是scheduler.Run()
		OnStoppedLeading: func() {
			klog.Fatalf("leaderelection lost")
		},
	}
	leaderElector, err := leaderelection.NewLeaderElector(*cc.LeaderElection)
	if err != nil {
		return fmt.Errorf("couldn't create leader elector: %v", err)
	}

	leaderElector.Run(ctx)

	return fmt.Errorf("lost lease")
}

// Leader election is disabled, so runCommand inline until done.
sched.Run(ctx)
return fmt.Errorf("finished without leader elect")

```

实际的运行

```
// Run begins watching and scheduling. It waits for cache to be synced, then starts scheduling and blocked until the context is done.
func (sched *Scheduler) Run(ctx context.Context) {
	// 等待Pod加载
	if !cache.WaitForCacheSync(ctx.Done(), sched.scheduledPodsHasSynced) {
		return
	}
	// 开始运行sched.scheduleOne
	wait.UntilWithContext(ctx, sched.scheduleOne, 0)
}


```

开始正式进入调度阶段 ```func (sched *Scheduler) scheduleOne(ctx context.Context) ```

```
// 从优先级队列中弹出一个Pod
podInfo := sched.NextPod()
// pod could be nil when schedulerQueue is closed
if podInfo == nil || podInfo.Pod == nil {
	return
}
pod := podInfo.Pod
if pod.DeletionTimestamp != nil {
	sched.Recorder.Eventf(pod, nil, v1.EventTypeWarning, "FailedScheduling", "Scheduling", "skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
	klog.V(3).Infof("Skip schedule deleting pod: %v/%v", pod.Namespace, pod.Name)
	return
}

klog.V(3).Infof("Attempting to schedule pod: %v/%v", pod.Namespace, pod.Name)

….
// 调度这个Pod
scheduleResult, err := sched.Algorithm.Schedule(schedulingCycleCtx, state, pod)
->
// Schedule tries to schedule the given pod to one of the nodes in the node list.
// If it succeeds, it will return the name of the node.
// If it fails, it will return a FitError error with reasons.
func (g *genericScheduler) Schedule(ctx context.Context, state *framework.CycleState, pod *v1.Pod) (result ScheduleResult, err error) 

// 首先是基本项检查 查看pvc是否存在并且这个Pod不是已经删除的Pod
if err := podPassesBasicChecks(pod, g.pvcLister); err != nil {
	return result, err
}

// 这里会对nodes进行一次快照更新
if err := g.snapshot(); err != nil {
	return result, err
}

->
// snapshot snapshots scheduler cache and node infos for all fit and priority
// functions.
// 用cache中的信息更新快照用于调度
func (g *genericScheduler) snapshot() error {
	// Used for all fit and priority funcs.
	return g.cache.UpdateNodeInfoSnapshot(g.nodeInfoSnapshot)
}
<-


if len(g.nodeInfoSnapshot.NodeInfoList) == 0 {
	return result, ErrNoNodesAvailable
}

// Run "prefilter" plugins.
// 运行prefilter插件
preFilterStatus := g.framework.RunPreFilterPlugins(ctx, state, pod)
if !preFilterStatus.IsSuccess() {
	return result, preFilterStatus.AsError()
}

// 过滤Nodes
filteredNodes, failedPredicateMap, filteredNodesStatuses, err := g.findNodesThatFit(ctx, state, pod)
if err != nil {
	return result, err
}

->

// Filters the nodes to find the ones that fit based on the given predicate functions
// Each node is passed through the predicate functions to determine if it is a fit
func (g *genericScheduler) findNodesThatFit(ctx context.Context, state *framework.CycleState, pod *v1.Pod) ([]*v1.Node, FailedPredicateMap, framework.NodeToStatusMap, error) {
	var filtered []*v1.Node
	failedPredicateMap := FailedPredicateMap{} //  map[string][]predicates.PredicateFailureReason
	filteredNodesStatuses := framework.NodeToStatusMap{} // map[string]*Status

	if len(g.predicates) == 0 && !g.framework.HasFilterPlugins() {
		filtered = g.nodeInfoSnapshot.ListNodes()
	} else {
		allNodes := len(g.nodeInfoSnapshot.NodeInfoList)
		// 这个是percentageOfNodesToScore功能，只对当前集群中一定数量的Nodes进行调度
		numNodesToFind := g.numFeasibleNodesToFind(int32(allNodes))

		// Create filtered list with enough space to avoid growing it
		// and allow assigning.
		filtered = make([]*v1.Node, numNodesToFind)
		errCh := util.NewErrorChannel()
		var (
			predicateResultLock sync.Mutex
			filteredLen         int32
		)

		ctx, cancel := context.WithCancel(ctx)

		// We can use the same metadata producer for all nodes.
		meta := g.predicateMetaProducer(pod, g.nodeInfoSnapshot)
		state.Write(migration.PredicatesStateKey, &migration.PredicatesStateData{Reference: meta})
		
		// 定义checkNode函数
		checkNode := func(i int) {
			// We check the nodes starting from where we left off in the previous scheduling cycle,
			// this is to make sure all nodes have the same chance of being examined across pods.
			// 这里是为了能够均匀的查找nodes
			nodeInfo := g.nodeInfoSnapshot.NodeInfoList[(g.nextStartNodeIndex+i)%allNodes]
			fits, failedPredicates, status, err := g.podFitsOnNode(
				ctx,
				state,
				pod,
				meta,
				nodeInfo,
				g.alwaysCheckAllPredicates,
			)
			if err != nil {
				errCh.SendErrorWithCancel(err, cancel)
				return
			}
			if fits {
				length := atomic.AddInt32(&filteredLen, 1)
				if length > numNodesToFind {
					cancel()
					atomic.AddInt32(&filteredLen, -1)
				} else {
					filtered[length-1] = nodeInfo.Node()
				}
			} else {
				predicateResultLock.Lock()
				if !status.IsSuccess() {
					filteredNodesStatuses[nodeInfo.Node().Name] = status
				}
				if len(failedPredicates) != 0 {
					failedPredicateMap[nodeInfo.Node().Name] = failedPredicates
				}
				predicateResultLock.Unlock()
			}
		}

		->
		// podFitsOnNode checks whether a node given by NodeInfo satisfies the given predicate functions.
// For given pod, podFitsOnNode will check if any equivalent pod exists and try to reuse its cached
// predicate results as possible.
// This function is called from two different places: Schedule and Preempt.
// When it is called from Schedule, we want to test whether the pod is schedulable
// on the node with all the existing pods on the node plus higher and equal priority
// pods nominated to run on the node.
// When it is called from Preempt, we should remove the victims of preemption and
// add the nominated pods. Removal of the victims is done by SelectVictimsOnNode().
// It removes victims from meta and NodeInfo before calling this function.
func (g *genericScheduler) podFitsOnNode(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	meta predicates.Metadata,
	info *schedulernodeinfo.NodeInfo,
	alwaysCheckAllPredicates bool,
) (bool, []predicates.PredicateFailureReason, *framework.Status, error) {
	var failedPredicates []predicates.PredicateFailureReason
	var status *framework.Status

	podsAdded := false
	// We run predicates twice in some cases. If the node has greater or equal priority
	// nominated pods, we run them when those pods are added to meta and nodeInfo.
	// If all predicates succeed in this pass, we run them again when these
	// nominated pods are not added. This second pass is necessary because some
	// predicates such as inter-pod affinity may not pass without the nominated pods.
	// If there are no nominated pods for the node or if the first run of the
	// predicates fail, we don't run the second pass.
	// We consider only equal or higher priority pods in the first pass, because
	// those are the current "pod" must yield to them and not take a space opened
	// for running them. It is ok if the current "pod" take resources freed for
	// lower priority pods.
	// Requiring that the new pod is schedulable in both circumstances ensures that
	// we are making a conservative decision: predicates like resources and inter-pod
	// anti-affinity are more likely to fail when the nominated pods are treated
	// as running, while predicates like pod affinity are more likely to fail when
	// the nominated pods are treated as not running. We can't just assume the
	// nominated pods are running because they are not running right now and in fact,
	// they may end up getting scheduled to a different node.
	// 这里会调用两次，第一次会将节点nominatedPods进行调度，第二次才是这个真正的Pod
	for i := 0; i < 2; i++ {
		metaToUse := meta
		stateToUse := state
		nodeInfoToUse := info
		if i == 0 {
			var err error
			podsAdded, metaToUse, stateToUse, nodeInfoToUse, err = g.addNominatedPods(ctx, pod, meta, state, info)
			if err != nil {
				return false, []predicates.PredicateFailureReason{}, nil, err
			}
		} else if !podsAdded || len(failedPredicates) != 0 || !status.IsSuccess() {
			break
		}
		
		// 会调用所有的predicate跑一遍
		for _, predicateKey := range predicates.Ordering() {
			var (
				fit     bool
				reasons []predicates.PredicateFailureReason
				err     error
			)

			if predicate, exist := g.predicates[predicateKey]; exist {
				fit, reasons, err = predicate(pod, metaToUse, nodeInfoToUse)
				if err != nil {
					return false, []predicates.PredicateFailureReason{}, nil, err
				}

				if !fit {
					// eCache is available and valid, and predicates result is unfit, record the fail reasons
					failedPredicates = append(failedPredicates, reasons...)
					// if alwaysCheckAllPredicates is false, short circuit all predicates when one predicate fails.
					if !alwaysCheckAllPredicates {
						klog.V(5).Infoln("since alwaysCheckAllPredicates has not been set, the predicate " +
							"evaluation is short circuited and there are chances " +
							"of other predicates failing as well.")
						break
					}
				}
			}
		}
		
		// filterPlugin跑一遍
		status = g.framework.RunFilterPlugins(ctx, stateToUse, pod, nodeInfoToUse)
		if !status.IsSuccess() && !status.IsUnschedulable() {
			return false, failedPredicates, status, status.AsError()
		}
	}

	return len(failedPredicates) == 0 && status.IsSuccess(), failedPredicates, status, nil
}
<-

		// Stops searching for more nodes once the configured number of feasible nodes
		// are found.
		// 并行运行predicate
		workqueue.ParallelizeUntil(ctx, 16, allNodes, checkNode)
		processedNodes := int(filteredLen) + len(filteredNodesStatuses) + len(failedPredicateMap)
		g.nextStartNodeIndex = (g.nextStartNodeIndex + processedNodes) % allNodes

		filtered = filtered[:filteredLen]
		if err := errCh.ReceiveError(); err != nil {
			return []*v1.Node{}, FailedPredicateMap{}, framework.NodeToStatusMap{}, err
		}
	}

	// 运行extenders
	if len(filtered) > 0 && len(g.extenders) != 0 {
		for _, extender := range g.extenders {
			if !extender.IsInterested(pod) {
				continue
			}
			filteredList, failedMap, err := extender.Filter(pod, filtered, g.nodeInfoSnapshot.NodeInfoMap)
			if err != nil {
				if extender.IsIgnorable() {
					klog.Warningf("Skipping extender %v as it returned error %v and has ignorable flag set",
						extender, err)
					continue
				}

				return []*v1.Node{}, FailedPredicateMap{}, framework.NodeToStatusMap{}, err
			}

			for failedNodeName, failedMsg := range failedMap {
				if _, found := failedPredicateMap[failedNodeName]; !found {
					failedPredicateMap[failedNodeName] = []predicates.PredicateFailureReason{}
				}
				failedPredicateMap[failedNodeName] = append(failedPredicateMap[failedNodeName], predicates.NewFailureReason(failedMsg))
			}
			filtered = filteredList
			if len(filtered) == 0 {
				break
			}
		}
	}
	return filtered, failedPredicateMap, filteredNodesStatuses, nil
}

<-

<-

// Run "postfilter" plugins.
postfilterStatus := g.framework.RunPostFilterPlugins(ctx, state, pod, filteredNodes, filteredNodesStatuses)
if !postfilterStatus.IsSuccess() {
	return result, postfilterStatus.AsError()
}
// 如果没有合适Node返回结果
if len(filteredNodes) == 0 {
	return result, &FitError{
		Pod:                   pod,
		NumAllNodes:           len(g.nodeInfoSnapshot.NodeInfoList),
		FailedPredicates:      failedPredicateMap,
		FilteredNodesStatuses: filteredNodesStatuses,
	}
}

// 如果只有一个节点那就返回这个result
// When only one node after predicate, just use it.
if len(filteredNodes) == 1 {
	metrics.SchedulingAlgorithmPriorityEvaluationDuration.Observe(metrics.SinceInSeconds(startPriorityEvalTime))
	metrics.DeprecatedSchedulingAlgorithmPriorityEvaluationDuration.Observe(metrics.SinceInMicroseconds(startPriorityEvalTime))
	return ScheduleResult{
		SuggestedHost:  filteredNodes[0].Name,
		EvaluatedNodes: 1 + len(failedPredicateMap) + len(filteredNodesStatuses),
		FeasibleNodes:  1,
	}, nil
}

// 开始进行priority排序

metaPrioritiesInterface := g.priorityMetaProducer(pod, filteredNodes, g.nodeInfoSnapshot)
// 这里会用到所有priorityFunctions的MapFunc,ReduceFunc，具体不再详细展开
priorityList, err := g.prioritizeNodes(ctx, state, pod, metaPrioritiesInterface, filteredNodes)
if err != nil {
	return result, err
}

// 正式选择节点
host, err := g.selectHost(priorityList)

->

// selectHost takes a prioritized list of nodes and then picks one
// in a reservoir sampling manner from the nodes that had the highest score.
// 这个方法会首先计算MaxScore 并且在所有相同的maxScore的节点中随机抽取一个
func (g *genericScheduler) selectHost(nodeScoreList framework.NodeScoreList) (string, error) {
	if len(nodeScoreList) == 0 {
		return "", fmt.Errorf("empty priorityList")
	}
	maxScore := nodeScoreList[0].Score
	selected := nodeScoreList[0].Name
	cntOfMaxScore := 1
	for _, ns := range nodeScoreList[1:] {
		if ns.Score > maxScore {
			maxScore = ns.Score
			selected = ns.Name
			cntOfMaxScore = 1
		} else if ns.Score == maxScore {
			cntOfMaxScore++
			if rand.Intn(cntOfMaxScore) == 0 {
				// Replace the candidate with probability of 1/cntOfMaxScore
				selected = ns.Name
			}
		}
	}
	return selected, nil
}

<-

// 最后返回结果
return ScheduleResult{
	SuggestedHost:  host,
	EvaluatedNodes: len(filteredNodes) + len(failedPredicateMap) + len(filteredNodesStatuses),
	FeasibleNodes:  len(filteredNodes),
}, err

<-

// 至此对所有的节点进行了predicates, priority，如果有合适的Node会选择了一个分数最高的Node

if err != nil {
// 这一块是抢占相关的逻辑先不看，先看看后续如果成功选择了Node如果操作

// Tell the cache to assume that a pod now is running on a given node, even though it hasn't been bound yet.
// This allows us to keep scheduling without waiting on binding to occur.
// assumedPod 这个pod假设已经分配完成了，下边会用这个pod做各种bind操作
assumedPodInfo := podInfo.DeepCopy()
assumedPod := assumedPodInfo.Pod

// Assume volumes first before assuming the pod.
//
// If all volumes are completely bound, then allBound is true and binding will be skipped.
//
// Otherwise, binding of volumes is started after the pod is assumed, but before pod binding.
//
// This function modifies 'assumedPod' if volume binding is required.
// 首先是绑定volume的操作，这里涉及到了PersistentVolume和PersistentVolumeClaim的操作
// 这里注意一下 PVs,PVCs已经在VolumeBindingChecker.predicate() 里设置了，主要是调用了 volumeBinder.FindPodVolumes()来设置的
// 对于deleybind的PVC，通过storageclass的提供来做到调度时bind,具体的代码在pv_controller.go当中
// 这里会通过设置一个pvutil.AnnSelectedNode来设置一个Node，PersistentVolumeController.rescheduleProvisioning()会进行相关绑定操作
allBound, err := sched.VolumeBinder.Binder.AssumePodVolumes(assumedPod, scheduleResult.SuggestedHost)
if err != nil {
	sched.recordSchedulingFailure(assumedPodInfo, err, SchedulerError,
		fmt.Sprintf("AssumePodVolumes failed: %v", err))
	metrics.PodScheduleErrors.Inc()
	return
}


// Run "reserve" plugins.
// 操作完Volume调用了ReservePlugins
if sts := fwk.RunReservePlugins(schedulingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost); !sts.IsSuccess() {
	sched.recordSchedulingFailure(assumedPodInfo, sts.AsError(), SchedulerError, sts.Message())
	metrics.PodScheduleErrors.Inc()
	return
}

// assume modifies `assumedPod` by setting NodeName=scheduleResult.SuggestedHost
// 这里是更新cache和清理队列里nominatedPods的结构
// cache的操作为
// cache.podStates[key] = ps
// cache.assumedPods[key] = true
err = sched.assume(assumedPod, scheduleResult.SuggestedHost)

// bind the pod to its host asynchronously (we can do this b/c of the assumption step above).
// 最后这一大段是真正的bind操作和一些plugin的操作
go func() {
	bindingCycleCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	metrics.SchedulerGoroutines.WithLabelValues("binding").Inc()
	defer metrics.SchedulerGoroutines.WithLabelValues("binding").Dec()

	// Run "permit" plugins.
	permitStatus := fwk.RunPermitPlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
	if !permitStatus.IsSuccess() {
		var reason string
		if permitStatus.IsUnschedulable() {
			metrics.PodScheduleFailures.Inc()
			reason = v1.PodReasonUnschedulable
		} else {
			metrics.PodScheduleErrors.Inc()
			reason = SchedulerError
		}
		if forgetErr := sched.Cache().ForgetPod(assumedPod); forgetErr != nil {
			klog.Errorf("scheduler cache ForgetPod failed: %v", forgetErr)
		}
		// trigger un-reserve plugins to clean up state associated with the reserved Pod
		fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
		sched.recordSchedulingFailure(assumedPodInfo, permitStatus.AsError(), reason, permitStatus.Message())
		return
	}

	// Bind volumes first before Pod
	if !allBound {
		err := sched.bindVolumes(assumedPod)
		if err != nil {
			sched.recordSchedulingFailure(assumedPodInfo, err, "VolumeBindingFailed", err.Error())
			metrics.PodScheduleErrors.Inc()
			// trigger un-reserve plugins to clean up state associated with the reserved Pod
			fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
			return
		}
	}

	// Run "prebind" plugins.
	preBindStatus := fwk.RunPreBindPlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
	if !preBindStatus.IsSuccess() {
		var reason string
		metrics.PodScheduleErrors.Inc()
		reason = SchedulerError
		if forgetErr := sched.Cache().ForgetPod(assumedPod); forgetErr != nil {
			klog.Errorf("scheduler cache ForgetPod failed: %v", forgetErr)
		}
		// trigger un-reserve plugins to clean up state associated with the reserved Pod
		fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
		sched.recordSchedulingFailure(assumedPodInfo, preBindStatus.AsError(), reason, preBindStatus.Message())
		return
	}

	err := sched.bind(bindingCycleCtx, assumedPod, scheduleResult.SuggestedHost, state)
	metrics.E2eSchedulingLatency.Observe(metrics.SinceInSeconds(start))
	metrics.DeprecatedE2eSchedulingLatency.Observe(metrics.SinceInMicroseconds(start))
	if err != nil {
		metrics.PodScheduleErrors.Inc()
		// trigger un-reserve plugins to clean up state associated with the reserved Pod
		fwk.RunUnreservePlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
		sched.recordSchedulingFailure(assumedPodInfo, err, SchedulerError, fmt.Sprintf("Binding rejected: %v", err))
	} else {
		// Calculating nodeResourceString can be heavy. Avoid it if klog verbosity is below 2.
		if klog.V(2) {
			klog.Infof("pod %v/%v is bound successfully on node %q, %d nodes evaluated, %d nodes were found feasible.", assumedPod.Namespace, assumedPod.Name, scheduleResult.SuggestedHost, scheduleResult.EvaluatedNodes, scheduleResult.FeasibleNodes)
		}

		metrics.PodScheduleSuccesses.Inc()
		metrics.PodSchedulingAttempts.Observe(float64(podInfo.Attempts))
		metrics.PodSchedulingDuration.Observe(metrics.SinceInSeconds(podInfo.InitialAttemptTimestamp))

		// Run "postbind" plugins.
		fwk.RunPostBindPlugins(bindingCycleCtx, state, assumedPod, scheduleResult.SuggestedHost)
	}
}()

// 回头再看看抢占操作

if err != nil {
	sched.recordSchedulingFailure(podInfo.DeepCopy(), err, v1.PodReasonUnschedulable, err.Error())
	// Schedule() may have failed because the pod would not fit on any host, so we try to
	// preempt, with the expectation that the next time the pod is tried for scheduling it
	// will fit due to the preemption. It is also possible that a different pod will schedule
	// into the resources that were preempted, but this is harmless.
	if fitError, ok := err.(*core.FitError); ok {
		if sched.DisablePreemption {
			klog.V(3).Infof("Pod priority feature is not enabled or preemption is disabled by scheduler configuration." +
				" No preemption is performed.")
		} else {
			preemptionStartTime := time.Now()
			// 主要就是这句操作
			sched.preempt(schedulingCycleCtx, state, fwk, pod, fitError)
			metrics.PreemptionAttempts.Inc()
			metrics.SchedulingAlgorithmPreemptionEvaluationDuration.Observe(metrics.SinceInSeconds(preemptionStartTime))
			metrics.DeprecatedSchedulingAlgorithmPreemptionEvaluationDuration.Observe(metrics.SinceInMicroseconds(preemptionStartTime))
			metrics.SchedulingLatency.WithLabelValues(metrics.PreemptionEvaluation).Observe(metrics.SinceInSeconds(preemptionStartTime))
			metrics.DeprecatedSchedulingLatency.WithLabelValues(metrics.PreemptionEvaluation).Observe(metrics.SinceInSeconds(preemptionStartTime))
		}
		// Pod did not fit anywhere, so it is counted as a failure. If preemption
		// succeeds, the pod should get counted as a success the next time we try to
		// schedule it. (hopefully)
		metrics.PodScheduleFailures.Inc()
	} else {
		klog.Errorf("error selecting node for pod: %v", err)
		metrics.PodScheduleErrors.Inc()
	}
	return
}

->

// preempt tries to create room for a pod that has failed to schedule, by preempting lower priority pods if possible.
// If it succeeds, it adds the name of the node where preemption has happened to the pod spec.
// It returns the node name and an error if any.
func (sched *Scheduler) preempt(ctx context.Context, state *framework.CycleState, fwk framework.Framework, preemptor *v1.Pod, scheduleErr error) (string, error) {
	// 先找到这个Pod
	// return p.Client.CoreV1().Pods(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
	preemptor, err := sched.podPreemptor.getUpdatedPod(preemptor)
	if err != nil {
		klog.Errorf("Error getting the updated preemptor pod object: %v", err)
		return "", err
	}
	
	// 开始抢占具体查看这个调用
	node, victims, nominatedPodsToClear, err := sched.Algorithm.Preempt(ctx, state, preemptor, scheduleErr)
	if err != nil {
		klog.Errorf("Error preempting victims to make room for %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
		return "", err
	}
	var nodeName = ""
	if node != nil {
		nodeName = node.Name
		// Update the scheduling queue with the nominated pod information. Without
		// this, there would be a race condition between the next scheduling cycle
		// and the time the scheduler receives a Pod Update for the nominated pod.
		sched.SchedulingQueue.UpdateNominatedPodForNode(preemptor, nodeName)

		// Make a call to update nominated node name of the pod on the API server.
		err = sched.podPreemptor.setNominatedNodeName(preemptor, nodeName)
		if err != nil {
			klog.Errorf("Error in preemption process. Cannot set 'NominatedPod' on pod %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
			sched.SchedulingQueue.DeleteNominatedPodIfExists(preemptor)
			return "", err
		}

		for _, victim := range victims {
			if err := sched.podPreemptor.deletePod(victim); err != nil {
				klog.Errorf("Error preempting pod %v/%v: %v", victim.Namespace, victim.Name, err)
				return "", err
			}
			// If the victim is a WaitingPod, send a reject message to the PermitPlugin
			if waitingPod := fwk.GetWaitingPod(victim.UID); waitingPod != nil {
				waitingPod.Reject("preempted")
			}
			sched.Recorder.Eventf(victim, preemptor, v1.EventTypeNormal, "Preempted", "Preempting", "Preempted by %v/%v on node %v", preemptor.Namespace, preemptor.Name, nodeName)

		}
		metrics.PreemptionVictims.Observe(float64(len(victims)))
	}
	// Clearing nominated pods should happen outside of "if node != nil". Node could
	// be nil when a pod with nominated node name is eligible to preempt again,
	// but preemption logic does not find any node for it. In that case Preempt()
	// function of generic_scheduler.go returns the pod itself for removal of
	// the 'NominatedPod' field.
	for _, p := range nominatedPodsToClear {
		rErr := sched.podPreemptor.removeNominatedNodeName(p)
		if rErr != nil {
			klog.Errorf("Cannot remove 'NominatedPod' field of pod: %v", rErr)
			// We do not return as this error is not critical.
		}
	}
	return nodeName, err
}

->

// preempt finds nodes with pods that can be preempted to make room for "pod" to
// schedule. It chooses one of the nodes and preempts the pods on the node and
// returns 1) the node, 2) the list of preempted pods if such a node is found,
// 3) A list of pods whose nominated node name should be cleared, and 4) any
// possible error.
// Preempt does not update its snapshot. It uses the same snapshot used in the
// scheduling cycle. This is to avoid a scenario where preempt finds feasible
// nodes without preempting any pod. When there are many pending pods in the
// scheduling queue a nominated pod will go back to the queue and behind
// other pods with the same priority. The nominated pod prevents other pods from
// using the nominated resources and the nominated pod could take a long time
// before it is retried after many other pending pods.
func (g *genericScheduler) Preempt(ctx context.Context, state *framework.CycleState, pod *v1.Pod, scheduleErr error) (*v1.Node, []*v1.Pod, []*v1.Pod, error) {
	// Scheduler may return various types of errors. Consider preemption only if
	// the error is of type FitError.
	fitError, ok := scheduleErr.(*FitError)
	if !ok || fitError == nil {
		return nil, nil, nil, nil
	}
	// 首先是查看这个Pod有没有抢占资格，PreemptionPolicy功能在这里实现，如果是PreemptNever则不抢占其他Pod
	// 再就是查看这个Pod如果有NominatedNodeName,则这个node上Pod的优先级是否都高于这个Pod
	if !podEligibleToPreemptOthers(pod, g.nodeInfoSnapshot.NodeInfoMap, g.enableNonPreempting) {
		klog.V(5).Infof("Pod %v/%v is not eligible for more preemption.", pod.Namespace, pod.Name)
		return nil, nil, nil, nil
	}
	if len(g.nodeInfoSnapshot.NodeInfoMap) == 0 {
		return nil, nil, nil, ErrNoNodesAvailable
	}
	// 这里找出了那些之前predicate失败的节点，用于抢占操作
	potentialNodes := nodesWherePreemptionMightHelp(g.nodeInfoSnapshot.NodeInfoMap, fitError)
	if len(potentialNodes) == 0 {
		klog.V(3).Infof("Preemption will not help schedule pod %v/%v on any node.", pod.Namespace, pod.Name)
		// In this case, we should clean-up any existing nominated node name of the pod.
		return nil, nil, []*v1.Pod{pod}, nil
	}
	var (
		pdbs []*policy.PodDisruptionBudget
		err  error
	)
	if g.pdbLister != nil {
		pdbs, err = g.pdbLister.List(labels.Everything())
		if err != nil {
			return nil, nil, nil, err
		}
	}

	// 返回Victims的结果 Node->{[]Pod,NumPDBViolations int64}
	// 这个结果是计算所有节点上要抢占的Pod以及对PDB(PodDisruptionBudget)的影响程度
	// 这个方法展开看一下
	nodeToVictims, err := g.selectNodesForPreemption(ctx, state, pod, potentialNodes, pdbs)
	if err != nil {
		return nil, nil, nil, err
	}

->
func (g *genericScheduler) selectVictimsOnNode(
	ctx context.Context,
	state *framework.CycleState,
	pod *v1.Pod,
	meta predicates.Metadata,
	nodeInfo *schedulernodeinfo.NodeInfo,
	pdbs []*policy.PodDisruptionBudget,
) ([]*v1.Pod, int, bool) {
	var potentialVictims []*v1.Pod

	// 删除节点上的Pod
	removePod := func(rp *v1.Pod) error {
		if err := nodeInfo.RemovePod(rp); err != nil {
			return err
		}
		if meta != nil {
			if err := meta.RemovePod(rp, nodeInfo.Node()); err != nil {
				return err
			}
		}
		status := g.framework.RunPreFilterExtensionRemovePod(ctx, state, pod, rp, nodeInfo)
		if !status.IsSuccess() {
			return status.AsError()
		}
		return nil
	}
	// 向节点添加Pod
	addPod := func(ap *v1.Pod) error {
		nodeInfo.AddPod(ap)
		if meta != nil {
			if err := meta.AddPod(ap, nodeInfo.Node()); err != nil {
				return err
			}
		}
		status := g.framework.RunPreFilterExtensionAddPod(ctx, state, pod, ap, nodeInfo)
		if !status.IsSuccess() {
			return status.AsError()
		}
		return nil
	}
	// As the first step, remove all the lower priority pods from the node and
	// check if the given pod can be scheduled.
	// 先找到所有优先级低的可抢占Pod, 然后从Node上remove掉
	podPriority := podutil.GetPodPriority(pod)
	for _, p := range nodeInfo.Pods() {
		if podutil.GetPodPriority(p) < podPriority {
			potentialVictims = append(potentialVictims, p)
			if err := removePod(p); err != nil {
				return nil, 0, false
			}
		}
	}
	// If the new pod does not fit after removing all the lower priority pods,
	// we are almost done and this node is not suitable for preemption. The only
	// condition that we could check is if the "pod" is failing to schedule due to
	// inter-pod affinity to one or more victims, but we have decided not to
	// support this case for performance reasons. Having affinity to lower
	// priority pods is not a recommended configuration anyway.
	// 随后查看这要抢占别人的Pod是否可以fit到这个Node上
	if fits, _, _, err := g.podFitsOnNode(ctx, state, pod, meta, nodeInfo, false); !fits {
		if err != nil {
			klog.Warningf("Encountered error while selecting victims on node %v: %v", nodeInfo.Node().Name, err)
		}

		return nil, 0, false
	}
	var victims []*v1.Pod
	numViolatingVictim := 0
	// 这里的排序算法是根据哪个Prioirty大或者运行时间更久来比较
	sort.Slice(potentialVictims, func(i, j int) bool { return util.MoreImportantPod(potentialVictims[i], potentialVictims[j]) })
	// Try to reprieve as many pods as possible. We first try to reprieve the PDB
	// violating victims and then other non-violating ones. In both cases, we start
	// from the highest priority victims.
	// 这个方法会根据PDB来返回要抢占的这批Pod里哪些是违反了PDB的，那些不是
	violatingVictims, nonViolatingVictims := filterPodsWithPDBViolation(potentialVictims, pdbs)

	//这个方法就是把那些要抢占的violatingVictims，nonViolatingVictims加回去，然后看看Pod是否能Fit成功
	// 目的是尽可能的保留那些violatingVictims的Pod，如果把要抢占的Victims加进去，并且Pod还fit成功了，那么reprievePod返回true
	reprievePod := func(p *v1.Pod) (bool, error) {
		if err := addPod(p); err != nil {
			return false, err
		}
		fits, _, _, _ := g.podFitsOnNode(ctx, state, pod, meta, nodeInfo, false)
		if !fits {
			if err := removePod(p); err != nil {
				return false, err
			}
			victims = append(victims, p)
			klog.V(5).Infof("Pod %v/%v is a potential preemption victim on node %v.", p.Namespace, p.Name, nodeInfo.Node().Name)
		}
		return fits, nil
	}
	
	// 这里先用violatingVictims去调用reprievePod, 如果reprievePod没有成功则numViolatingVictim++
	for _, p := range violatingVictims {
		if fits, err := reprievePod(p); err != nil {
			klog.Warningf("Failed to reprieve pod %q: %v", p.Name, err)
			return nil, 0, false
		} else if !fits {
			numViolatingVictim++
		}
	}
	// Now we try to reprieve non-violating victims.
	// 抢救完violatingVictims开始抢救nonViolatingVictims
	for _, p := range nonViolatingVictims {
		if _, err := reprievePod(p); err != nil {
			klog.Warningf("Failed to reprieve pod %q: %v", p.Name, err)
			return nil, 0, false
		}
	}
	
	// 最后返回在这个Node上的victims和numViolatingVictim
	return victims, numViolatingVictim, true
}

<-
// checkNodes的方法定义看完接下来就是处理操作
pods, numPDBViolations, fits := g.selectVictimsOnNode(ctx, stateCopy, pod, metaCopy, nodeInfoCopy, pdbs)
if fits {
	resultLock.Lock()
	victims := extenderv1.Victims{
		Pods:             pods,
		NumPDBViolations: int64(numPDBViolations),
	}
	nodeToVictims[potentialNodes[i]] = &victims
	resultLock.Unlock()
}
// 实际调用了checkNodes返回了查询的结果
workqueue.ParallelizeUntil(context.TODO(), 16, len(potentialNodes), checkNode)
return nodeToVictims, nil
<-

	// We will only check nodeToVictims with extenders that support preemption.
	// Extenders which do not support preemption may later prevent preemptor from being scheduled on the nominated
	// node. In that case, scheduler will find a different host for the preemptor in subsequent scheduling cycles.
	// 这里是extender的一些调用
	nodeToVictims, err = g.processPreemptionWithExtenders(pod, nodeToVictims)
	if err != nil {
		return nil, nil, nil, err
	}

	// 正式选择Node
	// 1. 先查找NumPDBViolations最小的节点
	// 2. 找到的节点中查找节点中最大优先级Pod为相对较小的节点
	// 3. 查找节点中优先级总和最小的
	// 4. 查找节点中Pod最少的
	// 5. 查找节点中最大优先级中启动最早的，然后在从中找出最近的Pod所在的节点。(// Find the node that satisfies latest(earliestStartTime(all highest-priority pods on node))
)
	
	candidateNode := pickOneNodeForPreemption(nodeToVictims)
	if candidateNode == nil {
		return nil, nil, nil, nil
	}

	// Lower priority pods nominated to run on this node, may no longer fit on
	// this node. So, we should remove their nomination. Removing their
	// nomination updates these pods and moves them to the active queue. It
	// lets scheduler find another place for them.
	// 查找当前要抢占的节点中比Pod还要小优先级的nominatedPods
	nominatedPods := g.getLowerPriorityNominatedPods(pod, candidateNode.Name)
	if nodeInfo, ok := g.nodeInfoSnapshot.NodeInfoMap[candidateNode.Name]; ok {
		// 返回结果
		return nodeInfo.Node(), nodeToVictims[candidateNode].Pods, nominatedPods, nil
	}

	return nil, nil, nil, fmt.Errorf(
		"preemption failed: the target node %s has been deleted from scheduler cache",
		candidateNode.Name)
}

<- 
回到 
node, victims, nominatedPodsToClear, err := sched.Algorithm.Preempt(ctx, state, preemptor, scheduleErr)

if err != nil {
	klog.Errorf("Error preempting victims to make room for %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
	return "", err
}
var nodeName = ""
if node != nil {
	nodeName = node.Name
	// Update the scheduling queue with the nominated pod information. Without
	// this, there would be a race condition between the next scheduling cycle
	// and the time the scheduler receives a Pod Update for the nominated pod.

	// 增加了nominatedPods p.nominatedPods.add(pod, nodeName)
	sched.SchedulingQueue.UpdateNominatedPodForNode(preemptor, nodeName)

	// Make a call to update nominated node name of the pod on the API server.
	// 更新Pod.Status.NominatedNodeName=nodeName
	err = sched.podPreemptor.setNominatedNodeName(preemptor, nodeName)
	if err != nil {
		klog.Errorf("Error in preemption process. Cannot set 'NominatedPod' on pod %v/%v: %v", preemptor.Namespace, preemptor.Name, err)
		sched.SchedulingQueue.DeleteNominatedPodIfExists(preemptor)
		return "", err
	}

	// 开始正式删除victims
	for _, victim := range victims {
		if err := sched.podPreemptor.deletePod(victim); err != nil {
			klog.Errorf("Error preempting pod %v/%v: %v", victim.Namespace, victim.Name, err)
			return "", err
		}
		// If the victim is a WaitingPod, send a reject message to the PermitPlugin
		if waitingPod := fwk.GetWaitingPod(victim.UID); waitingPod != nil {
			waitingPod.Reject("preempted")
		}
		sched.Recorder.Eventf(victim, preemptor, v1.EventTypeNormal, "Preempted", "Preempting", "Preempted by %v/%v on node %v", preemptor.Namespace, preemptor.Name, nodeName)

	}
	metrics.PreemptionVictims.Observe(float64(len(victims)))
}
// Clearing nominated pods should happen outside of "if node != nil". Node could
// be nil when a pod with nominated node name is eligible to preempt again,
// but preemption logic does not find any node for it. In that case Preempt()
// function of generic_scheduler.go returns the pod itself for removal of
// the 'NominatedPod' field.
// 返回nominatedPodsToClear的Pod已经有nominatedNode了，所以删除掉，因为这个Node已经被抢占一次了
// 注释里说这个逻辑放到 "if node != nil" 之外是由于Pod已经有nominatedNode了，那返回的Node就为nil
// 并且nominatedPodsToClear返回它自己
for _, p := range nominatedPodsToClear {
	rErr := sched.podPreemptor.removeNominatedNodeName(p)
	if rErr != nil {
		klog.Errorf("Cannot remove 'NominatedPod' field of pod: %v", rErr)
		// We do not return as this error is not critical.
	}
}
return nodeName, err

至此，抢占的逻辑完成。

```

下边介绍一下错误处理逻辑，具体逻辑在```src/k8s.io/kubernetes/pkg/scheduler/factory.go```文件中

在构建Scheduler的时候设置
```
 &Scheduler{
	SchedulerCache:  c.schedulerCache,
	Algorithm:       algo,
	GetBinder:       getBinderFunc(c.client, extenders),
	Framework:       framework,
	NextPod:         internalqueue.MakeNextPodFunc(podQueue),
	Error:           MakeDefaultErrorFunc(c.client, podQueue, c.schedulerCache),
	StopEverything:  c.StopEverything,
	VolumeBinder:    c.volumeBinder,
	SchedulingQueue: podQueue,
	Plugins:         plugins,
	PluginConfig:    pluginConfig,
}

```

```
// MakeDefaultErrorFunc construct a function to handle pod scheduler error
func MakeDefaultErrorFunc(client clientset.Interface, podQueue internalqueue.SchedulingQueue, schedulerCache internalcache.Cache) func(*framework.PodInfo, error) {
	return func(podInfo *framework.PodInfo, err error) {
		pod := podInfo.Pod
		if err == core.ErrNoNodesAvailable {
			klog.V(2).Infof("Unable to schedule %v/%v: no nodes are registered to the cluster; waiting", pod.Namespace, pod.Name)
		} else {
			if _, ok := err.(*core.FitError); ok {
				klog.V(2).Infof("Unable to schedule %v/%v: no fit: %v; waiting", pod.Namespace, pod.Name, err)
			} else if errors.IsNotFound(err) {
				klog.V(2).Infof("Unable to schedule %v/%v: possibly due to node not found: %v; waiting", pod.Namespace, pod.Name, err)
				if errStatus, ok := err.(errors.APIStatus); ok && errStatus.Status().Details.Kind == "node" {
					nodeName := errStatus.Status().Details.Name
					// when node is not found, We do not remove the node right away. Trying again to get
					// the node and if the node is still not found, then remove it from the scheduler cache.
					// 如果错误是因为Node找不到，则从cache中移除
					_, err := client.CoreV1().Nodes().Get(nodeName, metav1.GetOptions{})
					if err != nil && errors.IsNotFound(err) {
						node := v1.Node{ObjectMeta: metav1.ObjectMeta{Name: nodeName}}
						if err := schedulerCache.RemoveNode(&node); err != nil {
							klog.V(4).Infof("Node %q is not found; failed to remove it from the cache.", node.Name)
						}
					}
				}
			} else {
				klog.Errorf("Error scheduling %v/%v: %v; retrying", pod.Namespace, pod.Name, err)
			}
		}

		podSchedulingCycle := podQueue.SchedulingCycle()
		// Retry asynchronously.
		// Note that this is extremely rudimentary and we need a more real error handling path.
		// 这里会尝试去获取Pod，并将其放置到sched.UnschedulableQ中
		// 如果找不到这个Pod，这直接返回
		go func() {
			defer runtime.HandleCrash()
			podID := types.NamespacedName{
				Namespace: pod.Namespace,
				Name:      pod.Name,
			}

			// An unschedulable pod will be placed in the unschedulable queue.
			// This ensures that if the pod is nominated to run on a node,
			// scheduler takes the pod into account when running predicates for the node.
			// Get the pod again; it may have changed/been scheduled already.
			getBackoff := initialGetBackoff
			for {
				pod, err := client.CoreV1().Pods(podID.Namespace).Get(podID.Name, metav1.GetOptions{})
				if err == nil {
					if len(pod.Spec.NodeName) == 0 {
						podInfo.Pod = pod
						if err := podQueue.AddUnschedulableIfNotPresent(podInfo, podSchedulingCycle); err != nil {
							klog.Error(err)
						}
					}
					break
				}
				if errors.IsNotFound(err) {
					klog.Warningf("A pod %v no longer exists", podID)
					return
				}
				klog.Errorf("Error getting pod %v for retry: %v; retrying...", podID, err)
				if getBackoff = getBackoff * 2; getBackoff > maximalGetBackoff {
					getBackoff = maximalGetBackoff
				}
				time.Sleep(getBackoff)
			}
		}()
	}
}

```
