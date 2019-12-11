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



