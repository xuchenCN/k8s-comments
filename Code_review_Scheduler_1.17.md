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

