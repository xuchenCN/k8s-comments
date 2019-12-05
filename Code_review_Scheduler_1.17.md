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

依然是通过Scheme来初始化默认的config
