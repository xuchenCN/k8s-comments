## Kublet 启动注册心跳 与Pods updates 过程

入口文件,cmd/kubelet/kubelet.go -> NewKubeletCommand()

[Run func](cmd/kubelet/app/server.go#L142) 方法定义

经过一系列的初始化到达 [Run()](cmd/kubelet/app/server.go#L404) -> [run()](cmd/kubelet/app/server.go#L467)

```

func run(s *options.KubeletServer, kubeDeps *kubelet.Dependencies, stopCh <-chan struct{}) (err error) {
	// Set global feature gates based on the value on the initial KubeletServer
	...
	// validate the initial KubeletServer (we set feature gates first, because this validation depends on feature gates)
	...

	// Obtain Kubelet Lock File
	...

	// Register current configuration with /configz endpoint
	...

	// About to get clients and such, detect standaloneMode
	standaloneMode := true
	if len(s.KubeConfig) > 0 {
		standaloneMode = false
	}

	...

	// if in standalone mode, indicate as much by setting all clients to nil
	if standaloneMode {
		...
	} else if kubeDeps.KubeClient == nil || kubeDeps.ExternalKubeClient == nil || kubeDeps.EventClient == nil || kubeDeps.HeartbeatClient == nil {
		// initialize clients if not standalone mode and any of the clients are not provided
		var kubeClient clientset.Interface
		var eventClient v1core.EventsGetter
		var heartbeatClient v1core.CoreV1Interface
		var externalKubeClient clientset.Interface

		clientConfig, err := createAPIServerClientConfig(s)
		if err != nil {
			return fmt.Errorf("invalid kubeconfig: %v", err)
		}

		...

		kubeClient, err = clientset.NewForConfig(clientConfig)
		...

		// make a separate client for events
		eventClientConfig := *clientConfig
		eventClientConfig.QPS = float32(s.EventRecordQPS)
		eventClientConfig.Burst = int(s.EventBurst)
		eventClient, err = v1core.NewForConfig(&eventClientConfig)
		if err != nil {
			glog.Warningf("Failed to create API Server client for Events: %v", err)
		}

		// make a separate client for heartbeat with throttling disabled and a timeout attached
		heartbeatClientConfig := *clientConfig
		heartbeatClientConfig.Timeout = s.KubeletConfiguration.NodeStatusUpdateFrequency.Duration
		heartbeatClientConfig.QPS = float32(-1)
		heartbeatClient, err = v1core.NewForConfig(&heartbeatClientConfig)
		if err != nil {
			glog.Warningf("Failed to create API Server client for heartbeat: %v", err)
		}

		kubeDeps.KubeClient = kubeClient
		kubeDeps.ExternalKubeClient = externalKubeClient
		if heartbeatClient != nil {
			kubeDeps.HeartbeatClient = heartbeatClient
			kubeDeps.OnHeartbeatFailure = closeAllConns
		}
		if eventClient != nil {
			kubeDeps.EventClient = eventClient
		}
	}

	// If the kubelet config controller is available, and dynamic config is enabled, start the config and status sync loops
	...

	// Setup event recorder if required.
	makeEventRecorder(kubeDeps, nodeName)

	if kubeDeps.ContainerManager == nil {
		if s.CgroupsPerQOS && s.CgroupRoot == "" {
			glog.Infof("--cgroups-per-qos enabled, but --cgroup-root was not specified.  defaulting to /")
			s.CgroupRoot = "/"
		}
		kubeReserved, err := parseResourceList(s.KubeReserved)
		if err != nil {
			return err
		}
		systemReserved, err := parseResourceList(s.SystemReserved)
		if err != nil {
			return err
		}
		var hardEvictionThresholds []evictionapi.Threshold
		// If the user requested to ignore eviction thresholds, then do not set valid values for hardEvictionThresholds here.
		if !s.ExperimentalNodeAllocatableIgnoreEvictionThreshold {
			hardEvictionThresholds, err = eviction.ParseThresholdConfig([]string{}, s.EvictionHard, nil, nil, nil)
			if err != nil {
				return err
			}
		}
		experimentalQOSReserved, err := cm.ParseQOSReserved(s.QOSReserved)
		if err != nil {
			return err
		}

		devicePluginEnabled := utilfeature.DefaultFeatureGate.Enabled(features.DevicePlugins)

		kubeDeps.ContainerManager, err = cm.NewContainerManager(
			kubeDeps.Mounter,
			kubeDeps.CAdvisorInterface,
			cm.NodeConfig{
				RuntimeCgroupsName:    s.RuntimeCgroups,
				SystemCgroupsName:     s.SystemCgroups,
				KubeletCgroupsName:    s.KubeletCgroups,
				ContainerRuntime:      s.ContainerRuntime,
				CgroupsPerQOS:         s.CgroupsPerQOS,
				CgroupRoot:            s.CgroupRoot,
				CgroupDriver:          s.CgroupDriver,
				KubeletRootDir:        s.RootDirectory,
				ProtectKernelDefaults: s.ProtectKernelDefaults,
				NodeAllocatableConfig: cm.NodeAllocatableConfig{
					KubeReservedCgroupName:   s.KubeReservedCgroup,
					SystemReservedCgroupName: s.SystemReservedCgroup,
					EnforceNodeAllocatable:   sets.NewString(s.EnforceNodeAllocatable...),
					KubeReserved:             kubeReserved,
					SystemReserved:           systemReserved,
					HardEvictionThresholds:   hardEvictionThresholds,
				},
				QOSReserved:                           *experimentalQOSReserved,
				ExperimentalCPUManagerPolicy:          s.CPUManagerPolicy,
				ExperimentalCPUManagerReconcilePeriod: s.CPUManagerReconcilePeriod.Duration,
				ExperimentalPodPidsLimit:              s.PodPidsLimit,
				EnforceCPULimits:                      s.CPUCFSQuota,
			},
			s.FailSwapOn,
			devicePluginEnabled,
			kubeDeps.Recorder)

		if err != nil {
			return err
		}
	}

	...

	if err := RunKubelet(s, kubeDeps, s.RunOnce); err != nil {
		return err
	}

	if s.HealthzPort > 0 {
		healthz.DefaultHealthz()
		go wait.Until(func() {
			err := http.ListenAndServe(net.JoinHostPort(s.HealthzBindAddress, strconv.Itoa(int(s.HealthzPort))), nil)
			if err != nil {
				glog.Errorf("Starting health server failed: %v", err)
			}
		}, 5*time.Second, wait.NeverStop)
	}

	if s.RunOnce {
		return nil
	}

	// If systemd is used, notify it that we have started
	go daemon.SdNotify(false, "READY=1")

	select {
	case <-done:
		break
	case <-stopCh:
		break
	}

	return nil
}
```
kubelet允许三个sources提供pod的update,分别是 file , http , api

查看 RunKubelet()

```

// RunKubelet is responsible for setting up and running a kubelet.  It is used in three different applications:
//   1 Integration tests
//   2 Kubelet binary
//   3 Standalone 'kubernetes' binary
// Eventually, #2 will be replaced with instances of #3
func RunKubelet(kubeServer *options.KubeletServer, kubeDeps *kubelet.Dependencies, runOnce bool) error {
	hostname := nodeutil.GetHostname(kubeServer.HostnameOverride)
	// Query the cloud provider for our node name, default to hostname if kubeDeps.Cloud == nil
	nodeName, err := getNodeName(kubeDeps.Cloud, hostname)
	if err != nil {
		return err
	}
	// Setup event recorder if required.
	makeEventRecorder(kubeDeps, nodeName)

	// TODO(mtaufen): I moved the validation of these fields here, from UnsecuredKubeletConfig,
	//                so that I could remove the associated fields from KubeletConfiginternal. I would
	//                prefer this to be done as part of an independent validation step on the
	//                KubeletConfiguration. But as far as I can tell, we don't have an explicit
	//                place for validation of the KubeletConfiguration yet.
  //哪些sources(file,http,api)过来的update可以使用host network
	hostNetworkSources, err := kubetypes.GetValidatedSources(kubeServer.HostNetworkSources)
	if err != nil {
		return err
	}
  //哪些sources(file,http,api)过来的update可以使用 host pid
	hostPIDSources, err := kubetypes.GetValidatedSources(kubeServer.HostPIDSources)
	if err != nil {
		return err
	}
 //哪些sources(file,http,api)过来的update可以使用 host ipc
	hostIPCSources, err := kubetypes.GetValidatedSources(kubeServer.HostIPCSources)
	if err != nil {
		return err
	}

	privilegedSources := capabilities.PrivilegedSources{
		HostNetworkSources: hostNetworkSources,
		HostPIDSources:     hostPIDSources,
		HostIPCSources:     hostIPCSources,
	}
	capabilities.Setup(kubeServer.AllowPrivileged, privilegedSources, 0)

	credentialprovider.SetPreferredDockercfgPath(kubeServer.RootDirectory)
	glog.V(2).Infof("Using root directory: %v", kubeServer.RootDirectory)

	if kubeDeps.OSInterface == nil {
		kubeDeps.OSInterface = kubecontainer.RealOS{}
	}
  //主要看这里
	k, err := CreateAndInitKubelet(&kubeServer.KubeletConfiguration,
		kubeDeps,
		&kubeServer.ContainerRuntimeOptions,
		kubeServer.ContainerRuntime,
		kubeServer.RuntimeCgroups,
		kubeServer.HostnameOverride,
		kubeServer.NodeIP,
		kubeServer.ProviderID,
		kubeServer.CloudProvider,
		kubeServer.CertDirectory,
		kubeServer.RootDirectory,
		kubeServer.RegisterNode,
		kubeServer.RegisterWithTaints,
		kubeServer.AllowedUnsafeSysctls,
		kubeServer.RemoteRuntimeEndpoint,
		kubeServer.RemoteImageEndpoint,
		kubeServer.ExperimentalMounterPath,
		kubeServer.ExperimentalKernelMemcgNotification,
		kubeServer.ExperimentalCheckNodeCapabilitiesBeforeMount,
		kubeServer.ExperimentalNodeAllocatableIgnoreEvictionThreshold,
		kubeServer.MinimumGCAge,
		kubeServer.MaxPerPodContainerCount,
		kubeServer.MaxContainerCount,
		kubeServer.MasterServiceNamespace,
		kubeServer.RegisterSchedulable,
		kubeServer.NonMasqueradeCIDR,
		kubeServer.KeepTerminatedPodVolumes,
		kubeServer.NodeLabels,
		kubeServer.SeccompProfileRoot,
		kubeServer.BootstrapCheckpointPath,
		kubeServer.NodeStatusMaxImages)
	if err != nil {
		return fmt.Errorf("failed to create kubelet: %v", err)
	}

	// NewMainKubelet should have set up a pod source config if one didn't exist
	// when the builder was run. This is just a precaution.
	if kubeDeps.PodConfig == nil {
		return fmt.Errorf("failed to create kubelet, pod source config was nil")
	}
	podCfg := kubeDeps.PodConfig

	rlimit.RlimitNumFiles(uint64(kubeServer.MaxOpenFiles))

	// process pods and exit.
	if runOnce {
		if _, err := k.RunOnce(podCfg.Updates()); err != nil {
			return fmt.Errorf("runonce failed: %v", err)
		}
		glog.Infof("Started kubelet as runonce")
	} else { //这里启动kubelet
		startKubelet(k, podCfg, &kubeServer.KubeletConfiguration, kubeDeps, kubeServer.EnableServer)
		glog.Infof("Started kubelet")
	}
	return nil
}
```
接着看 CreateAndInitKubelet()


