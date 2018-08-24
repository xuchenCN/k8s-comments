## 主要记录APIInstall过程,目的是了解Api最后的处理入口与处理方式

ApiServer入口文件
[cmd/kube-apiserver/apiserver.g](cmd/kube-apiserver/apiserver.go)
创建Command的方法
```
command := app.NewAPIServerCommand(server.SetupSignalHandler())
```

然后主要看[RunE](cmd/kube-apiserver/app/server.go#L121)

```
RunE: func(cmd *cobra.Command, args []string) error {
			verflag.PrintAndExitIfRequested()
			utilflag.PrintFlags(cmd.Flags())

			// set default options
			completedOptions, err := Complete(s)
			if err != nil {
				return err
			}

			// validate options
			if errs := completedOptions.Validate(); len(errs) != 0 {
				return utilerrors.NewAggregate(errs)
			}
			// 运行Server
			return Run(completedOptions, stopCh)
		},
```
主要看[Run](cmd/kube-apiserver/app/server.go#L146)方法
```
// Run runs the specified APIServer.  This should never exit.
func Run(completeOptions completedServerRunOptions, stopCh <-chan struct{}) error {
	// To help debugging, immediately log version
	glog.Infof("Version: %+v", version.Get())

	server, err := CreateServerChain(completeOptions, stopCh)
	if err != nil {
		return err
	}

	return server.PrepareRun().Run(stopCh)
}
```
然后查看方法[CreateServerChain](cmd/kube-apiserver/app/server.go#L159)方法
```
// CreateServerChain creates the apiservers connected via delegation.
func CreateServerChain(completedOptions completedServerRunOptions, stopCh <-chan struct{}) (*genericapiserver.GenericAPIServer, error) {
	......
	apiExtensionsServer, err := createAPIExtensionsServer(apiExtensionsConfig, genericapiserver.NewEmptyDelegate())
	if err != nil {
		return nil, err
	}

	kubeAPIServer, err := CreateKubeAPIServer(kubeAPIServerConfig, apiExtensionsServer.GenericAPIServer, sharedInformers, versionedInformers, admissionPostStartHook)
	if err != nil {
		return nil, err
	}
  ......
```
先不看apiExtensionsServer,主要去看CreateKubeAPIServer
```
// CreateKubeAPIServer creates and wires a workable kube-apiserver
func CreateKubeAPIServer(kubeAPIServerConfig *master.Config, delegateAPIServer genericapiserver.DelegationTarget, sharedInformers informers.SharedInformerFactory, versionedInformers clientgoinformers.SharedInformerFactory, admissionPostStartHook genericapiserver.PostStartHookFunc) (*master.Master, error) {
	kubeAPIServer, err := kubeAPIServerConfig.Complete(versionedInformers).New(delegateAPIServer) //Install Api
	if err != nil {
		return nil, err
	}

	kubeAPIServer.GenericAPIServer.AddPostStartHookOrDie("start-kube-apiserver-informers", func(context genericapiserver.PostStartHookContext) error {
		sharedInformers.Start(context.StopCh)
		return nil
	})
	kubeAPIServer.GenericAPIServer.AddPostStartHookOrDie("start-kube-apiserver-admission-initializer", admissionPostStartHook)

	return kubeAPIServer, nil
}
```
初始化各种配置后主要看[New()](pkg/master/master.go#L301)方法
在 306 行 
```
s, err := c.GenericConfig.New("kube-apiserver", delegationTarget)
```
初始化了GenericAPIServer
然后关注320行
```
// install legacy rest storage
	if c.ExtraConfig.APIResourceConfigSource.VersionEnabled(apiv1.SchemeGroupVersion) {
		legacyRESTStorageProvider := corerest.LegacyRESTStorageProvider{
			StorageFactory:              c.ExtraConfig.StorageFactory,
			ProxyTransport:              c.ExtraConfig.ProxyTransport,
			KubeletClientConfig:         c.ExtraConfig.KubeletClientConfig,
			EventTTL:                    c.ExtraConfig.EventTTL,
			ServiceIPRange:              c.ExtraConfig.ServiceIPRange,
			ServiceNodePortRange:        c.ExtraConfig.ServiceNodePortRange,
			LoopbackClientConfig:        c.GenericConfig.LoopbackClientConfig,
			ServiceAccountIssuer:        c.ExtraConfig.ServiceAccountIssuer,
			ServiceAccountAPIAudiences:  c.ExtraConfig.ServiceAccountAPIAudiences,
			ServiceAccountMaxExpiration: c.ExtraConfig.ServiceAccountMaxExpiration,
		}
		m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter, legacyRESTStorageProvider)
	}
```
关键就在这里 
```
m.InstallLegacyAPI(&c, c.GenericConfig.RESTOptionsGetter, legacyRESTStorageProvider)
```
master.go中有两个InstallAPI的地方 一个是这个 ```InstallLegacyAPI``` 还有一个```InstallAPIs```
分别对应[config.go](staging/src/k8s.io/apiserver/pkg/server/config.go#L72)中的两个prefix

进入该方法
```
func (m *Master) InstallLegacyAPI(c *completedConfig, restOptionsGetter generic.RESTOptionsGetter, legacyRESTStorageProvider corerest.LegacyRESTStorageProvider) {
	legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(restOptionsGetter)
	if err != nil {
		glog.Fatalf("Error building core storage: %v", err)
	}

	controllerName := "bootstrap-controller"
	coreClient := coreclient.NewForConfigOrDie(c.GenericConfig.LoopbackClientConfig)
	bootstrapController := c.NewBootstrapController(legacyRESTStorage, coreClient, coreClient, coreClient)
	m.GenericAPIServer.AddPostStartHookOrDie(controllerName, bootstrapController.PostStartHook)
	m.GenericAPIServer.AddPreShutdownHookOrDie(controllerName, bootstrapController.PreShutdownHook)

	if err := m.GenericAPIServer.InstallLegacyAPIGroup(genericapiserver.DefaultLegacyAPIPrefix, &apiGroupInfo); err != nil {
		glog.Fatalf("Error in registering group versions: %v", err)
	}
}
```
主要看
```
legacyRESTStorage, apiGroupInfo, err := legacyRESTStorageProvider.NewLegacyRESTStorage(restOptionsGetter)
```
详细内容
```

func (c LegacyRESTStorageProvider) NewLegacyRESTStorage(restOptionsGetter generic.RESTOptionsGetter) (LegacyRESTStorage, genericapiserver.APIGroupInfo, error) {
  //初始化apiGroupInfo
	apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		Scheme:               legacyscheme.Scheme,
		ParameterCodec:       legacyscheme.ParameterCodec,
		NegotiatedSerializer: legacyscheme.Codecs,
	}
  
	var podDisruptionClient policyclient.PodDisruptionBudgetsGetter
	if policyGroupVersion := (schema.GroupVersion{Group: "policy", Version: "v1beta1"}); legacyscheme.Scheme.IsVersionRegistered(policyGroupVersion) {
		var err error
		podDisruptionClient, err = policyclient.NewForConfig(c.LoopbackClientConfig)
		if err != nil {
			return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
		}
	}
	restStorage := LegacyRESTStorage{}
  //生成各种Storage
	podTemplateStorage := podtemplatestore.NewREST(restOptionsGetter)

	eventStorage := eventstore.NewREST(restOptionsGetter, uint64(c.EventTTL.Seconds()))
	limitRangeStorage := limitrangestore.NewREST(restOptionsGetter)

	resourceQuotaStorage, resourceQuotaStatusStorage := resourcequotastore.NewREST(restOptionsGetter)
	secretStorage := secretstore.NewREST(restOptionsGetter)
	persistentVolumeStorage, persistentVolumeStatusStorage := pvstore.NewREST(restOptionsGetter)
	persistentVolumeClaimStorage, persistentVolumeClaimStatusStorage := pvcstore.NewREST(restOptionsGetter)
	configMapStorage := configmapstore.NewREST(restOptionsGetter)

	namespaceStorage, namespaceStatusStorage, namespaceFinalizeStorage := namespacestore.NewREST(restOptionsGetter)

	endpointsStorage := endpointsstore.NewREST(restOptionsGetter)

	nodeStorage, err := nodestore.NewStorage(restOptionsGetter, c.KubeletClientConfig, c.ProxyTransport)
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	podStorage := podstore.NewStorage(
		restOptionsGetter,
		nodeStorage.KubeletConnectionInfo,
		c.ProxyTransport,
		podDisruptionClient,
	)

	var serviceAccountStorage *serviceaccountstore.REST
	if c.ServiceAccountIssuer != nil && utilfeature.DefaultFeatureGate.Enabled(features.TokenRequest) {
		serviceAccountStorage = serviceaccountstore.NewREST(restOptionsGetter, c.ServiceAccountIssuer, c.ServiceAccountAPIAudiences, c.ServiceAccountMaxExpiration, podStorage.Pod.Store, secretStorage.Store)
	} else {
		serviceAccountStorage = serviceaccountstore.NewREST(restOptionsGetter, nil, nil, 0, nil, nil)
	}

	serviceRESTStorage, serviceStatusStorage := servicestore.NewGenericREST(restOptionsGetter)

	var serviceClusterIPRegistry rangeallocation.RangeRegistry
	serviceClusterIPRange := c.ServiceIPRange
	if serviceClusterIPRange.IP == nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, fmt.Errorf("service clusterIPRange is missing")
	}

	serviceStorageConfig, err := c.StorageFactory.NewConfig(api.Resource("services"))
	if err != nil {
		return LegacyRESTStorage{}, genericapiserver.APIGroupInfo{}, err
	}

	serviceClusterIPAllocator := ipallocator.NewAllocatorCIDRRange(&serviceClusterIPRange, func(max int, rangeSpec string) allocator.Interface {
		mem := allocator.NewAllocationMap(max, rangeSpec)
		// TODO etcdallocator package to return a storage interface via the storageFactory
		etcd := serviceallocator.NewEtcd(mem, "/ranges/serviceips", api.Resource("serviceipallocations"), serviceStorageConfig)
		serviceClusterIPRegistry = etcd
		return etcd
	})
	restStorage.ServiceClusterIPAllocator = serviceClusterIPRegistry

	var serviceNodePortRegistry rangeallocation.RangeRegistry
	serviceNodePortAllocator := portallocator.NewPortAllocatorCustom(c.ServiceNodePortRange, func(max int, rangeSpec string) allocator.Interface {
		mem := allocator.NewAllocationMap(max, rangeSpec)
		// TODO etcdallocator package to return a storage interface via the storageFactory
		etcd := serviceallocator.NewEtcd(mem, "/ranges/servicenodeports", api.Resource("servicenodeportallocations"), serviceStorageConfig)
		serviceNodePortRegistry = etcd
		return etcd
	})
	restStorage.ServiceNodePortAllocator = serviceNodePortRegistry

	controllerStorage := controllerstore.NewStorage(restOptionsGetter)

	serviceRest, serviceRestProxy := servicestore.NewREST(serviceRESTStorage, endpointsStorage, podStorage.Pod, serviceClusterIPAllocator, serviceNodePortAllocator, c.ProxyTransport)
  //安装资源请求路径到对应的Storage处理方法
	restStorageMap := map[string]rest.Storage{
		"pods":             podStorage.Pod,
		"pods/attach":      podStorage.Attach,
		"pods/status":      podStorage.Status,
		"pods/log":         podStorage.Log,
		"pods/exec":        podStorage.Exec,
		"pods/portforward": podStorage.PortForward,
		"pods/proxy":       podStorage.Proxy,
		"pods/binding":     podStorage.Binding,
		"bindings":         podStorage.Binding,

		"podTemplates": podTemplateStorage,

		"replicationControllers":        controllerStorage.Controller,
		"replicationControllers/status": controllerStorage.Status,

		"services":        serviceRest,
		"services/proxy":  serviceRestProxy,
		"services/status": serviceStatusStorage,

		"endpoints": endpointsStorage,

		"nodes":        nodeStorage.Node,
		"nodes/status": nodeStorage.Status,
		"nodes/proxy":  nodeStorage.Proxy,

		"events": eventStorage,

		"limitRanges":                   limitRangeStorage,
		"resourceQuotas":                resourceQuotaStorage,
		"resourceQuotas/status":         resourceQuotaStatusStorage,
		"namespaces":                    namespaceStorage,
		"namespaces/status":             namespaceStatusStorage,
		"namespaces/finalize":           namespaceFinalizeStorage,
		"secrets":                       secretStorage,
		"serviceAccounts":               serviceAccountStorage,
		"persistentVolumes":             persistentVolumeStorage,
		"persistentVolumes/status":      persistentVolumeStatusStorage,
		"persistentVolumeClaims":        persistentVolumeClaimStorage,
		"persistentVolumeClaims/status": persistentVolumeClaimStatusStorage,
		"configMaps":                    configMapStorage,

		"componentStatuses": componentstatus.NewStorage(componentStatusStorage{c.StorageFactory}.serversToValidate),
	}
	if legacyscheme.Scheme.IsVersionRegistered(schema.GroupVersion{Group: "autoscaling", Version: "v1"}) {
		restStorageMap["replicationControllers/scale"] = controllerStorage.Scale
	}
	if legacyscheme.Scheme.IsVersionRegistered(schema.GroupVersion{Group: "policy", Version: "v1beta1"}) {
		restStorageMap["pods/eviction"] = podStorage.Eviction
	}
	if serviceAccountStorage.Token != nil {
		restStorageMap["serviceaccounts/token"] = serviceAccountStorage.Token
	}
	apiGroupInfo.VersionedResourcesStorageMap["v1"] = restStorageMap

	return restStorage, apiGroupInfo, nil
}
```
主要看
```
apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		Scheme:               legacyscheme.Scheme,
		ParameterCodec:       legacyscheme.ParameterCodec,
		NegotiatedSerializer: legacyscheme.Codecs,
	}
```

主要结构```APIGroupInfo```
```

// Info about an API group.
type APIGroupInfo struct {
	PrioritizedVersions []schema.GroupVersion
	// Info about the resources in this group. It's a map from version to resource to the storage.
	VersionedResourcesStorageMap map[string]map[string]rest.Storage
	// OptionsExternalVersion controls the APIVersion used for common objects in the
	// schema like api.Status, api.DeleteOptions, and metav1.ListOptions. Other implementors may
	// define a version "v1beta1" but want to use the Kubernetes "v1" internal objects.
	// If nil, defaults to groupMeta.GroupVersion.
	// TODO: Remove this when https://github.com/kubernetes/kubernetes/issues/19018 is fixed.
	OptionsExternalVersion *schema.GroupVersion
	// MetaGroupVersion defaults to "meta.k8s.io/v1" and is the scheme group version used to decode
	// common API implementations like ListOptions. Future changes will allow this to vary by group
	// version (for when the inevitable meta/v2 group emerges).
	MetaGroupVersion *schema.GroupVersion

	// Scheme includes all of the types used by this group and how to convert between them (or
	// to convert objects from outside of this group that are accepted in this API).
	// TODO: replace with interfaces
	Scheme *runtime.Scheme
	// NegotiatedSerializer controls how this group encodes and decodes data
	NegotiatedSerializer runtime.NegotiatedSerializer
	// ParameterCodec performs conversions for query parameters passed to API calls
	ParameterCodec runtime.ParameterCodec
}
```
其中```VersionedResourcesStorageMap``` 是定位资源的关键
这个数据结构会维护一个 ```Group(v1,v1beta1,...) -> resources/subresources -> storage(实际操作Etcd)``` 的关系

[186](pkg/master/master.go#L186)行开始定义了```map[string]rest.Storage``` 对应的是 resources/subresources = storage(其实就是对应Etcd的一些操作)

```
restStorageMap := map[string]rest.Storage{
		"pods":             podStorage.Pod,
		"pods/attach":      podStorage.Attach,
		....
		"componentStatuses": componentstatus.NewStorage(componentStatusStorage{c.StorageFactory}.serversToValidate),
	}
```
239行 ```apiGroupInfo.VersionedResourcesStorageMap["v1"] = restStorageMap```
其中```v1```是版本号,还有```v1beta1```,```v1alpha1```等
接下来看 [master.go 386](pkg/master/master.go#L386) 行 
```m.GenericAPIServer.InstallLegacyAPIGroup(genericapiserver.DefaultLegacyAPIPrefix, &apiGroupInfo)```
这个方法的两个参数 ```DefaultLegacyAPIPrefix```是上边提到过的两个legacy , non-legacy两个prefix中的 legacy 就是 ```v1```这个值
```apiGroupInfo``` 是之前 ```NewLegacyRESTStorage()```返回的
```

func (s *GenericAPIServer) InstallLegacyAPIGroup(apiPrefix string, apiGroupInfo *APIGroupInfo) error {
	if !s.legacyAPIGroupPrefixes.Has(apiPrefix) {
		return fmt.Errorf("%q is not in the allowed legacy API prefixes: %v", apiPrefix, s.legacyAPIGroupPrefixes.List())
	}
	if err := s.installAPIResources(apiPrefix, apiGroupInfo); err != nil {
		return err
	}

	// Install the version handler.
	// Add a handler at /<apiPrefix> to enumerate the supported api versions.
	s.Handler.GoRestfulContainer.Add(discovery.NewLegacyRootAPIHandler(s.discoveryAddresses, s.Serializer, apiPrefix).WebService())

	return nil
}
```
主要看 ```installAPIResources()```

```

// installAPIResources is a private method for installing the REST storage backing each api groupversionresource
func (s *GenericAPIServer) installAPIResources(apiPrefix string, apiGroupInfo *APIGroupInfo) error {
	for _, groupVersion := range apiGroupInfo.PrioritizedVersions {
		if len(apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version]) == 0 {
			glog.Warningf("Skipping API %v because it has no resources.", groupVersion)
			continue
		}

		apiGroupVersion := s.getAPIGroupVersion(apiGroupInfo, groupVersion, apiPrefix)
		if apiGroupInfo.OptionsExternalVersion != nil {
			apiGroupVersion.OptionsExternalVersion = apiGroupInfo.OptionsExternalVersion
		}

		if err := apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer); err != nil {
			return fmt.Errorf("unable to setup API %v: %v", apiGroupInfo, err)
		}
	}

	return nil
}
```
首先是一个for循环,遍历的内容是```apiGroupInfo.PrioritizedVersions```
这个数据是通过各个包下边的install包提供的,首先看初始化 apiGroupInfo的时候
```
apiGroupInfo := genericapiserver.APIGroupInfo{
		PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
		VersionedResourcesStorageMap: map[string]map[string]rest.Storage{},
		Scheme:               legacyscheme.Scheme,
		ParameterCodec:       legacyscheme.ParameterCodec,
		NegotiatedSerializer: legacyscheme.Codecs,
	}
```
看这句
```
PrioritizedVersions:          legacyscheme.Scheme.PrioritizedVersionsForGroup(""),
```
内容
```

// PrioritizedVersionsForGroup returns versions for a single group in priority order
func (s *Scheme) PrioritizedVersionsForGroup(group string) []schema.GroupVersion {
	ret := []schema.GroupVersion{}
	for _, version := range s.versionPriority[group] {
		ret = append(ret, schema.GroupVersion{Group: group, Version: version})
	}
	for _, observedVersion := range s.observedVersions {
		if observedVersion.Group != group {
			continue
		}
		found := false
		for _, existing := range ret {
			if existing == observedVersion {
				found = true
				break
			}
		}
		if !found {
			ret = append(ret, observedVersion)
		}
	}

	return ret
}
```
遍历两个数据组织成最终的结果,搜索发现很多设置这两个的地方主要看 GroupName="" 的,等抽空加上断点再跟踪一下

回头看```installAPIResources```
```
for _, groupVersion := range apiGroupInfo.PrioritizedVersions
```
这里的GroupVersion结构
```
type GroupVersion struct {
	Group   string
	Version string
}
```
其中Group有类似```kubeadm.k8s.io```,```admission.k8s.io```...;
其中Version有类似```v1```,```v1beta1```,...
然后
```
apiGroupVersion := s.getAPIGroupVersion(apiGroupInfo, groupVersion, apiPrefix)
```
组织成一个带有GroupVersion的ApiInfo
```
func (s *GenericAPIServer) getAPIGroupVersion(apiGroupInfo *APIGroupInfo, groupVersion schema.GroupVersion, apiPrefix string) *genericapi.APIGroupVersion {
	storage := make(map[string]rest.Storage)
	for k, v := range apiGroupInfo.VersionedResourcesStorageMap[groupVersion.Version] {
		storage[strings.ToLower(k)] = v
	}
	version := s.newAPIGroupVersion(apiGroupInfo, groupVersion)
	version.Root = apiPrefix
	version.Storage = storage
	return version
}
```
把该要的东西都组织到一起,apiPrefix,Storage等
```
apiGroupVersion.InstallREST(s.Handler.GoRestfulContainer)
```
开始设置Rest处理
```
// InstallREST registers the REST handlers (storage, watch, proxy and redirect) into a restful Container.
// It is expected that the provided path root prefix will serve all operations. Root MUST NOT end
// in a slash.
func (g *APIGroupVersion) InstallREST(container *restful.Container) error {
	prefix := path.Join(g.Root, g.GroupVersion.Group, g.GroupVersion.Version)
	installer := &APIInstaller{
		group:                        g,
		prefix:                       prefix,
		minRequestTimeout:            g.MinRequestTimeout,
		enableAPIResponseCompression: g.EnableAPIResponseCompression,
	}

	apiResources, ws, registrationErrors := installer.Install()
	versionDiscoveryHandler := discovery.NewAPIVersionHandler(g.Serializer, g.GroupVersion, staticLister{apiResources})
	versionDiscoveryHandler.AddToWebService(ws)
	container.Add(ws)
	return utilerrors.NewAggregate(registrationErrors)
}
```
主要看 ```Install()``` 方法
```

// Install handlers for API resources.
func (a *APIInstaller) Install() ([]metav1.APIResource, *restful.WebService, []error) {
	var apiResources []metav1.APIResource
	var errors []error
	ws := a.newWebService()

	// Register the paths in a deterministic (sorted) order to get a deterministic swagger spec.
	paths := make([]string, len(a.group.Storage))
	var i int = 0
	for path := range a.group.Storage {
		paths[i] = path
		i++
	}
	sort.Strings(paths)
	for _, path := range paths {
		apiResource, err := a.registerResourceHandlers(path, a.group.Storage[path], ws)
		if err != nil {
			errors = append(errors, fmt.Errorf("error in registering resource: %s, %v", path, err))
		}
		if apiResource != nil {
			apiResources = append(apiResources, *apiResource)
		}
	}
	return apiResources, ws, errors
}
```
这里的paths是之前设置那些Storage后来给了APIGroupVersionInfo的结构,里边包含了 resource/subresource的path
排序之后进行```registerResourceHandlers()```
这个方法里设置了Restful对应的请求与资源path对应的storage的处理
```

func (a *APIInstaller) registerResourceHandlers(path string, storage rest.Storage, ws *restful.WebService) (*metav1.APIResource, error) {
	admit := a.group.Admit

	optionsExternalVersion := a.group.GroupVersion
	if a.group.OptionsExternalVersion != nil {
		optionsExternalVersion = *a.group.OptionsExternalVersion
	}

	resource, subresource, err := splitSubresource(path)
	if err != nil {
		return nil, err
	}

	fqKindToRegister, err := a.getResourceKind(path, storage)
	if err != nil {
		return nil, err
	}

	versionedPtr, err := a.group.Creater.New(fqKindToRegister)
	if err != nil {
		return nil, err
	}
	defaultVersionedObject := indirectArbitraryPointer(versionedPtr)
	kind := fqKindToRegister.Kind
	isSubresource := len(subresource) > 0
	//资源分为有namespace和无namespace两种
	// If there is a subresource, namespace scoping is defined by the parent resource
	namespaceScoped := true
	if isSubresource {
		parentStorage, ok := a.group.Storage[resource]
		if !ok {
			return nil, fmt.Errorf("missing parent storage: %q", resource)
		}
		scoper, ok := parentStorage.(rest.Scoper)
		if !ok {
			return nil, fmt.Errorf("%q must implement scoper", resource)
		}
		namespaceScoped = scoper.NamespaceScoped()

	} else {
		scoper, ok := storage.(rest.Scoper)
		if !ok {
			return nil, fmt.Errorf("%q must implement scoper", resource)
		}
		namespaceScoped = scoper.NamespaceScoped()
	}
	//这里其实是对应的storage的操作
	// what verbs are supported by the storage, used to know what verbs we support per path
	creater, isCreater := storage.(rest.Creater)
	namedCreater, isNamedCreater := storage.(rest.NamedCreater)
	lister, isLister := storage.(rest.Lister)
	getter, isGetter := storage.(rest.Getter)
	getterWithOptions, isGetterWithOptions := storage.(rest.GetterWithOptions)
	gracefulDeleter, isGracefulDeleter := storage.(rest.GracefulDeleter)
	collectionDeleter, isCollectionDeleter := storage.(rest.CollectionDeleter)
	updater, isUpdater := storage.(rest.Updater)
	patcher, isPatcher := storage.(rest.Patcher)
	watcher, isWatcher := storage.(rest.Watcher)
	connecter, isConnecter := storage.(rest.Connecter)
	storageMeta, isMetadata := storage.(rest.StorageMetadata)
	if !isMetadata {
		storageMeta = defaultStorageMetadata{}
	}
	exporter, isExporter := storage.(rest.Exporter)
	if !isExporter {
		exporter = nil
	}

	versionedExportOptions, err := a.group.Creater.New(optionsExternalVersion.WithKind("ExportOptions"))
	if err != nil {
		return nil, err
	}

	if isNamedCreater {
		isCreater = true
	}

	var versionedList interface{}
	if isLister {
		list := lister.NewList()
		listGVKs, _, err := a.group.Typer.ObjectKinds(list)
		if err != nil {
			return nil, err
		}
		versionedListPtr, err := a.group.Creater.New(a.group.GroupVersion.WithKind(listGVKs[0].Kind))
		if err != nil {
			return nil, err
		}
		versionedList = indirectArbitraryPointer(versionedListPtr)
	}

	versionedListOptions, err := a.group.Creater.New(optionsExternalVersion.WithKind("ListOptions"))
	if err != nil {
		return nil, err
	}

	var versionedDeleteOptions runtime.Object
	var versionedDeleterObject interface{}
	if isGracefulDeleter {
		versionedDeleteOptions, err = a.group.Creater.New(optionsExternalVersion.WithKind("DeleteOptions"))
		if err != nil {
			return nil, err
		}
		versionedDeleterObject = indirectArbitraryPointer(versionedDeleteOptions)
	}

	versionedStatusPtr, err := a.group.Creater.New(optionsExternalVersion.WithKind("Status"))
	if err != nil {
		return nil, err
	}
	versionedStatus := indirectArbitraryPointer(versionedStatusPtr)
	var (
		getOptions             runtime.Object
		versionedGetOptions    runtime.Object
		getOptionsInternalKind schema.GroupVersionKind
		getSubpath             bool
	)
	if isGetterWithOptions {
		getOptions, getSubpath, _ = getterWithOptions.NewGetOptions()
		getOptionsInternalKinds, _, err := a.group.Typer.ObjectKinds(getOptions)
		if err != nil {
			return nil, err
		}
		getOptionsInternalKind = getOptionsInternalKinds[0]
		versionedGetOptions, err = a.group.Creater.New(a.group.GroupVersion.WithKind(getOptionsInternalKind.Kind))
		if err != nil {
			versionedGetOptions, err = a.group.Creater.New(optionsExternalVersion.WithKind(getOptionsInternalKind.Kind))
			if err != nil {
				return nil, err
			}
		}
		isGetter = true
	}

	var versionedWatchEvent interface{}
	if isWatcher {
		versionedWatchEventPtr, err := a.group.Creater.New(a.group.GroupVersion.WithKind("WatchEvent"))
		if err != nil {
			return nil, err
		}
		versionedWatchEvent = indirectArbitraryPointer(versionedWatchEventPtr)
	}

	var (
		connectOptions             runtime.Object
		versionedConnectOptions    runtime.Object
		connectOptionsInternalKind schema.GroupVersionKind
		connectSubpath             bool
	)
	if isConnecter {
		connectOptions, connectSubpath, _ = connecter.NewConnectOptions()
		if connectOptions != nil {
			connectOptionsInternalKinds, _, err := a.group.Typer.ObjectKinds(connectOptions)
			if err != nil {
				return nil, err
			}

			connectOptionsInternalKind = connectOptionsInternalKinds[0]
			versionedConnectOptions, err = a.group.Creater.New(a.group.GroupVersion.WithKind(connectOptionsInternalKind.Kind))
			if err != nil {
				versionedConnectOptions, err = a.group.Creater.New(optionsExternalVersion.WithKind(connectOptionsInternalKind.Kind))
				if err != nil {
					return nil, err
				}
			}
		}
	}

	allowWatchList := isWatcher && isLister // watching on lists is allowed only for kinds that support both watch and list.
	nameParam := ws.PathParameter("name", "name of the "+kind).DataType("string")
	pathParam := ws.PathParameter("path", "path to the resource").DataType("string")

	params := []*restful.Parameter{}
	actions := []action{}

	var resourceKind string
	kindProvider, ok := storage.(rest.KindProvider)
	if ok {
		resourceKind = kindProvider.Kind()
	} else {
		resourceKind = kind
	}

	tableProvider, _ := storage.(rest.TableConvertor)

	var apiResource metav1.APIResource
	// Get the list of actions for the given scope.
	switch {
	case !namespaceScoped:
		// Handle non-namespace scoped resources like nodes.
		resourcePath := resource
		resourceParams := params
		itemPath := resourcePath + "/{name}"
		nameParams := append(params, nameParam)
		proxyParams := append(nameParams, pathParam)
		suffix := ""
		if isSubresource {
			suffix = "/" + subresource
			itemPath = itemPath + suffix
			resourcePath = itemPath
			resourceParams = nameParams
		}
		apiResource.Name = path
		apiResource.Namespaced = false
		apiResource.Kind = resourceKind
		namer := handlers.ContextBasedNaming{
			SelfLinker:         a.group.Linker,
			ClusterScoped:      true,
			SelfLinkPathPrefix: gpath.Join(a.prefix, resource) + "/",
			SelfLinkPathSuffix: suffix,
		}
		//添加Action
		// Handler for standard REST verbs (GET, PUT, POST and DELETE).
		// Add actions at the resource path: /api/apiVersion/resource
		actions = appendIf(actions, action{"LIST", resourcePath, resourceParams, namer, false}, isLister)
		actions = appendIf(actions, action{"POST", resourcePath, resourceParams, namer, false}, isCreater)
		actions = appendIf(actions, action{"DELETECOLLECTION", resourcePath, resourceParams, namer, false}, isCollectionDeleter)
		// DEPRECATED
		actions = appendIf(actions, action{"WATCHLIST", "watch/" + resourcePath, resourceParams, namer, false}, allowWatchList)

		// Add actions at the item path: /api/apiVersion/resource/{name}
		actions = appendIf(actions, action{"GET", itemPath, nameParams, namer, false}, isGetter)
		if getSubpath {
			actions = appendIf(actions, action{"GET", itemPath + "/{path:*}", proxyParams, namer, false}, isGetter)
		}
		actions = appendIf(actions, action{"PUT", itemPath, nameParams, namer, false}, isUpdater)
		actions = appendIf(actions, action{"PATCH", itemPath, nameParams, namer, false}, isPatcher)
		actions = appendIf(actions, action{"DELETE", itemPath, nameParams, namer, false}, isGracefulDeleter)
		actions = appendIf(actions, action{"WATCH", "watch/" + itemPath, nameParams, namer, false}, isWatcher)
		actions = appendIf(actions, action{"CONNECT", itemPath, nameParams, namer, false}, isConnecter)
		actions = appendIf(actions, action{"CONNECT", itemPath + "/{path:*}", proxyParams, namer, false}, isConnecter && connectSubpath)
		break
	default:
		namespaceParamName := "namespaces"
		// Handler for standard REST verbs (GET, PUT, POST and DELETE).
		namespaceParam := ws.PathParameter("namespace", "object name and auth scope, such as for teams and projects").DataType("string")
		namespacedPath := namespaceParamName + "/{" + "namespace" + "}/" + resource
		namespaceParams := []*restful.Parameter{namespaceParam}

		resourcePath := namespacedPath
		resourceParams := namespaceParams
		itemPath := namespacedPath + "/{name}"
		nameParams := append(namespaceParams, nameParam)
		proxyParams := append(nameParams, pathParam)
		itemPathSuffix := ""
		if isSubresource {
			itemPathSuffix = "/" + subresource
			itemPath = itemPath + itemPathSuffix
			resourcePath = itemPath
			resourceParams = nameParams
		}
		apiResource.Name = path
		apiResource.Namespaced = true
		apiResource.Kind = resourceKind
		namer := handlers.ContextBasedNaming{
			SelfLinker:         a.group.Linker,
			ClusterScoped:      false,
			SelfLinkPathPrefix: gpath.Join(a.prefix, namespaceParamName) + "/",
			SelfLinkPathSuffix: itemPathSuffix,
		}

		actions = appendIf(actions, action{"LIST", resourcePath, resourceParams, namer, false}, isLister)
		actions = appendIf(actions, action{"POST", resourcePath, resourceParams, namer, false}, isCreater)
		actions = appendIf(actions, action{"DELETECOLLECTION", resourcePath, resourceParams, namer, false}, isCollectionDeleter)
		// DEPRECATED
		actions = appendIf(actions, action{"WATCHLIST", "watch/" + resourcePath, resourceParams, namer, false}, allowWatchList)

		actions = appendIf(actions, action{"GET", itemPath, nameParams, namer, false}, isGetter)
		if getSubpath {
			actions = appendIf(actions, action{"GET", itemPath + "/{path:*}", proxyParams, namer, false}, isGetter)
		}
		actions = appendIf(actions, action{"PUT", itemPath, nameParams, namer, false}, isUpdater)
		actions = appendIf(actions, action{"PATCH", itemPath, nameParams, namer, false}, isPatcher)
		actions = appendIf(actions, action{"DELETE", itemPath, nameParams, namer, false}, isGracefulDeleter)
		actions = appendIf(actions, action{"WATCH", "watch/" + itemPath, nameParams, namer, false}, isWatcher)
		actions = appendIf(actions, action{"CONNECT", itemPath, nameParams, namer, false}, isConnecter)
		actions = appendIf(actions, action{"CONNECT", itemPath + "/{path:*}", proxyParams, namer, false}, isConnecter && connectSubpath)

		// list or post across namespace.
		// For ex: LIST all pods in all namespaces by sending a LIST request at /api/apiVersion/pods.
		// TODO: more strongly type whether a resource allows these actions on "all namespaces" (bulk delete)
		if !isSubresource {
			actions = appendIf(actions, action{"LIST", resource, params, namer, true}, isLister)
			actions = appendIf(actions, action{"WATCHLIST", "watch/" + resource, params, namer, true}, allowWatchList)
		}
		break
	}

	// Create Routes for the actions.
	// TODO: Add status documentation using Returns()
	// Errors (see api/errors/errors.go as well as go-restful router):
	// http.StatusNotFound, http.StatusMethodNotAllowed,
	// http.StatusUnsupportedMediaType, http.StatusNotAcceptable,
	// http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
	// http.StatusRequestTimeout, http.StatusConflict, http.StatusPreconditionFailed,
	// http.StatusUnprocessableEntity, http.StatusInternalServerError,
	// http.StatusServiceUnavailable
	// and api error codes
	// Note that if we specify a versioned Status object here, we may need to
	// create one for the tests, also
	// Success:
	// http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent
	//
	// test/integration/auth_test.go is currently the most comprehensive status code test

	mediaTypes, streamMediaTypes := negotiation.MediaTypesForSerializer(a.group.Serializer)
	allMediaTypes := append(mediaTypes, streamMediaTypes...)
	ws.Produces(allMediaTypes...)

	kubeVerbs := map[string]struct{}{}
	reqScope := handlers.RequestScope{
		Serializer:      a.group.Serializer,
		ParameterCodec:  a.group.ParameterCodec,
		Creater:         a.group.Creater,
		Convertor:       a.group.Convertor,
		Defaulter:       a.group.Defaulter,
		Typer:           a.group.Typer,
		UnsafeConvertor: a.group.UnsafeConvertor,
		Authorizer:      a.group.Authorizer,

		// TODO: Check for the interface on storage
		TableConvertor: tableProvider,

		// TODO: This seems wrong for cross-group subresources. It makes an assumption that a subresource and its parent are in the same group version. Revisit this.
		Resource:    a.group.GroupVersion.WithResource(resource),
		Subresource: subresource,
		Kind:        fqKindToRegister,

		MetaGroupVersion: metav1.SchemeGroupVersion,
	}
	if a.group.MetaGroupVersion != nil {
		reqScope.MetaGroupVersion = *a.group.MetaGroupVersion
	}
	if a.group.OpenAPIConfig != nil {
		openAPIDefinitions, err := openapibuilder.BuildOpenAPIDefinitionsForResource(defaultVersionedObject, a.group.OpenAPIConfig)
		if err != nil {
			return nil, fmt.Errorf("unable to build openapi definitions for %v: %v", fqKindToRegister, err)
		}
		reqScope.OpenAPISchema, err = utilopenapi.ToProtoSchema(openAPIDefinitions, fqKindToRegister)
		if err != nil {
			return nil, fmt.Errorf("unable to get openapi schema for %v: %v", fqKindToRegister, err)
		}
	}
	//开始遍历之前添加的action
	for _, action := range actions {
		producedObject := storageMeta.ProducesObject(action.Verb)
		if producedObject == nil {
			producedObject = defaultVersionedObject
		}
		reqScope.Namer = action.Namer

		requestScope := "cluster"
		var namespaced string
		var operationSuffix string
		if apiResource.Namespaced {
			requestScope = "namespace"
			namespaced = "Namespaced"
		}
		if strings.HasSuffix(action.Path, "/{path:*}") {
			requestScope = "resource"
			operationSuffix = operationSuffix + "WithPath"
		}
		if action.AllNamespaces {
			requestScope = "cluster"
			operationSuffix = operationSuffix + "ForAllNamespaces"
			namespaced = ""
		}

		if kubeVerb, found := toDiscoveryKubeVerb[action.Verb]; found {
			if len(kubeVerb) != 0 {
				kubeVerbs[kubeVerb] = struct{}{}
			}
		} else {
			return nil, fmt.Errorf("unknown action verb for discovery: %s", action.Verb)
		}

		routes := []*restful.RouteBuilder{}

		// If there is a subresource, kind should be the parent's kind.
		if isSubresource {
			parentStorage, ok := a.group.Storage[resource]
			if !ok {
				return nil, fmt.Errorf("missing parent storage: %q", resource)
			}

			fqParentKind, err := a.getResourceKind(resource, parentStorage)
			if err != nil {
				return nil, err
			}
			kind = fqParentKind.Kind
		}

		verbOverrider, needOverride := storage.(StorageMetricsOverride)
		//设置实际Restful处理
		switch action.Verb {
		case "GET": // Get a resource.
			var handler restful.RouteFunction
			if isGetterWithOptions {
				handler = restfulGetResourceWithOptions(getterWithOptions, reqScope, isSubresource)
			} else {
				handler = restfulGetResource(getter, exporter, reqScope)
			}

			if needOverride {
				// need change the reported verb
				handler = metrics.InstrumentRouteFunc(verbOverrider.OverrideMetricsVerb(action.Verb), resource, subresource, requestScope, handler)
			} else {
				handler = metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, handler)
			}

			if a.enableAPIResponseCompression {
				handler = genericfilters.RestfulWithCompression(handler)
			}
			doc := "read the specified " + kind
			if isSubresource {
				doc = "read " + subresource + " of the specified " + kind
			}
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("read"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				Writes(producedObject)
			if isGetterWithOptions {
				if err := addObjectParams(ws, route, versionedGetOptions); err != nil {
					return nil, err
				}
			}
			if isExporter {
				if err := addObjectParams(ws, route, versionedExportOptions); err != nil {
					return nil, err
				}
			}
			addParams(route, action.Params)
			routes = append(routes, route)
		case "LIST": // List all resources of a kind.
			doc := "list objects of kind " + kind
			if isSubresource {
				doc = "list " + subresource + " of objects of kind " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulListResource(lister, watcher, reqScope, false, a.minRequestTimeout))
			if a.enableAPIResponseCompression {
				handler = genericfilters.RestfulWithCompression(handler)
			}
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("list"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), allMediaTypes...)...).
				Returns(http.StatusOK, "OK", versionedList).
				Writes(versionedList)
			if err := addObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, err
			}
			switch {
			case isLister && isWatcher:
				doc := "list or watch objects of kind " + kind
				if isSubresource {
					doc = "list or watch " + subresource + " of objects of kind " + kind
				}
				route.Doc(doc)
			case isWatcher:
				doc := "watch objects of kind " + kind
				if isSubresource {
					doc = "watch " + subresource + "of objects of kind " + kind
				}
				route.Doc(doc)
			}
			addParams(route, action.Params)
			routes = append(routes, route)
		case "PUT": // Update a resource.
			doc := "replace the specified " + kind
			if isSubresource {
				doc = "replace " + subresource + " of the specified " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulUpdateResource(updater, reqScope, admit))
			route := ws.PUT(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("replace"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				// TODO: in some cases, the API may return a v1.Status instead of the versioned object
				// but currently go-restful can't handle multiple different objects being returned.
				Returns(http.StatusCreated, "Created", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			addParams(route, action.Params)
			routes = append(routes, route)
		case "PATCH": // Partially update a resource
			doc := "partially update the specified " + kind
			if isSubresource {
				doc = "partially update " + subresource + " of the specified " + kind
			}
			supportedTypes := []string{
				string(types.JSONPatchType),
				string(types.MergePatchType),
				string(types.StrategicMergePatchType),
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulPatchResource(patcher, reqScope, admit, supportedTypes))
			route := ws.PATCH(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Consumes(string(types.JSONPatchType), string(types.MergePatchType), string(types.StrategicMergePatchType)).
				Operation("patch"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				Reads(metav1.Patch{}).
				Writes(producedObject)
			addParams(route, action.Params)
			routes = append(routes, route)
		case "POST": // Create a resource.
			var handler restful.RouteFunction
			if isNamedCreater {
				handler = restfulCreateNamedResource(namedCreater, reqScope, admit)
			} else {
				handler = restfulCreateResource(creater, reqScope, admit)
			}
			handler = metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, handler)
			article := getArticleForNoun(kind, " ")
			doc := "create" + article + kind
			if isSubresource {
				doc = "create " + subresource + " of" + article + kind
			}
			route := ws.POST(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("create"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Returns(http.StatusOK, "OK", producedObject).
				// TODO: in some cases, the API may return a v1.Status instead of the versioned object
				// but currently go-restful can't handle multiple different objects being returned.
				Returns(http.StatusCreated, "Created", producedObject).
				Returns(http.StatusAccepted, "Accepted", producedObject).
				Reads(defaultVersionedObject).
				Writes(producedObject)
			addParams(route, action.Params)
			routes = append(routes, route)
		case "DELETE": // Delete a resource.
			article := getArticleForNoun(kind, " ")
			doc := "delete" + article + kind
			if isSubresource {
				doc = "delete " + subresource + " of" + article + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulDeleteResource(gracefulDeleter, isGracefulDeleter, reqScope, admit))
			route := ws.DELETE(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("delete"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Writes(versionedStatus).
				Returns(http.StatusOK, "OK", versionedStatus).
				Returns(http.StatusAccepted, "Accepted", versionedStatus)
			if isGracefulDeleter {
				route.Reads(versionedDeleterObject)
				if err := addObjectParams(ws, route, versionedDeleteOptions); err != nil {
					return nil, err
				}
			}
			addParams(route, action.Params)
			routes = append(routes, route)
		case "DELETECOLLECTION":
			doc := "delete collection of " + kind
			if isSubresource {
				doc = "delete collection of " + subresource + " of a " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulDeleteCollection(collectionDeleter, isCollectionDeleter, reqScope, admit))
			route := ws.DELETE(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("deletecollection"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(append(storageMeta.ProducesMIMETypes(action.Verb), mediaTypes...)...).
				Writes(versionedStatus).
				Returns(http.StatusOK, "OK", versionedStatus)
			if err := addObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)
		// TODO: deprecated
		case "WATCH": // Watch a resource.
			doc := "watch changes to an object of kind " + kind
			if isSubresource {
				doc = "watch changes to " + subresource + " of an object of kind " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulListResource(lister, watcher, reqScope, true, a.minRequestTimeout))
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("watch"+namespaced+kind+strings.Title(subresource)+operationSuffix).
				Produces(allMediaTypes...).
				Returns(http.StatusOK, "OK", versionedWatchEvent).
				Writes(versionedWatchEvent)
			if err := addObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)
		// TODO: deprecated
		case "WATCHLIST": // Watch all resources of a kind.
			doc := "watch individual changes to a list of " + kind
			if isSubresource {
				doc = "watch individual changes to a list of " + subresource + " of " + kind
			}
			handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulListResource(lister, watcher, reqScope, true, a.minRequestTimeout))
			route := ws.GET(action.Path).To(handler).
				Doc(doc).
				Param(ws.QueryParameter("pretty", "If 'true', then the output is pretty printed.")).
				Operation("watch"+namespaced+kind+strings.Title(subresource)+"List"+operationSuffix).
				Produces(allMediaTypes...).
				Returns(http.StatusOK, "OK", versionedWatchEvent).
				Writes(versionedWatchEvent)
			if err := addObjectParams(ws, route, versionedListOptions); err != nil {
				return nil, err
			}
			addParams(route, action.Params)
			routes = append(routes, route)
		case "CONNECT":
			for _, method := range connecter.ConnectMethods() {
				connectProducedObject := storageMeta.ProducesObject(method)
				if connectProducedObject == nil {
					connectProducedObject = "string"
				}
				doc := "connect " + method + " requests to " + kind
				if isSubresource {
					doc = "connect " + method + " requests to " + subresource + " of " + kind
				}
				handler := metrics.InstrumentRouteFunc(action.Verb, resource, subresource, requestScope, restfulConnectResource(connecter, reqScope, admit, path, isSubresource))
				route := ws.Method(method).Path(action.Path).
					To(handler).
					Doc(doc).
					Operation("connect" + strings.Title(strings.ToLower(method)) + namespaced + kind + strings.Title(subresource) + operationSuffix).
					Produces("*/*").
					Consumes("*/*").
					Writes(connectProducedObject)
				if versionedConnectOptions != nil {
					if err := addObjectParams(ws, route, versionedConnectOptions); err != nil {
						return nil, err
					}
				}
				addParams(route, action.Params)
				routes = append(routes, route)

				// transform ConnectMethods to kube verbs
				if kubeVerb, found := toDiscoveryKubeVerb[method]; found {
					if len(kubeVerb) != 0 {
						kubeVerbs[kubeVerb] = struct{}{}
					}
				}
			}
		default:
			return nil, fmt.Errorf("unrecognized action verb: %s", action.Verb)
		}
		for _, route := range routes {
			route.Metadata(ROUTE_META_GVK, metav1.GroupVersionKind{
				Group:   reqScope.Kind.Group,
				Version: reqScope.Kind.Version,
				Kind:    reqScope.Kind.Kind,
			})
			route.Metadata(ROUTE_META_ACTION, strings.ToLower(action.Verb))
			ws.Route(route)
		}
		// Note: update GetAuthorizerAttributes() when adding a custom handler.
	}

	apiResource.Verbs = make([]string, 0, len(kubeVerbs))
	for kubeVerb := range kubeVerbs {
		apiResource.Verbs = append(apiResource.Verbs, kubeVerb)
	}
	sort.Strings(apiResource.Verbs)

	if shortNamesProvider, ok := storage.(rest.ShortNamesProvider); ok {
		apiResource.ShortNames = shortNamesProvider.ShortNames()
	}
	if categoriesProvider, ok := storage.(rest.CategoriesProvider); ok {
		apiResource.Categories = categoriesProvider.Categories()
	}
	if gvkProvider, ok := storage.(rest.GroupVersionKindProvider); ok {
		gvk := gvkProvider.GroupVersionKind(a.group.GroupVersion)
		apiResource.Group = gvk.Group
		apiResource.Version = gvk.Version
		apiResource.Kind = gvk.Kind
	}

	return &apiResource, nil
}
```
例如GET方法请求的处理,会将Getter绑定进来,最终调用这个Getter的方法,这个Getter其实是之前资源path对应的Storage的处理方法,最终会调用获得数据
Storage也分为cache和 non-cache两种,具体查看Storage初始化部分

