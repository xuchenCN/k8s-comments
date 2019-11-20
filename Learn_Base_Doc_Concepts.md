# Kubernetes 基础文档学习，Concepts

## Overview
## Kubernetes Architecture
## Containers
## Workload
### Pod
#### Pod Preset
预先设置一些Pod的属性，有Pod创建的时候通过selector来决定填充到哪些Pod上。
#### Pod Topology Spread Constraints since 1.16
为Node设置一些Label划分区域并标示机器，这样使用topologySpreadConstraints特性可以
将Pod均匀的分布在不同的区域，也可以设置skew来决定分布的Pod均匀程度，当不满足条件时也可以设置 DoNotSchedule/ScheduleAnyway 
来设置调度逻辑
#### Disruptions
熔断机制，可以在服务出现问题时进行流量隔离。
#### EphemeralContainers
用于调试或者bug诊断用，有一些限制。

### Controller
#### StatefulSets
设置一些Volume并且与Pod可以进行绑定，当某个Pod失效，Volume并不会删除，新的Pod生成后继续用原来的Volume
#### DaemonSet
新加入的Node符合Selector的可以启动一些Pod
#### Garbage Collection 
垃圾回收机制，有前台，后台两种，还有一些权限设置
#### TTL Controller for Finished Resources
设置一个时长来清理运行完Job的资源，目前只用于Job

### Services, Load Balancing, and Networking
#### Services
暴露服务给Cluster内部使用;
Headless service : 将ClusterIP 设置为None 让DNS能够解析到pod一层
#### Ingress
暴露Service给Cluster外部使用，目前只有单点（如果不在云上），有些方案例如VIP等来解决单点
不同的Controller对应不同的方案
#### Ingress Controller
提供Ingress的控制器，需要单独启动。
#### Network Policies
隔离网络流量，podSelector来设置哪些pod,policyTypes:Ingress(入口),Egress(出口)
#### HostAliases
配置Pod.spec来添加/etc/hosts中的条目
#### Dry Run

Example
```
POST /api/v1/namespaces/test/pods?dryRun=All
    Content-Type: application/json
    Accept: application/json
```
提交后并不会影响后端存储，用来调试。

#### Server Side Apply 1.16 Beta
当有多个客户端与组件同时修改Object时会造成冲突，为了解决这个问题1.16提出Server Side Apply
处理Merge等问题交给服务端；
提出了一个新的定义 ```Fields Managemenet```，将Field设置权限。
```
apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  namespace: default
  labels:
    test-label: test
  managedFields:
  - manager: kubectl
    operation: Apply
    apiVersion: v1
    fields:
      f:metadata:
        f:labels:
          f:test-label: {}
  - manager: kube-controller-manager
    operation: Update
    apiVersion: v1
    time: '2019-03-30T16:00:00.000Z'
    fields:
      f:data:
        f:key: {}
data:
  key: new value
```

#### Assigning Pods to Nodes
##### Affinity, Anti-Affinity
Pod调度到Node时可以通过 nodeAffinity 来影响调度到的Node
requiredDuringSchedulingIgnoredDuringExecution,preferredDuringSchedulingIgnoredDuringExecution 选项相对于hard , soft

对于相对于Pod 有 Inter-pod affinity and anti-affinity
podAffinity 会调度到响应的Pod所在的机器上
podAntiAffinity 会把Pod调度到某些Pod不在的机器上

##### Taints and Tolerations
Taints 将Node设置一个状态 例如 ```kubectl taint nodes node1 key=value:NoSchedule```
影响Scheduler去调度该Node
Pod可以设置 tolerations 来调度到已经设置 Taint的Node上
```
apiVersion: v1
kind: Pod
metadata:
  name: nginx
  labels:
    env: test
spec:
  containers:
  - name: nginx
    image: nginx
    imagePullPolicy: IfNotPresent
  tolerations:
  - key: "example-key"
    operator: "Exists"
    effect: "NoSchedule"
```

##### CPU Management Policies on the Node
--cpu-manager-policy kubelet option 控制Node的cpu分配策略
将所有可用的core - reserved = shared pool
当有符合分配exclusive的POD到来将从shared pool中将CPU移除，并分配给该POD
将POD的资源描述进行分类 （ QoS ）
1. Burstable ：Pod CPU资源描述request和limit不一致
2. BestEffort ： 没有指定资源描述
3. Guaranteed ： cpu资源描述 resquest = limit && >= 1 可分配两个exclusive的CPU
4. Guaranteed ： CPU资源描述并不是整数，所以分在shared pool里
5. Guaranteed ： 只描述了CPU limit 并且是整数 可分配exclusive的cpu

##### Topology Management Policies on a node
用来设置资源的Affinity , 对应的device绑定到对应的cpuset上 (NUMA Node affinity)
必须符合两个条件
1.--cpu-manager-policy = static
2.POD QoS is Guaranteed
分配策略：
none (default) ：啥都不干
best-effort ： 将分配对应的cpuset(preferred NUMA )，如果不符合也分配在该node
restricted ： 将分配对应的cpuset(preferred NUMA )，如果不符合 POD将会 in Terminated state
single-numa-node 将分配对应的cpuset(single NUMA)，如果不符合 POD将会 in Terminated state

```
spec:
  containers:
  - name: nginx
    image: nginx
    resources:
      limits:
        memory: "200Mi"
        cpu: "2"
        example.com/device: "1"
      requests:
        memory: "200Mi"
        cpu: "2"
        example.com/device: "1"
```
This pod runs in the Guaranteed QoS class because requests are equal to limits.

Topology Manager would consider this Pod. The Topology Manager consults the CPU Manager static policy, which returns the topology of available CPUs. Topology Manager also consults Device Manager to discover the topology of available devices for example.com/device.

Topology Manager will use this information to store the best Topology for this container. In the case of this Pod, CPU and Device Manager will use this stored information at the resource allocation stage.


#### Secrets
可以将一些敏感数据加密后(base64加密)存放，给Pod,或者作为kubelet拉取镜像的账号密码
pod使用可以挂载文件，或者使用环境变量

创建secret
```
apiVersion: v1
kind: Secret
metadata:
  name: mysecret
type: Opaque
data:
  username: YWRtaW4=
stringData:
  username: administrator
```

data 为加密的，stringData为明文的

pod作为volume使用
```
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: mypod
    image: redis
    volumeMounts:
    - name: foo
      mountPath: "/etc/foo"
      readOnly: true
  volumes:
  - name: foo
    secret:
      secretName: mysecret
```

将路径对应不同文件

```
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  containers:
  - name: mypod
    image: redis
    volumeMounts:
    - name: foo
      mountPath: "/etc/foo"
  volumes:
  - name: foo
    secret:
      secretName: mysecret
      items:
      - key: username
        path: my-group/my-username
        mode: 511
```

作为环境变量

```
apiVersion: v1
kind: Pod
metadata:
  name: secret-env-pod
spec:
  containers:
  - name: mycontainer
    image: redis
    env:
      - name: SECRET_USERNAME
        valueFrom:
          secretKeyRef:
            name: mysecret
            key: username
      - name: SECRET_PASSWORD
        valueFrom:
          secretKeyRef:
            name: mysecret
            key: password
  restartPolicy: Never
```

使用限制：
secret volume必须要创建在使用secret的Pod之前
文件不能超过1M
kubelet只能为apiserver过来的pod挂载secret
secret作为环境变量必须要在Pod之前启动，除非设置成optional否则pod无法启动
以```secretKeyRef```作为引用的secret不存在则无法启动pod
作为环境变量时通过```envFrom```,如果有不合法的key会允许Pod启动，会记录event

启动的pod如果引用的secret不存在则会等待secret存在后才会启动


### Scheduler framework since 1.15
由于当前core scheduler越来越复杂，导致了诸多问题，而且扩展调度器实现自己的业务逻辑变得更加复杂
该功能能让扩展代码与core scheduler一起编译生成二进制而且不需要修改代码只是扩展
[design doc](https://github.com/kubernetes/enhancements/blob/master/keps/sig-scheduling/20180409-scheduling-framework.md)
Use case [kube-batch](https://github.com/kubernetes-sigs/kube-batch)