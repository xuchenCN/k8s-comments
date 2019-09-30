# Kubernetes 基础文档学习，Concepts

## Overview
## Kubernetes Architecture
## Containers
## Workload
### Pod
#### Pod Preset
预先设置一些Pod的属性，有Pod创建的时候通过selector来决定填充到哪些Pod上。
#### Pod Topology Spread Constraints
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
