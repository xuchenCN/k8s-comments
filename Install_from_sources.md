# 一. 前期准备
### 1. 安装golang编译环境, 官网(golang.org)下载安装

### 2. git clone https://github.com/kubernetes/kubernetes.git

### 3. 直接在clone的目录下编译 如何编译参考这个第一节

### 4. 将二进制文件上传到服务器上

 

# 二. 生成证书
### 1. 使用cfssl方式生成证书,[参考地址](https://kubernetes.io/docs/concepts/cluster-administration/certificates/#cfssl)
#### 1.1 下载安装
```
curl -L https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 -o cfssl
chmod +x cfssl
curl -L https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64 -o cfssljson
chmod +x cfssljson
curl -L https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64 -o cfssl-certinfo
chmod +x cfssl-certinfo
```
##### 1.2 创建 ca-config.json 文件并填写内容
```Json
{
  "signing": {
    "default": {
      "expiry": "8760h"
    },
    "profiles": {
      "kubernetes": {
        "usages": [
          "signing",
          "key encipherment",
          "server auth",
          "client auth"
        ],
        "expiry": "8760h"
      }
    }
  }
}
```

> 备注：
>> 过期时间配置为10年   
>> ca-config.json：可以定义多个 profiles，分别指定不同的过期时间、使用场景等参数，后续在签名证书时使用某个profile；  
>> signing：表示该证书可用于签名其它证书，生成的ca.pem证书中CA=TRUE；
>> server auth：表示client可以用该CA对server提供的证书进行验证；
>> client auth：表示server可以用该CA对client提供的证书进行验证；
      

##### 1.3 创建 ca-csr.json 并填写内容

```Json
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names":[{
    "C": "<country>",
    "ST": "<state>",
    "L": "<city>",
    "O": "<organization>",
    "OU": "<organization unit>"
  }]
}
```
> 备注:
>> CN : Common Name，kube-apiserver从证书中提取该字段作为请求的用户名；
>> O : Organization，kube-apiserver从证书中提取该字段作为请求用户所属的组；

##### 1.4 生成证书秘钥
```Bash
$ cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

### 2. 生成kubernetes证书
##### 2.1 

```Bash
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "<MASTER_IP>",
    "<MASTER_CLUSTER_IP>",
    "kubernetes",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster",
    "kubernetes.default.svc.cluster.local"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [{
    "C": "<country>",
    "ST": "<state>",
    "L": "<city>",
    "O": "<organization>",
    "OU": "<organization unit>"
  }]
} 
```

##### 2.2 生成kubernetes的证书和私钥
```Bash
$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kubernetes-csr.json | cfssljson -bare kubernetes
```
> 说明：
>> 该证书后面可以提供给k8s集群和etcd集群使用。
>> hosts字段中制定授权使用该证书的IP和域名列表，因为现在要生成的证书需要被Kubernetes Master集群各个节点使用，所以这里指定了各个节点的IP和hostname。同时还要指定集群内部kube-apiserver的多个域名和IP地址10.254.0.1(后边kube-apiserver-service-cluster-ip-range=10.254.0.0/12参数的指定网段的第一个IP)。


##### 2.3 创建kubernetes-admin证书配置文件
```Bash
$ vim admin-csr.json
{
  "CN": "kubernetes-admin",
  "hosts": [
        "172.16.110.108",
        "172.16.110.105",
        "172.16.110.107"
  ],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "HangZhou",
      "L": "HangZhou",
      "O": "system:masters",
      "OU": "system"
    }
  ]
}
```

> 说明：
>> kube-apiserver将提取CN作为客户端的用户名，这里是kubernetes-admin，将提取O作为用户所属的组，这里是system:master。
>> kube-apiserver预定义了一些 RBAC使用的ClusterRoleBindings，例如 cluster-admin将组system:masters与 ClusterRole cluster-admin绑定，而cluster-admin拥有访问kube-apiserver的所有权限，因此kubernetes-admin这个用户将作为集群的超级管理员。

##### 2.4 生成admin证书和私钥
```Bash
$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
```

##### 2.5、创建kube-proxy证书
创建配置文件
```Bash
$ vim kube-proxy-csr.json
{
     "CN": "system:kube-proxy",
     "hosts": [],
     "key": {
       "algo": "rsa",
       "size": 2048
     },
"names": [ {
         "C": "CN",
         "ST": "HangZhoue",
         "L": "HangZhoue",
         "O": "k8s",
         "OU": "System"
} ]
}
```

> 说明：
>> 指定证书User为 system:kube-proxy
>> kube-apiserver 预定义的RoleBinding cluster-admin将User system:kube-proxy与Role system:node-proxier绑定，将Role授予调用kube-apiserver Proxy相关API的权限；

生成证书和私钥

```Bash
$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes  kube-proxy-csr.json | cfssljson -bare kube-proxy
```

最终生成的证书和秘钥规划如下：

|组件|	证书|	说明|
|----|-----|-----|
|etcd|	ca.pem、kubernetes-key.pem、kubernetes.pem|	和kube-apiserver通用
|kube-apiserver|	ca.pem、kubernetes-key.pem、kubernetes.pem|	kube-controller、kube-scheduler和apiserver都是部署在master可以使用非安全通行，不再单独安装证书。
|kube-proxy|	ca.pem、kube-proxy-key.pem、kube-proxy.pem|	
|kubectl	|ca.pem、admin-key.pem、admin.pem|

# 三. Etcd搭建
### 1. [安装etcd](https://coreos.com/etcd/docs/latest/dl_build.html)
### 2. 编写 etcd.service 文件并放置在service目录下(centos7 /usr/lib/systemd/system/)
```Bash
[Unit]
Description=Etcd Server
[Service]
Type=notify
WorkingDirectory=/data/etcd/
EnvironmentFile=-/etc/etcd/etcd.conf
ExecStart=/usr/bin/etcd \\
  --name k8s-master \\
  --cert-file=/etc/kubernetes/ssl/kubernetes.pem \\
  --key-file=/etc/kubernetes/ssl/kubernetes-key.pem \\
  --peer-cert-file=/etc/kubernetes/ssl/kubernetes.pem \\
  --peer-key-file=/etc/kubernetes/ssl/kubernetes-key.pem \\
  --trusted-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --peer-trusted-ca-file=/etc/kubernetes/ssl/ca.pem \\
  --initial-advertise-peer-urls https://172.16.110.108:2380 \\
  --listen-peer-urls https://172.16.110.108:2380 \\
  --listen-client-urls https://172.16.110.108:2379,https://127.0.0.1:2379 \\
  --advertise-client-urls https://172.16.110.108:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster k8s-master=https://172.16.110.108:2380,k8s-node1=https://172.16.110.15:2380,k8s-node2=https://172.16.110.107:2380 \\
  --initial-cluster-state new \\
  --data-dir=/data/etcd
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
> 注意：在不同的设备上要替换name、initial-advertise-peer-urls、listen-peer-urls、listen-client-urls、advertise-client-urls中的名称和IP。

创建etcd的数据目录
```Bash
$ mkdir -p /data/etcd
```
### 3. 启动Etcd服务
```Bash
$ systemctl daemon-reload
$ systemctl start etcd
$ systemctl enable etcd  //开机自动启动
```

> 启动的过程中，如果出现类似下面的错误
>> etcd[1109]: request cluster ID mismatch (got 67a2ce01fa646032 want f863541ccf739acf)
>> 应该是date-dir引起的，清空该目录，重新启动。

### 4. 检查安装
在任意节点执行检查命令
```Bash
$ etcdctl --ca-file=/etc/kubernetes/ssl/ca.pem \
    --cert-file=/etc/kubernetes/ssl/kubernetes.pem \
    --key-file=/etc/kubernetes/ssl/kubernetes-key.pem \
    --endpoints=https://172.16.110.108:2379,https://172.16.110.105:2379,https://172.16.110.107:2379   cluster-health
```
输出
```Bash
member 41793ee167c4a0b1 is healthy: got healthy result from https://172.16.110.105:2379
member d5e994c7ce1b8ced is healthy: got healthy result from https://172.16.110.107:2379
member e809b7931db45374 is healthy: got healthy result from https://172.16.110.108:2379
cluster is healthy
```
# 三. 安装Flannel [参考文档](http://www.heaventony.com/2017/06/29/k8s1-6-6%E9%9B%86%E7%BE%A4%E9%83%A8%E7%BD%B2-%E5%BC%80%E5%90%AFTLS%E5%AE%89%E5%85%A8%E8%AE%A4%E8%AF%81-%EF%BC%88%E4%BA%8C%EF%BC%89/)

# 四. 安装kubectl
> kubectl 默认从 ~/.kube/config 配置文件获取访问 kube-apiserver 地址、证书、用户名等信息，如果没有配置该文件，执行命令时出错：
```Bash
$ kubectl get componentstatuses
The connection to the server localhost:8080 was refused - did you specify the right host or port?
```
### 1. 安装admin证书和私钥
将前面创建的admin证书和私钥拷贝到/etc/kubernetes/ssl目录下

### 2. 创建kubectl kubeconfig文件
```Bash
#设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server="https://172.16.110.108:6443"
#设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=/etc/kubernetes/ssl/admin.pem \
  --embed-certs=true \
  --client-key=/etc/kubernetes/ssl/admin-key.pem
#设置上下文参数
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin
#设置默认上下文
kubectl config use-context kubernetes
```

# 五. 部署master节点
### 1. 部署apiserver
##### 1.1 配置 token 文件
> k8s支持通过kube-apiserver为客户端生成TLS证书的TLS Bootstrapping功能，kubelet 首次启动时向 kube-apiserver 发送 TLS Bootstrapping 请求，kube-apiserver 验证 kubelet 请求中的 token 是否与它配置的 token.csv 一致，如果一致则自动为 kubelet生成证书和秘钥。
[生成方法](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/)
请阅读[RBAC文档](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#api-overview)
生成后
```Bash
ZhqAdfUAmq6tRLTD5HxIOYBQg19fYQ38,kubelet-bootstrap,10001,"system:node"
```
移动到
```Bash
$ mv token.csv /etc/kubernetes/
```
##### 1.2 创建kube-apiserver的systemd unit文件
kube-apiserver.service
```Bash
[Unit]
  Description=Kubernetes API Service
  Documentation=https://github.com/GoogleCloudPlatform/kubernetes
  After=network.target
  After=etcd.service
[Service]
  EnvironmentFile=-/etc/kubernetes/config
  EnvironmentFile=-/etc/kubernetes/apiserver
  ExecStart=/root/k8s/cmd/kube-apiserver \
          $KUBE_LOGTOSTDERR \
          $KUBE_LOG_LEVEL \
          $KUBE_ETCD_SERVERS \
          $KUBE_API_ADDRESS \
          $KUBE_API_PORT \
          $KUBELET_PORT \
          $KUBE_ALLOW_PRIV \
          $KUBE_SERVICE_ADDRESSES \
          $KUBE_ADMISSION_CONTROL \
          $KUBE_API_ARGS
  Restart=on-failure
  Type=notify
  LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
##### 1.3 创建config在前面创建的/etc/kubernetes目录下
```Bash
KUBE_LOGTOSTDERR="--logtostderr=true"
KUBE_LOG_LEVEL="--v=0"
KUBE_ALLOW_PRIV="--allow-privileged=true"
KUBE_MASTER="--master=http://10.100.208.177:8080"
```
##### 1.4 创建apiserver配置文件同样在/etc/kubernetes目录下，内容如下：
```Bash
KUBE_API_ADDRESS="--advertise-address=10.100.208.177 --bind-address=10.100.208.177 --insecure-bind-address=10.100.208.177"
KUBE_ETCD_SERVERS="--etcd-servers=https://10.100.208.177:2379"
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"
KUBE_ADMISSION_CONTROL="--admission-control=ServiceAccount,NamespaceLifecycle,NamespaceExists,LimitRanger,ResourceQuota"
KUBE_API_ARGS="--authorization-mode=RBAC --runtime-config=rbac.authorization.k8s.io/v1beta1 --kubelet-https=true --token-auth-file=/etc/kubernetes/token.csv --service-node-port-range=30000-32767 --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem --client-ca-file=/etc/kubernetes/ssl/ca.pem --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem --etcd-cafile=/etc/kubernetes/ssl/ca.pem --etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem --etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem --enable-swagger-ui=true --apiserver-count=3 --audit-log-maxage=30 --audit-log-maxbackup=3 --audit-log-maxsize=100 --audit-log-path=/var/lib/audit.log --event-ttl=1h"
```
>> --authorization-mode=RBAC 指定在安全端口使用 RBAC 授权模式，拒绝未通过授权的请求；

>> kube-scheduler、kube-controller-manager 一般和 kube-apiserver 部署在同一台机器上，它们使用非安全端口和 kube-apiserver通信;

>> kubelet、kube-proxy、kubectl 部署在其它 Node 节点上，如果通过安全端口访问 kube-apiserver，则必须先通过 TLS 证书认证，再通过 RBAC 授权；

>> kube-proxy、kubectl 通过在使用的证书里指定相关的 User、Group 来达到通过 RBAC 授权的目的；

>> 如果使用了 kubelet TLS Boostrap 机制，则不能再指定 --kubelet-certificate-authority、--kubelet-client-certificate 和 --kubelet-client-key 选项，否则后续 kube-apiserver 校验 kubelet 证书时出现 ”x509: certificate signed by unknown authority“ 错误；

>> --admission-control 值必须包含 ServiceAccount；

>> --bind-address 不能为 127.0.0.1；

>> runtime-config配置为rbac.authorization.k8s.io/v1beta1，表示运行时的apiVersion；

>> --service-cluster-ip-range 指定 Service Cluster IP 地址段，该地址段不能路由可达；

>> 缺省情况下 kubernetes 对象保存在 etcd /registry 路径下，可以通过 --etcd-prefix参数进行调整；

启动服务
```Bash
$ sudo systemctl daemon-reload
$ sudo systemctl enable kube-apiserver
$ sudo systemctl start kube-apiserver
$ sudo systemctl status kube-apiserver
```

### 2. 部署kube-controller-manager
##### 2.1 创建kube-controller-manager的systemd unit文件
kube-controller-manager.service
```Bash
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/controller-manager
ExecStart=/root/k8s/cmd/kube-controller-manager \
           $KUBE_LOGTOSTDERR \
           $KUBE_LOG_LEVEL \
           $KUBE_MASTER \
           $KUBE_CONTROLLER_MANAGER_ARGS
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
```
##### 2.2 创建controller-manager文件同样放在/etc/kubernetes/目录下，内容如下：
```Bash
KUBE_CONTROLLER_MANAGER_ARGS="--address=127.0.0.1 --service-cluster-ip-range=10.254.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem --root-ca-file=/etc/kubernetes/ssl/ca.pem --leader-elect=true"
```
>> --service-cluster-ip-range 参数指定 Cluster 中 Service 的CIDR范围，该网络在各 Node 间必须路由不可达，必须和 kube-apiserver 中的参数一致；

>> --cluster-signing-* 指定的证书和私钥文件用来签名为 TLS BootStrap 创建的证书和私钥；

>> --root-ca-file 用来对 kube-apiserver 证书进行校验，指定该参数后，才会在Pod 容器的 ServiceAccount 中放置该 CA 证书文件；

>> --address 值必须为 127.0.0.1，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器

启动服务
```Bash
$ sudo systemctl daemon-reload
$ sudo systemctl enable kube-controller-manager
$ sudo systemctl start kube-controller-manager
$ sudo systemctl status kube-controller-manager
```

### 3. kube-scheduler
##### 3.1 创建kube-scheduler的systemd unit文件 文件为/etc/systemd/system/kube-scheduler.service,内容如下：
```Bash
[Unit]
   Description=Kubernetes Scheduler Plugin
   Documentation=https://github.com/GoogleCloudPlatform/kubernetes
[Service]
   EnvironmentFile=-/etc/kubernetes/config
   EnvironmentFile=-/etc/kubernetes/scheduler
   ExecStart=/root/k8s/cmd/kube-scheduler \
               $KUBE_LOGTOSTDERR \
               $KUBE_LOG_LEVEL \
               $KUBE_MASTER \
               $KUBE_SCHEDULER_ARGS
   Restart=on-failure
   LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
##### 3.2 创建scheduler文件 文件同样是在/etc/kubernetes目录下，内容如下：
```Bash
KUBE_SCHEDULER_ARGS="--leader-elect=true --address=127.0.0.1"
```
>> --address 值同样必须为 127.0.0.1，因为当前 kube-apiserver 期望 scheduler 和 controller-manager 在同一台机器；

启动服务
```Bash
$ systemctl daemon-reload
$ systemctl enable kube-scheduler
$ systemctl start kube-scheduler
$ systemctl status kube-scheduler
```
### 4. 验证安装

```Bash
$ kubectl get componentstatuses
NAME                 STATUS    MESSAGE              ERROR
scheduler            Healthy   ok
controller-manager   Healthy   ok
etcd-0               Healthy   {"health": "true"}
etcd-2               Healthy   {"health": "true"}
etcd-1               Healthy   {"health": "true"}
```

# 五. node节点安装[参考](http://www.heaventony.com/2017/06/30/k8s1-6-6%E9%9B%86%E7%BE%A4%E9%83%A8%E7%BD%B2-%E5%BC%80%E5%90%AFTLS%E5%AE%89%E5%85%A8%E8%AE%A4%E8%AF%81-%EF%BC%88%E4%B8%89%EF%BC%89/)
### 1. 安装证书和私钥
将之前生成admin-key.pem、admin.pem、ca-key.pem、ca.pem、kube-proxy-key.pem、kube-proxy.pem、kubernetes-key.pem、kubernetes.pem等证书拷贝到108、105、107三台设备的/etc/kubernetes/ssl目录下，将token.csv文件拷贝到/etc/kubernetes目录下。

### 2. 安装配置kubelet
##### 2.1 创建角色绑定
```Bash
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node --user=kubelet-bootstrap
```
>> kubelet 启动时向 kube-apiserver 发送 TLS bootstrapping 请求，需要先将 bootstrap token 文件中的 kubelet-bootstrap 用户赋予 system:node 角色，然后 kubelet 才有权限创建认证请求(certificatesigningrequests)：

>> --user=kubelet-bootstrap 是文件 /etc/kubernetes/token.csv 中指定的用户名

##### 2.2 创建bootstrapping kubeconfig文件
```Bash
#设置集群参数
$ kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server="https://<MASTER_IP>:6443" \
  --kubeconfig=bootstrap.kubeconfig
#设置客户端认证参数
$ kubectl config set-credentials kubelet-bootstrap \
     --token=<Your token on the token.csv> \
     --kubeconfig=bootstrap.kubeconfig
#设置上下文参数
$ kubectl config set-context default \
     --cluster=kubernetes \
     --user=kubelet-bootstrap \
     --kubeconfig=bootstrap.kubeconfig
#设置默认上下文
$ kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```

##### 2.3 创建kubelet的systemd unit文件 文件为/etc/systemd/system/kubelet.service，内容如下：
```Bash
[Unit]
   Description=Kubernetes Kubelet Server
   After=docker.service
   Requires=docker.service
[Service]
   WorkingDirectory=/var/lib/kubelet
   EnvironmentFile=-/etc/kubernetes/config
   EnvironmentFile=-/etc/kubernetes/kubelet
   ExecStart=/root/k8s/cmd/kubelet \
               $KUBE_LOGTOSTDERR \
               $KUBE_LOG_LEVEL \
               $KUBELET_API_SERVER \
               $KUBELET_ADDRESS \
               $KUBELET_PORT \
               $KUBELET_HOSTNAME \
               $KUBE_ALLOW_PRIV \
               $KUBELET_POD_INFRA_CONTAINER \
               $KUBELET_ARGS
Restart=on-failure 
[Install]
WantedBy=multi-user.target
```
创建工作目录
```Bash
$ mkdir -p /var/lib/kubelet
```
##### 2.4 创建kubelet配置文件
/etc/kubernetes/kubelet
```Bash
KUBELET_ADDRESS="--address=10.100.208.178"
KUBELET_HOSTNAME="--hostname-override=10.100.208.178"
KUBELET_POD_INFRA_CONTAINER="--pod-infra-container-image=registry.access.redhat.com/rhel7/pod-infrastructure:latest"
KUBELET_ARGS="--config=/etc/kubernetes/manifests/kubelet.yml --cluster_dns=10.254.0.2 --kubeconfig=/etc/kubernetes/bootstrap.kubeconfig --cert-dir=/etc/kubernetes/ssl --cluster_domain=cluster.local. --hairpin-mode promiscuous-bridge --serialize-image-pulls=false"
```
>> --address 不能设置为 127.0.0.1，否则后续 Pods 访问 kubelet 的 API 接口时会失败，因为 Pods 访问的 127.0.0.1指向自己而不是 kubelet，然后不同的节点根据实际IP来配置；

>> 如果设置了 --hostname-override 选项，则 kube-proxy 也需要设置该选项，否则会出现找不到 Node 的情况；

>> --experimental-bootstrap-kubeconfig 指向 bootstrap kubeconfig 文件，kubelet 使用该文件中的用户名和 token 向 kube-apiserver 发送 TLS Bootstrapping 请求；

>> 管理员通过了 CSR 请求后，kubelet 自动在 --cert-dir 目录创建证书和私钥文件(kubelet-client.crt 和 kubelet-client.key)，然后写入 --kubeconfig 文件(自动创建 --kubeconfig 指定的文件)；

>> 建议在 --kubeconfig 配置文件中指定 kube-apiserver 地址，如果未指定 --api-servers 选项，则必须指定 --require-kubeconfig 选项后才从配置文件中读取 kue-apiserver 的地址，否则 kubelet 启动后将找不到 kube-apiserver (日志中提示未找到 API Server），kubectl get nodes 不会返回对应的 Node 信息;

>> --cluster_dns 指定 kubedns 的 Service IP(可以先分配，后续创建 kubedns 服务时指定该 IP)，--cluster_domain 指定域名后缀，这两个参数同时指定后才会生效；

可选配置
/etc/kubernetes/manifests/kubelet.yml
[相关文档](https://kubernetes.io/docs/tasks/administer-cluster/kubelet-config-file/)
```Bash
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
failSwapOn: false
kubeletCgroups: /systemd/system.slice
evictionHard:
    memory.available: "200Mi"
```

启动服务
```Bash
$ sudo systemctl daemon-reload
$ sudo systemctl enable kubelet
$ sudo systemctl start kubelet
$ sudo systemctl status kubelet
```
如果启动出现下面错误：
```Bash
failed to create kubelet: misconfiguration: kubelet cgroup driver: "systemd" is different from docker cgroup driver: "systemd" is different from docker cgroup driver: "cgroupfs"
```
要么修改kubelet的配置要么修改docker的配置，我这里修改kubelet的配置如下：
```Bash
KUBELET_ARGS="--cgroup-driver=cgroupfs --cluster_dns=10.254.0.2 --experimental-bootstrap-kubeconfig=/etc/kubernetes/bootstrap.kubeconfig --kubeconfig=/etc/kubernetes/kubelet.kubeconfig --require-kubeconfig --cert-dir=/etc/kubernetes/ssl --cluster_domain=cluster.local. --hairpin-mode promiscuous-bridge --serialize-image-pulls=false"
```

### 3. 安装配置kube-proxy
##### 3.1 创建kube-proxy kubeconfig文件
```Bash
# 设置集群参数
$ kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server="https://172.16.110.108:6443" \
  --kubeconfig=kube-proxy.kubeconfig
# 设置客户端认证参数
$ kubectl config set-credentials kube-proxy \
  --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
  --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig
# 设置上下文参数
$ kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig
# 设置默认上下文
$ kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```
>> 设置集群参数和客户端认证参数时 --embed-certs 都为 true，这会将 certificate-authority、client-certificate和 client-key 指向的证书文件内容写入到生成的 kube-proxy.kubeconfig 文件中；

>> kube-proxy.pem 证书中 CN 为 system:kube-proxy，kube-apiserver 预定义的 RoleBinding cluster-admin 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；

##### 3.2 创建kube-proxy文件在目录/etc/kubernetes，内容如下：
```Bash
KUBE_PROXY_ARGS="--bind-address=10.100.208.178 --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig --cluster-cidr=10.254.0.0/16"
```
>> --hostname-override 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 iptables 规则；

>> --cluster-cidr 必须与 kube-apiserver 的 --service-cluster-ip-range 选项值一致；

>> kube-proxy 根据 --cluster-cidr 判断集群内部和外部流量，指定 --cluster-cidr 或 --masquerade-all 选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT；

>> --kubeconfig 指定的配置文件嵌入了 kube-apiserver 的地址、用户名、证书、秘钥等请求和认证信息；

>>预定义的 RoleBinding cluster-admin 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；

##### 3.2 创建kube-proxy的systemd unit文件
```Bash
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target
[Service]
EnvironmentFile=-/etc/kubernetes/config
EnvironmentFile=-/etc/kubernetes/kube-proxy
ExecStart=/root/k8s/cmd/kube-proxy \
           $KUBE_LOGTOSTDERR \
           $KUBE_LOG_LEVEL \
           $KUBE_MASTER \
           $KUBE_PROXY_ARGS
Restart=on-failure
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
```
确定服务
```Bash
$ sudo systemctl daemon-reload
$ sudo systemctl enable kube-proxy
$ sudo systemctl start kube-proxy
$ sudo systemctl status kube-proxy
```

### 4. 验证安装
```Bash
$ kubectl get nodes
NAME             STATUS    ROLES     AGE       VERSION
xxx.xxx.xxx.xxx   Ready     <none>    2d17h     xxx
............
```
