
# Prepare Nodes

Node1 10.110.158.162 (master,kubelet,etcd)
Node1 10.110.158.165 (kubelet)

Disable the SELinux using the below commands.

```
exec bash
setenforce 0
sed -i --follow-symlinks 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/sysconfig/selinux
```

Open the sysctl.conf file.

```vi /etc/sysctl.conf```

Add the below entries in the conf file to change the Linux host bridge values and save the changes.

```
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
```

open the fstab file.

```vi /etc/fstab```

Disable the SWAP by adding the # symbol at the beginning and save the changes.

```
# /dev/mapper/centos-swap swap                    swap    defaults        0 0
```

Restart the VM using the command init 6 to apply the SELinux and SWAP changes.

```
# Install Docker CE
## Set up the repository
### Install required packages.
    yum install yum-utils device-mapper-persistent-data lvm2

### Add docker repository.
yum-config-manager \
    --add-repo \
    https://download.docker.com/linux/centos/docker-ce.repo

## Install docker ce.
yum update && yum install docker-ce-18.06.1.ce

## Create /etc/docker directory.
mkdir /etc/docker

mkdir -p /etc/systemd/system/docker.service.d

# Restart docker.
systemctl daemon-reload
systemctl restart docker
```

Install Nvidia-docker 2.0

Remove nvidia-docker 1.0

```
docker volume ls -q -f driver=nvidia-docker | xargs -r -I{} -n1 docker ps -q -a -f volume={} | xargs -r docker rm -f
sudo yum remove nvidia-docker
```

Add yum repo

```
distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
curl -s -L https://nvidia.github.io/nvidia-docker/$distribution/nvidia-docker.repo | \
  sudo tee /etc/yum.repos.d/nvidia-docker.repo
```

Install Nvidia-docker 2.0

```
sudo yum install nvidia-docker2
sudo pkill -SIGHUP dockerd
```
Config Docker ```/etc/docker/daemon.json```

```
  "insecure-registries":["xxx","xxx"],
  "registry-mirrors": ["xxx"],
  "data-root" : "/home/docker",
  "default-runtime": "nvidia",
  "experimental": true,
  "live-restore": true,
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ],
  "runtimes": {
     "nvidia": {
        "path": "nvidia-container-runtime",
        "runtimeArgs": []
     }
  }
```

Config TLS

```
mkdir /etc/kubernetes
```
Install cfssl

```
$ wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
$ chmod +x cfssl_linux-amd64
$ mv cfssl_linux-amd64 /usr/local/bin/cfssl
$ wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
$ chmod +x cfssljson_linux-amd64
$ mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
$ wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
$ chmod +x cfssl-certinfo_linux-amd64
$ mv cfssl-certinfo_linux-amd64 /usr/local/bin/cfssl-certinfo
```

Will generate certs 

```
ca-key.pem
ca.pem
kubernetes-key.pem
kubernetes.pem
kube-proxy.pem
kube-proxy-key.pem
admin.pem
admin-key.pem
```

relations

```
etcd  ca.pem、kubernetes-key.pem、kubernetes.pem；
kube-apiserver： ca.pem、kubernetes-key.pem、kubernetes.pem；
kubelet： ca.pem；
kube-proxy： ca.pem、kube-proxy-key.pem、kube-proxy.pem；
kubectl： ca.pem、admin-key.pem、admin.pem；
kube-controller-manager： ca-key.pem、ca.pem
```


$ vim ca-config.json

```
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
vim ca-csr.json

```
{
  "CN": "kubernetes",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names":[{
    "C": "CN",
    "ST": "Peking",
    "L": "Peking",
    "O": "k8s",
    "OU": "system"
  }]
}
```

Generate private key

```
cfssl gencert -initca ca-csr.json | cfssljson -bare ca
```

vim kubernetes-csr.json

```
{
  "CN": "kubernetes",
  "hosts": [
    "127.0.0.1",
    "10.110.158.162",
    "10.254.0.1",
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
    "C": "CN",
    "ST": "Peking",
    "L": "Peking",
    "O": "k8s",
    "OU": "system"
  }]
}
```
vim admin-csr.json

```
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Peking",
      "L": "Peking",
      "O": "system:masters",
      "OU": "system"
    }
  ]
}
```

```
$ cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
```

vim kube-proxy-csr.json

```
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "Peking",
      "L": "Peking",
      "O": "k8s",
      "OU": "system"
    }
  ]
}
```
vim metrics-server-csr.json

```
{
     "CN": "system:metrics-server",
     "hosts": [],
     "key": {
       "algo": "rsa",
       "size": 2048
     },
"names": [ {
         "C": "CN",
         "ST": "Peking",
         "L": "Peking",
         "O": "k8s",
         "OU": "system"
} ]

}
```

```
cfssl gencert -ca=/etc/kubernetes/ssl/ca.pem -ca-key=/etc/kubernetes/ssl/ca-key.pem -config=ca-config.json -profile=kubernetes metrics-server-csr.json | cfssljson -bare metrics-server
```


On all nodes ``` mkdir -p /etc/kubernetes/ssl/```
Dispatch all pem files acorrding the relations to ```/etc/kubernetes/ssl/```


```
etcd  ca.pem、kubernetes-key.pem、kubernetes.pem；
kube-apiserver： ca.pem、kubernetes-key.pem、kubernetes.pem；
kubelet： ca.pem；
kube-proxy： ca.pem、kube-proxy-key.pem、kube-proxy.pem；
kubectl： ca.pem、admin-key.pem、admin.pem；
kube-controller-manager： ca-key.pem、ca.pem
metrics-server: metrics-server.pem metrics-server-key.pem
```

Install Etcd

```
wget https://github.com/coreos/etcd/releases/download/v3.2.1/etcd-v3.2.1-linux-amd64.tar.gz
tar -xvf etcd-v3.2.1-linux-amd64.tar.gz
etcd-v3.2.1-linux-amd64/etcd* /usr/bin
```

vim /etc/systemd/system/etcd.service

```
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

```
systemctl daemon-reload
systemctl start etcd
systemctl enable etcd
```

Make etcdctl alternatively file
etcdctl_ssl

```
ETCDCTL_API=3 ./etcdctl --endpoints https://10.110.158.162:2379 --cacert /etc/kubernetes/ssl/ca.pem --cert  /etc/kubernetes/ssl/kubernetes.pem  --key /etc/kubernetes/ssl/kubernetes-key.pem --dial-timeout=5s $@
```

etcdctl_ssl_v2

```
ETCDCTL_API=2 ./etcdctl     --endpoints https://10.110.158.162:2379 --ca-file /etc/kubernetes/ssl/ca.pem --cert-file /etc/kubernetes/ssl/kubernetes.pem  --key-file /etc/kubernetes/ssl/kubernetes-key.pem  $@
```

Install flannel

```
yum install flannel
```

/usr/lib/systemd/system/flanneld.service

```
[Unit]
Description=flannel
After=network.target
After=network-online.target
Wants=network-online.target
After=etcd.service
Before=docker.service
[Service]
#EnvironmentFile=-/etc/sysconfig/flanneld
ExecStart=/opt/flannel/flanneld -v=0 -etcd-prefix=/flannel/network --ip-masq --iface=eno1 --etcd-endpoints=https://10.110.158.162:2379 -etcd-cafile=/etc/kubernetes/ssl/ca.pem  -etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem -etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem
[Install]
WantedBy=multi-user.target
RequiredBy=docker.service
```

```
./etcdctl_ssl_v2   mk /flannel/network/config '{"Network":"172.17.0.0/16"}'
```

```
systemctl daemon-reload
systemctl start flanneld
```

Config docker /usr/lib/systemd/system/docker.service

```
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service flanneld.service
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=-/run/flannel/subnet.env
# the default is not to use systemd for cgroups because the delegate issues still
# exists and systemd currently does not support the cgroup feature set required
# for containers run by docker
ExecStart=/usr/bin/dockerd --bip=${FLANNEL_SUBNET} --mtu=${FLANNEL_MTU}
ExecReload=/bin/kill -s HUP $MAINPID
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
# Uncomment TasksMax if your systemd version supports it.
# Only systemd 226 and above support this version.
#TasksMax=infinity
TimeoutStartSec=0
# set delegate yes so that systemd does not reset the cgroups of docker containers
Delegate=yes
# kill only the docker process, not all processes in the cgroup
KillMode=process
# restart the docker process if it exits prematurely
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```

Don't forget ``` systemctl daemon-reload ```

Install kubernetes from source code 

```
git clone https://github.com/kubernetes/kubernetes.git
```

[Install Go](https://golang.org/doc/install) if needed

```
cd kubernetes
make
```
After make find commands from ```_output``` directory

Set  ```_output``` directory to ```PATH``` eniroments

Create kubeconfig

```
#set cluster
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server="https://172.16.110.108:6443"
#set credentials
kubectl config set-credentials admin \
  --client-certificate=/etc/kubernetes/ssl/admin.pem \
  --embed-certs=true \
  --client-key=/etc/kubernetes/ssl/admin-key.pem
#set context
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin
#set defualt context
kubectl config use-context kubernetes
```
Generate token [link](https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet-tls-bootstrapping/)

```
head -c 16 /dev/urandom | od -An -t x | tr -d ' '
```

vim token.csv

```
<token>,kubelet-bootstrap,10001,"system:node"
```

mv token.csv /etc/kubernetes/

vim /usr/lib/systemd/system/kube-apiserver.service

```
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

vim /etc/kubernetes/config

```
KUBE_LOGTOSTDERR="--logtostderr=true"
KUBE_LOG_LEVEL="--v=0"
KUBE_ALLOW_PRIV="--allow-privileged=true"
KUBE_MASTER="--master=http://<master_ip>:8080"
```

vim /etc/kubernetes/apiserver

```
KUBE_API_ADDRESS="--advertise-address=10.110.158.162 --bind-address=10.110.158.162 --insecure-bind-address=10.110.158.162"
KUBE_ETCD_SERVERS="--etcd-servers=https://10.110.158.162:2379"
KUBE_SERVICE_ADDRESSES="--service-cluster-ip-range=10.254.0.0/16"
KUBE_ADMISSION_CONTROL="--admission-control=ServiceAccount,NamespaceLifecycle,NamespaceExists,LimitRanger,ResourceQuota"
KUBE_API_ARGS="--authorization-mode=RBAC --runtime-config=rbac.authorization.k8s.io/v1beta1 --kubelet-https=true --token-auth-file=/etc/kubernetes/token.csv --service-node-port-range=30000-32767 --tls-cert-file=/etc/kubernetes/ssl/kubernetes.pem --tls-private-key-file=/etc/kubernetes/ssl/kubernetes-key.pem --client-ca-file=/etc/kubernetes/ssl/ca.pem --service-account-key-file=/etc/kubernetes/ssl/ca-key.pem --etcd-cafile=/etc/kubernetes/ssl/ca.pem --etcd-certfile=/etc/kubernetes/ssl/kubernetes.pem --etcd-keyfile=/etc/kubernetes/ssl/kubernetes-key.pem --enable-swagger-ui=true --apiserver-count=3 --audit-log-maxage=30 --audit-log-maxbackup=3 --audit-log-maxsize=100 --audit-log-path=/var/lib/audit.log --event-ttl=1h --requestheader-client-ca-file=/etc/kubernetes/ssl/ca.pem --requestheader-allowed-names=aggregator,metrics-server --requestheader-extra-headers-prefix=X-Remote-Extra- --requestheader-group-headers=X-Remote-Group --requestheader-username-headers=X-Remote-User --proxy-client-cert-file=/etc/kubernetes/ssl/metrics-server.pem --proxy-client-key-file=/etc/kubernetes/ssl/metrics-server-key.pem --kubelet-client-certificate=/etc/kubernetes/ssl/admin.pem --kubelet-client-key=/etc/kubernetes/ssl/admin-key.pem"
```

 systemctl daemon-reload
 
/usr/lib/systemd/system/kube-controller-manager.service

```
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

vim /etc/kubernetes/controller-manager

```
KUBE_CONTROLLER_MANAGER_ARGS="--address=127.0.0.1 --service-cluster-ip-range=10.254.0.0/16 --cluster-name=kubernetes --cluster-signing-cert-file=/etc/kubernetes/ssl/ca.pem --cluster-signing-key-file=/etc/kubernetes/ssl/ca-key.pem  --service-account-private-key-file=/etc/kubernetes/ssl/ca-key.pem --root-ca-file=/etc/kubernetes/ssl/ca.pem --leader-elect=true"
```

vim /etc/systemd/system/kube-scheduler.service

```
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

vim /etc/kubernetes/scheduler

```
KUBE_SCHEDULER_ARGS="--leader-elect=true --address=127.0.0.1"
```

Config Node

```
$ kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server="https://<master_ip>:6443" \
  --kubeconfig=bootstrap.kubeconfig

$ kubectl config set-credentials kubelet-bootstrap \
     --token=81f7y4ba8b7ca874fcff68bf5ct41a7c (your gen it above) \
     --kubeconfig=bootstrap.kubeconfig

$ kubectl config set-context default \
     --cluster=kubernetes \
     --user=kubelet-bootstrap \
     --kubeconfig=bootstrap.kubeconfig

$ kubectl config use-context default --kubeconfig=bootstrap.kubeconfig
```

vim /etc/systemd/system/kubelet.service

```
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
               $KUBELET_PORT \
               $KUBELET_HOSTNAME \
               $KUBE_ALLOW_PRIV \
               $KUBELET_POD_INFRA_CONTAINER \
               $KUBELET_ARGS
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

mkdir -p /var/lib/kubelet

vim /etc/kubernetes/kubelet

```
KUBELET_HOSTNAME="--hostname-override=10.110.158.165"
KUBELET_POD_INFRA_CONTAINER="--pod-infra-container-image=registry.access.redhat.com/rhel7/pod-infrastructure:latest"
KUBELET_ARGS="--config=/etc/kubernetes/manifests/kubelet.yml --kubeconfig=/etc/kubernetes/bootstrap.kubeconfig --cert-dir=/etc/kubernetes/ssl"
```
NOTE : ```KUBELET_HOSTNAME="--hostname-override=10.110.158.162" to 162```

Config kube-proxy

```
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/ssl/ca.pem \
  --embed-certs=true \
  --server="https://10.110.158.162:6443" \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy \
  --client-certificate=/etc/kubernetes/ssl/kube-proxy.pem \
  --client-key=/etc/kubernetes/ssl/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
```

vim /etc/kubernetes/kube-proxy

```
KUBE_PROXY_ARGS="--bind-address=<hostip> --kubeconfig=/etc/kubernetes/kube-proxy.kubeconfig --cluster-cidr=10.254.0.0/16"
```

vim /usr/lib/systemd/system/kube-proxy.service

```
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

systemctl daemon-reload

Deploy metrics-server

git clone https://github.com/kubernetes-incubator/metrics-server.git

```
cd metrics-server
git tag
v0.1.0
v0.2.0
v0.2.1
v0.3.0
v0.3.0-alpha.1
v0.3.1
```

Checkout last tag
```
git checkout v0.3.1
```

Modify metrics-server-deployment.yaml

```
spec:
    .......
      containers:
      - name: metrics-server
        command: ["/metrics-server"]
        args: ["--requestheader-client-ca-file=/etc/kubernetes/ssl/ca.pem","--client-ca-file=/etc/kubernetes/ssl/ca.pem","--tls-cert-file=/etc/kubernetes/ssl/metrics-server.pem","--tls-private-key-file=/etc/kubernetes/ssl/metrics-server-key.pem","--kubelet-insecure-tls"]
        #args: ["--requestheader-client-ca-file=/etc/kubernetes/ssl/ca.pem","--kubelet-insecure-tls"]
        # For the sake of GFW
        image: mirrorgooglecontainers/metrics-server-amd64:v0.3.1
        imagePullPolicy: Always
     ........
```

```
kubectl create -f ./deploy/1.8+/
```

```
kubectl get pods -n=kube-system
```


```
NAME                              READY   STATUS    RESTARTS   AGE
metrics-server-6cbd98fc8d-cvtcs   1/1     Running   0          31m
```

```
kubectl top nodes
```

```
NAME             CPU(cores)   CPU%   MEMORY(bytes)   MEMORY%
10.110.158.162   235m         0%     10081Mi         7%
10.110.158.165   64m          0%     962Mi           0%
```

Dashborad
cat ~/git/kubernetes/cluster/addons/dashboard/*.yaml

```
apiVersion: v1
kind: ConfigMap
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    # Allows editing resource and makes sure it is created first.
    addonmanager.kubernetes.io/mode: EnsureExists
  name: kubernetes-dashboard-settings
  namespace: kube-system
apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: Reconcile
  name: kubernetes-dashboard
  namespace: kube-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubernetes-dashboard
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  selector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: kubernetes-dashboard
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
        seccomp.security.alpha.kubernetes.io/pod: 'docker/default'
    spec:
      priorityClassName: system-cluster-critical
      containers:
      - name: kubernetes-dashboard
        image: mirrorgooglecontainers/kubernetes-dashboard-amd64:v1.10.1
        resources:
          limits:
            cpu: 100m
            memory: 300Mi
          requests:
            cpu: 50m
            memory: 100Mi
        ports:
        - containerPort: 8443
          protocol: TCP
        args:
          # PLATFORM-SPECIFIC ARGS HERE
          - --auto-generate-certificates
        volumeMounts:
        - name: kubernetes-dashboard-certs
          mountPath: /certs
        - name: tmp-volume
          mountPath: /tmp
        livenessProbe:
          httpGet:
            scheme: HTTPS
            path: /
            port: 8443
          initialDelaySeconds: 30
          timeoutSeconds: 30
      volumes:
      - name: kubernetes-dashboard-certs
        secret:
          secretName: kubernetes-dashboard-certs
      - name: tmp-volume
        emptyDir: {}
      serviceAccountName: kubernetes-dashboard
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
kind: Role
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: Reconcile
  name: kubernetes-dashboard-minimal
  namespace: kube-system
rules:
  # Allow Dashboard to get, update and delete Dashboard exclusive secrets.
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["kubernetes-dashboard-key-holder", "kubernetes-dashboard-certs"]
  verbs: ["get", "update", "delete"]
  # Allow Dashboard to get and update 'kubernetes-dashboard-settings' config map.
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["kubernetes-dashboard-settings"]
  verbs: ["get", "update"]
  # Allow Dashboard to get metrics from heapster.
- apiGroups: [""]
  resources: ["services"]
  resourceNames: ["heapster"]
  verbs: ["proxy"]
- apiGroups: [""]
  resources: ["services/proxy"]
  resourceNames: ["heapster", "http:heapster:", "https:heapster:"]
  verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kubernetes-dashboard-minimal
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: Reconcile
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: kubernetes-dashboard-minimal
subjects:
- kind: ServiceAccount
  name: kubernetes-dashboard
  namespace: kube-system
apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    # Allows editing resource and makes sure it is created first.
    addonmanager.kubernetes.io/mode: EnsureExists
  name: kubernetes-dashboard-certs
  namespace: kube-system
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    # Allows editing resource and makes sure it is created first.
    addonmanager.kubernetes.io/mode: EnsureExists
  name: kubernetes-dashboard-key-holder
  namespace: kube-system
type: Opaque
apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  #type: NodePort
  selector:
    k8s-app: kubernetes-dashboard
  ports:
  - port: 8443
```


Ingress

kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/provider/baremetal/service-nodeport.yaml

vim mandatory.yaml

```
apiVersion: v1
kind: Namespace
metadata:
  name: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---

kind: ConfigMap
apiVersion: v1
metadata:
  name: nginx-configuration
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
kind: ConfigMap
apiVersion: v1
metadata:
  name: tcp-services
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
kind: ConfigMap
apiVersion: v1
metadata:
  name: udp-services
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: nginx-ingress-serviceaccount
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: nginx-ingress-clusterrole
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
rules:
  - apiGroups:
      - ""
    resources:
      - configmaps
      - endpoints
      - nodes
      - pods
      - secrets
    verbs:
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - nodes
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - services
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - "extensions"
    resources:
      - ingresses
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - ""
    resources:
      - events
    verbs:
      - create
      - patch
  - apiGroups:
      - "extensions"
    resources:
      - ingresses/status
    verbs:
      - update

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: Role
metadata:
  name: nginx-ingress-role
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
rules:
  - apiGroups:
      - ""
    resources:
      - configmaps
      - pods
      - secrets
      - namespaces
    verbs:
      - get
  - apiGroups:
      - ""
    resources:
      - configmaps
    resourceNames:
      # Defaults to "<election-id>-<ingress-class>"
      # Here: "<ingress-controller-leader>-<nginx>"
      # This has to be adapted if you change either parameter
      # when launching the nginx-ingress-controller.
      - "ingress-controller-leader-nginx"
    verbs:
      - get
      - update
  - apiGroups:
      - ""
    resources:
      - configmaps
    verbs:
      - create
  - apiGroups:
      - ""
    resources:
      - endpoints
    verbs:
      - get

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: RoleBinding
metadata:
  name: nginx-ingress-role-nisa-binding
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: nginx-ingress-role
subjects:
  - kind: ServiceAccount
    name: nginx-ingress-serviceaccount
    namespace: ingress-nginx

---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: nginx-ingress-clusterrole-nisa-binding
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: nginx-ingress-clusterrole
subjects:
  - kind: ServiceAccount
    name: nginx-ingress-serviceaccount
    namespace: ingress-nginx

---

apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-ingress-controller
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ingress-nginx
      app.kubernetes.io/part-of: ingress-nginx
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ingress-nginx
        app.kubernetes.io/part-of: ingress-nginx
      annotations:
        prometheus.io/port: "10254"
        prometheus.io/scrape: "true"
    spec:
      serviceAccountName: nginx-ingress-serviceaccount
      #hostNetwork: true
      nodeSelector:
        kubernetes.io/hostname: 10.110.158.162
      containers:
        - name: nginx-ingress-controller
          #image: quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.21.0
          image: rancher/nginx-ingress-controller:0.21.0-rancher1
          args:
            - /nginx-ingress-controller
            - --configmap=$(POD_NAMESPACE)/nginx-configuration
            - --tcp-services-configmap=$(POD_NAMESPACE)/tcp-services
            - --udp-services-configmap=$(POD_NAMESPACE)/udp-services
            - --publish-service=$(POD_NAMESPACE)/ingress-nginx-nodeport
            - --annotations-prefix=nginx.ingress.kubernetes.io
            - --ingress-class=nginx
           # - --enable-ssl-passthrough
          securityContext:
            allowPrivilegeEscalation: true
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE
            # www-data -> 33
            runAsUser: 33
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          ports:
            - name: http
              containerPort: 80
            - name: https
              containerPort: 443
          livenessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 10254
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
          readinessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 10254
              scheme: HTTP
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1

---

apiVersion: v1
kind: Service
metadata:
  name: ingress-nginx-nodeport
  namespace: ingress-nginx
spec:
  type: NodePort
  ports:
  - name: http
    port: 80
    targetPort: 80
    #nodePort: 30090
    protocol: TCP
  - name: https
    port: 443
    targetPort: 443
    #nodePort: 30070
    protocol: TCP
  selector:
    #app: ingress-nginx-ic1
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
```
vim rule.yaml

```
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: dashboard-ingress
  namespace: kube-system
  annotations:
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
    nginx.ingress.kubernetes.io/secure-backends: "true"
spec:
  rules:
    - http:
        paths:
        - backend:
            serviceName: kubernetes-dashboard
            servicePort: 8443
```

Nvidia-device-plugin

```
apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: kube-system
spec:
  template:
    metadata:
      # Mark this pod as a critical add-on; when enabled, the critical add-on scheduler
      # reserves resources for critical add-on pods so that they can be rescheduled after
      # a failure.  This annotation works in tandem with the toleration below.
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ""
      labels:
        name: nvidia-device-plugin-ds
    spec:
      tolerations:
      # Allow this pod to be rescheduled while the node is in "critical add-ons only" mode.
      # This, along with the annotation above marks this pod as a critical add-on.
      - key: CriticalAddonsOnly
        operator: Exists
      - key: nvidia.com/gpu
        operator: Exists
        effect: NoSchedule
      containers:
      - image: nvidia/k8s-device-plugin:1.11
        name: nvidia-device-plugin-ctr
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
          - name: device-plugin
            mountPath: /var/lib/kubelet/device-plugins
      volumes:
        - name: device-plugin
          hostPath:
            path: /var/lib/kubelet/device-plugins
```

Minikube for aliyun

```
https://yq.aliyun.com/articles/221687?spm=a2c4e.11153940.blogcont508460.18.3ede63a3nSaMxE
```
