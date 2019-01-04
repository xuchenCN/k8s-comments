
# Prepare Nodes


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
    "C": "<country>",
    "ST": "<state>",
    "L": "<city>",
    "O": "<organization>",
    "OU": "<organization unit>"
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
    "<MASTER_IP>",
    "<NODE1_IP>",
    "<NODE2_IP>",
    "<MASTER_CLUSTER_IP>(10.254.0.1)",
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
    "O": "k8s",
    "OU": "<organization unit>"
  }]
}
```
vim admin-csr.json

```
{
  "CN": "admin",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names":[{
    "C": "<country>",
    "ST": "<state>",
    "L": "<city>",
    "O": "system:master",
    "OU": "<organization unit>"
  }]
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
"names": [ {
         "C": "CN",
         "ST": "HangZhoue",
         "L": "HangZhoue",
         "O": "k8s",
         "OU": "System"
} ]
}
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


