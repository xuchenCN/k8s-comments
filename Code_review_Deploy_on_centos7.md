
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
    "O": "<organization>",
    "OU": "<organization unit>"
  }]
}
```
