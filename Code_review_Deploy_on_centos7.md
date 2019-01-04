
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

Install Etcd

```
sudo yum install -y etcd
```

