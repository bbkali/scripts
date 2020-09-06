#!/bin/bash
cat >/etc/apt/sources.list <<EOF
deb http://mirrors.163.com/debian/ stretch main non-free contrib
deb http://mirrors.163.com/debian/ stretch-updates main non-free contrib
deb http://mirrors.163.com/debian/ stretch-backports main non-free contrib
deb-src http://mirrors.163.com/debian/ stretch main non-free contrib
deb-src http://mirrors.163.com/debian/ stretch-updates main non-free contrib
deb-src http://mirrors.163.com/debian/ stretch-backports main non-free contrib
deb http://mirrors.163.com/debian-security/ stretch/updates main non-free contrib
deb-src http://mirrors.163.com/debian-security/ stretch/updates main non-free contrib
EOF
apt update
apt install -y  apt-transport-https ca-certificates curl gnupg2 software-properties-common
curl -fsSL https://mirrors.ustc.edu.cn/docker-ce/linux/debian/gpg | apt-key add -
echo "deb [arch=amd64] https://mirrors.ustc.edu.cn/docker-ce/linux/debian stretch stable" >>/etc/apt/sources.list
apt update
apt install -y docker-ce
systemctl start docker
systemctl enable docker