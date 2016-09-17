#!/bin/bash
#
# DC/OS bootstrap node installer script for CentOS 7
# Author: Fernando Sanchez (fernando at mesosphere.com)
#
# Usage:
# sudo su, then "bash dcos_installer_centos7.sh"
#
#*********** INSTALLATION VARIABLES ****************
# Modify this section as per your own installation #
#***************************************************

USERNAME=bootstrapuser
PASSWORD=deleteme
DOWNLOAD_URL="https://downloads.dcos.io/dcos/EarlyAccess/dcos_generate_config.sh"
SECURITY_LEVEL="permissive" #strict|permissive|disabled
CLUSTERNAME=$(hostname)"-"$(date +"%m-%d-%y")       #DEFAULT: hostname plus date
BOOTSTRAP_IP=$(ip addr show eth0 | grep -Eo \
 '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1) #DEFAULT: this node's eth0
BOOTSTRAP_PORT=81                                  #DEFAULT. Can be any free/open port
WORKING_DIR=$HOME"/DCOS_install"

#****************************************************************
# These are for internal use and should not need modification
#****************************************************************
SERVICE_NAME=dcos-bootstrap
INSTALLER_FILE=$(basename $DOWNLOAD_URL)
BOOTSTRAP_FILE=$SERVICE_NAME.sh
PASSWORD_HASH_FILE=$WORKING_DIR/.pshash
NODE_INSTALLER=node_installer.sh
COMMAND_FILE=node_command.sh
TEST_FILE=$WORKING_DIR/genconf/serve/dcos_install.sh
MASTER_IP_FILE=$WORKING_DIR/.masterip
UNPACKED_INSTALLER_FILE=$WORKING_DIR/"dcos-genconf.*.tar"

# Pre-checks
#################################################################
# make sure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "** Please run as root. Exiting."
  exit
fi

#make sure we're running on CentOS 7
if [ $(grep "ID=" /etc/os-release | head -n1) != "ID=\"centos\"" ] || \
   [ $(grep "ID=" /etc/os-release | tail -n1) != "VERSION_ID=\"7\"" ] ; then
  echo "** This installer supports CentOS 7 only. Aborting"
  exit
else
  echo "** Operating system version check passed."
fi

#make sure there's an internet connection
if ping -q -c 1 -W 1 google.com >/dev/null; then
  echo "** Internet connectivity is working."
else
  echo "** Internet connectivity is not working. Aborting."
  exit
fi

#Get to $WORKING_DIR
mkdir -p $WORKING_DIR
cd $WORKING_DIR


#Parameter parsing, edit and confirmation
#################################################################
echo ""
echo "********* USAGE: [ sudo su ], THEN [ bash dcos_install_centos7.sh ] **********"
echo "                ([ sudo bash dcos_install_centos7.sh ] WILL FAIL. )"
echo ""
echo "******************************************************************************"
echo "***************************** Welcome to DC/OS *******************************"
echo "******************************************************************************"
echo ""

#ask for Master IP if not present
if [ ! -f $MASTER_IP_FILE ]; then
  read -p "** Please enter MASTER(s) private IP address(es) (comma separated, no spaces): " MASTER_IP
  echo $MASTER_IP > $MASTER_IP_FILE
else
  MASTER_IP=`cat $MASTER_IP_FILE`
fi

echo ""
echo "** Will now install a DC/OS bootstrap node with the following parameters:"
echo ""
echo "**************************          ****************"
echo "Master node private IP(s):          "$MASTER_IP
echo "**************************          ****************"
echo "DC/OS username:                     "$USERNAME
echo "Password:                           "$PASSWORD
echo "Generated Cluster Name:             "$CLUSTERNAME
echo "Detected IP for bootstrap server:   "$BOOTSTRAP_IP
echo "TCP port for bootstrap server:      "$BOOTSTRAP_PORT
echo "Installation directory:             "$WORKING_DIR
echo ""
echo "******************************************************************************"

while true; do
  read -p "** Are these parameters correct?: (y/n): " REPLY
  case $REPLY in
    [yY]) echo ""
          echo "** COPY THE COMMAND BELOW AND RUN IN CLUSTER NODES TO INSTALL (AFTER THIS INSTALLER HAS COMPLETED):"
          echo ""
          echo "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER"
          echo "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER" \
           > $WORKING_DIR/$COMMAND_FILE  #for future use (node additions)
          echo ""
          echo "** Command saved in $WORKING_DIR/$COMMAND_FILE for future use."
          read -p "** Press ENTER to proceed with installation..."
          break
          ;;
    [nN]) echo "** Aborting. Please edit the required values in the installer file then run this script again"
          #FIXME: add section to ask which parameter to change and read it from input
          exit 1
          ;;
    *) echo "** Invalid input. Please choose [y] or [n]"
       ;;
  esac
done

echo "** Installing to $WORKING_DIR. Please wait..."
cd $WORKING_DIR

#Requirements
#################################################################
#Update/upgrade
sudo yum update --exclude=docker-engine,docker-engine-selinux --assumeyes --tolerant
systemctl stop firewalld &&  systemctl disable firewalld

#docker with overlayfs
echo "** Configuring docker..."

echo 'overlay'\
>> /etc/modules-load.d/overlay.conf

#Add docker repo
sudo cat > /etc/yum.repos.d/docker.repo << 'EOF'
[dockerrepo]
name=Docker Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/$releasever/
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF

#Install docker engine, daemon and service
sudo yum install -y docker-engine-1.11.2-1.el7.centos docker-engine-selinux-1.11.2-1.el7.centos wget curl zip unzip ipset

#Add Overlay storage driver and restart docker
sudo modprobe overlay && \
sudo systemctl stop docker && \
sudo systemctl daemon-reload && \
sudo systemctl start docker && \
sudo systemctl enable docker

#Add docker override to start with Overlay driver
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/docker daemon --storage-driver=overlay -H fd://
EOF

#Create config directory
sudo mkdir -p $WORKING_DIR/genconf && sudo chmod 777 $WORKING_DIR/genconf

#IP-detect script
#################################################################
#Detect if I am running on amazon. Use corresponding ip-detect script
if [ -f /sys/hypervisor/uuid ] && [ `head -c 3 /sys/hypervisor/uuid` == ec2 ];
then
echo "** This is an EC2 instance. Using metadata to detect my IP."
        #ip-detect script - AWS version
        sudo cat > $WORKING_DIR/genconf/ip-detect << 'EOF'
#!/bin/sh
curl -fsSL http://169.254.169.254/latest/meta-data/local-ipv4
EOF
else
        echo "** This is not an EC2 instance. Using my [eth0] interface as my IP."
        #ip-detect script -- INTERFACE VERSION for BAREMETAL
        sudo cat > $WORKING_DIR/genconf/ip-detect << 'EOF'
#!/usr/bin/env bash
set -o nounset -o errexit
PATH=/usr/sbin:/usr/bin:$PATH
echo $(ip addr show eth0 | grep -Eo '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
EOF
fi

#Installer
#################################################################
#check whether the "dcos_generate_config.sh" script exists, download otherwise
if [[ ! -f $WORKING_DIR/$INSTALLER_FILE ]] ; then
  echo "** Downloading DC/OS..."
  wget -O $WORKING_DIR/$INSTALLER_FILE $DOWNLOAD_URL
else
  echo "** DC/OS image already present."
fi

#run the installer to generate password hash. Store it hidden and protected
if [ ! -f $PASSWORD_HASH_FILE ]; then
  echo "** Unpacking image and generating password hash..."
  sudo bash $WORKING_DIR/$INSTALLER_FILE --hash-password $PASSWORD | \
  tail -n1 > $PASSWORD_HASH_FILE
  chmod 0400 $PASSWORD_HASH_FILE
else
  echo "** DC/OS image unpacked and hashed."
fi
PASSWORD_HASH=`cat $PASSWORD_HASH_FILE`


#Generate configuration files
#################################################################
echo "** Generating configuration file..."

#parse MASTER IP to get each one
MASTER_1=$(echo $MASTER_IP | awk -F, '{print $1}')
MASTER_2=$(echo $MASTER_IP | awk -F, '{print $2}')
MASTER_3=$(echo $MASTER_IP | awk -F, '{print $3}')

#generate config.yaml
cat > $WORKING_DIR/genconf/config.yaml << EOF
bootstrap_url: http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT
cluster_name: $CLUSTERNAME
exhibitor_storage_backend: static
master_discovery: static
telemetry_enabled: false
security: $SECURITY_LEVEL
master_list:
$([[ $MASTER_1 != "" ]] && echo "- $MASTER_1")  \
$([[ $MASTER_2 != "" ]] && echo "
- $MASTER_2") \
$([[ $MASTER_3 != "" ]] && echo "
- $MASTER_3")
resolvers:
- 8.8.4.4
- 8.8.8.8
dcos_overlay_network:
  vtep_subnet: 192.15.0.0/20
  vtep_mac_oui: 70:B3:D5:00:00:00
  overlays:
   - name: dcos-0
     subnet: 192.168.0.0/19
     prefix: 24
   - name: dcos-1
     subnet: 192.168.32.0/19
     prefix: 24
   - name: dcos-2
     subnet: 192.168.64.0/19
     prefix: 24
   - name: dcos-3
     subnet: 192.168.96.0/19
     prefix: 24
   - name: dcos-4
     subnet: 192.168.128.0/19
     prefix: 24
   - name: dcos-5
     subnet: 192.168.160.0/19
     prefix: 24
   - name: dcos-6
     subnet: 192.168.192.0/19
     prefix: 24
   - name: dcos-7
     subnet: 192.168.224.0/19
     prefix: 24
   - name: dcos-8
     subnet: 10.0.0.0/18
     prefix: 24
   - name: dcos-9
     subnet: 10.0.64.0/18
     prefix: 24
superuser_password_hash: $PASSWORD_HASH
superuser_username: $USERNAME
EOF


#Create one-time installer and docker launcher for next reboot
#################################################################
echo "** Generating launcher..."

cat > $WORKING_DIR/$BOOTSTRAP_FILE << EOF
#!/bin/bash
#This script installs and boots DC/OS bootstrap installer.
#Interprets that DC/OS is installed if $TEST_FILE exists.
if [ ! -f $TEST_FILE ]; then
    echo "***************************************"
    echo "*** Setting up DC/OS bootstrap node ***"
    echo "***.................................***"
    cd $WORKING_DIR
    /bin/bash $WORKING_DIR/$INSTALLER_FILE
    if [ -f $TEST_FILE ]; then
      echo "***************************************"
      echo "* SUCCESS. DC/OS bootstrap node READY *"
      echo "***************************************"
    else
      echo "*******************************************"
      echo "***** DC/OS bootstrap install FAILED. *****"
      echo "***** Please run the installer again. *****"
      echo "*******************************************"
    fi
fi
EOF
#Make file executable
chmod 0755 $WORKING_DIR/$BOOTSTRAP_FILE

#Add services to startup
#################################################################
echo "** Adding services to startup..."

#Create systemd unit file for installer to start at reboot
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=$SERVICE_NAME server
Requires=docker.service
After=docker.service

[Service]
Type=forking
WorkingDirectory=$WORKING_DIR
TimeoutStartSec=0
ExecStart=/bin/bash $WORKING_DIR/$BOOTSTRAP_FILE
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
#Enable service so that it's run upon reboot
chmod 0755 /etc/systemd/system/$SERVICE_NAME.service
systemctl enable $SERVICE_NAME.service

#Bootstrap services inside docker containers equired for installer and serving nodes.
#TODO DELETE: Run local zookeeper instance for temporary storage of installer -- TO BE REMOVED
#/usr/bin/docker run -d -p 2181:2181 -p 2888:2888 -p 3888:3888 -v /var/zookeeper/dcos:/tmp/zookeeper --name=dcos_int_zk jplock/zookeeper
#Add to systemd for automatic restart
#cat > /etc/systemd/system/$SERVICE_NAME-zk.service << EOF
#[Unit]
#Description=$SERVICE_NAME zookeeper container
#Requires=docker.service
#After=docker.service
#[Service]
#Type=forking
#Restart=always
#RestartSec=5
#ExecStart=/usr/bin/docker start -a dcos_int_zk
#ExecStop=/usr/bin/docker stop -t 2 dcos_int_zk
#[Install]
#WantedBy=multi-user.target
#EOF
#chmod 0755 /etc/systemd/system/$SERVICE_NAME-zk.service
#systemctl enable $SERVICE_NAME-zk.service

#Run local nginx server to offer installation files to nodes
/usr/bin/docker run -d -p $BOOTSTRAP_PORT:80 -v $WORKING_DIR/genconf/serve:/usr/share/nginx/html:ro \
        --name=dcos_int_nginx nginx
#Add to systemd for automatic restart
cat > /etc/systemd/system/$SERVICE_NAME-nginx.service << EOF
[Unit]
Description=$SERVICE_NAME nginx container
Requires=docker.service
After=docker.service
[Service]
Type=forking
Restart=always
RestartSec=5
ExecStart=/usr/bin/docker start -a dcos_int_nginx
ExecStop=/usr/bin/docker stop -t 2 dcos_int_nginx
[Install]
WantedBy=multi-user.target
EOF
chmod 0755 /etc/systemd/system/$SERVICE_NAME-nginx.service
systemctl enable $SERVICE_NAME-nginx.service

systemctl daemon-reload

#Generate agent launcher so that agents just have to:
#sudo bash <(curl -s $BOOTSTRAP_IP:$BOOTSTRAP_PORT)
#################################################################
echo "** Generating agent launcher..."

mkdir -p $WORKING_DIR/genconf/serve/
# $$ start node installer
# $$ 'EOF2' with ticks - "leave variable names as they are here"
sudo cat > $WORKING_DIR/genconf/serve/$NODE_INSTALLER << 'EOF2'
#!/bin/bash
#
# DC/OS Installer script for cluster nodes
# Author: Fernando Sanchez (fernando at mesosphere.com)
#

ROLE_FILE="/root/.mesos_role"

#Make sure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "** Please run as root. Exiting."
  exit
fi

echo "** Please run as ROOT -- after "sudo su" ****"
echo ""
echo "** Installing DC/OS..."
echo "** Setting up installation directory.."
mkdir -p /tmp/dcos
cd /tmp/dcos

#Make sure there's an internet connection
if ping -q -c 1 -W 1 google.com >/dev/null; then
  echo "** Internet connectivity is working."
else
  echo "** Internet connectivity is not working. Aborting."
  exit 0
fi

#Update system
echo "** Updating system..."
sudo yum update --exclude=docker-engine,docker-engine-selinux --assumeyes --tolerant
EOF2
# $$ end "leave variables"
# $$ without ticks - "translate variables on generation"
sudo cat >>  $WORKING_DIR/genconf/serve/$NODE_INSTALLER << EOF2

echo "** Downloading installer from $BOOTSTRAP_IP..."
curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/dcos_install.sh

#Requirements
sudo groupadd nogroup &&

echo "** Disabling IPv6..."
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 &&
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 &&

echo "** Disabling SELinux..."
sed -i s/SELINUX=enforcing/SELINUX=permissive/g /etc/selinux/config
setenforce 0

echo "** Installing dependencies..."

#Docker with overlayfs
echo 'overlay'\
>> /etc/modules-load.d/overlay.conf

EOF2
# $$ end "translate variables"
# $$ start "leave variables"
sudo cat >> $WORKING_DIR/genconf/serve/$NODE_INSTALLER << 'EOF2'

#Add docker repo
sudo tee /etc/yum.repos.d/docker.repo <<-'EOF'
[dockerrepo]
name=Docker Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/$releasever/
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF

#Install docker engine, daemon and service, along with dependencies
sudo yum install -y docker-engine-1.11.2-1.el7.centos docker-engine-selinux-1.11.2-1.el7.centos wget tar xz curl zip unzip ipset && 

#Add overlay module to running system and start docker
sudo modprobe overlay
sudo systemctl stop docker
sudo systemctl daemon-reload
sudo systemctl start docker

#Add docker override so that it starts with Overlay driver
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/docker daemon --storage-driver=overlay -H fd://
EOF

#Reboot if storage driver is not overlay
if [[ $(docker info | grep "Storage Driver:" | cut -d " " -f 3) != "overlay" ]]; then
  echo "** Node needs to be rebooted for the updates to take place."
  echo "** PLEASE RUN THE NODE INSTALLER AGAIN UPON REBOOTING."
  read -p "** Press Enter to reboot..."
  reboot
fi

#check out if $ROLE has been defined in a previous run, ask otherwise
if [ ! -f $ROLE_FILE ]; then
  while [[ $ROLE != "master" ]] && \
        [[ $ROLE != "slave"  ]] && \
        [[ $ROLE != "slave_public" ]]
  do
    read -p "** Enter this node's role [master/slave/slave_public]: " ROLE
    echo $ROLE > $ROLE_FILE
  done
else
  ROLE=`cat $ROLE_FILE`
fi

echo "** Running installer as $ROLE..."
sudo bash /tmp/dcos/dcos_install.sh $ROLE
#catch result, print error if applicable. If the last entry of "dcos-setup" status is failed...

ERROR=$(systemctl status dcos-setup | tail -n1 | grep "Job dcos-setup.service/start failed")
if [[ $ERROR = *[!\ ]* ]]; then
  echo "** ERROR: "$ERROR
  echo "** Node installation FAILED. This is likely due to download or unpacking glitches. Please run the installer again"
  exit 0
else
  echo "** Node installed successfully."
  exit 1
fi
EOF2
# $$ end of node installer
#################################################################

#TODO DELETE: Avoid rebooting by adding the overlay module and restarting docker
###################################################################
#sudo modprobe overlay
#sudo systemctl stop docker
#sudo systemctl daemon-reload
#sudo systemctl start docker

#Reboot if required for docker storage driver change to overlay.
#################################################################
if [[ $(docker info | grep "Storage Driver:" | cut -d " " -f 3) != "overlay" ]]; then
  echo "** Node needs to be rebooted for the updates to take place."
  read -p "** Press Enter to reboot..."
  reboot
else
  #run the installer as we're ready for it
  sudo bash $WORKING_DIR/$BOOTSTRAP_FILE
fi

#Add dcos CLI to bootstrap node.
################################


#Check that installation finished successfully.
#################################################################
if [ -f $TEST_FILE ]; then
  echo "** SUCCESS. Bootstrap node installed."
  exit 1
else
  echo "** Bootstrap node installation FAILED."
  echo "** Deleting temporary files..."
  #remove password hash so that it's calculated again
  rm $PASSWORD_HASH_FILE
  #remove calculated unpacked tar file (assuming decompression/hashing failed)
  rm $UNPACKED_INSTALLER_FILE
  #FIXME: possibly also removed downloaded installer (assuming download failed)
  echo "** Temporary files deleted. Please run the installer again."
  exit 0
fi
