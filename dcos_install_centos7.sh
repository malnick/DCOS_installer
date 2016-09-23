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
CLI_DOWNLOAD_URL="https://downloads.dcos.io/binaries/cli/linux/x86-64/dcos-1.8/dcos"
SECURITY_LEVEL="permissive" #strict|permissive|disabled
CLUSTERNAME="DC/OS @ "$(hostname)
BOOTSTRAP_IP=$(ip addr show eth0 | grep -Eo \
 '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1) #this node's eth0
BOOTSTRAP_PORT=81                                          #any free/open port
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
NGINX_NAME=dcos_int_nginx
#pretty colours
RED='\033[0;31m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

# Pre-checks
#################################################################
#make sure we're running as root
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

#get to $WORKING_DIR
mkdir -p $WORKING_DIR
cd $WORKING_DIR


#Parameter parsing, edit and confirmation
#################################################################
echo ""
echo "******************************************************************************"
echo -e "***************************** ${BLUE}Welcome to DC/OS${NC} *******************************"
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
          echo "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER" \
           > $WORKING_DIR/$COMMAND_FILE  #for future use (node additions)
          echo ""
          echo "** Agent installation command saved in $WORKING_DIR/$COMMAND_FILE for future use."
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
#update/upgrade
sudo yum update --exclude=docker-engine,docker-engine-selinux --assumeyes --tolerant
systemctl stop firewalld &&  systemctl disable firewalld

#DOCKER REQUIREMENTS
#add docker repo
sudo cat > /etc/yum.repos.d/docker.repo << 'EOF'
[dockerrepo]
name=Docker Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/$releasever/
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF

#docker engine with selinux and other requirements
sudo yum install -y docker-engine-1.11.2-1.el7.centos docker-engine-selinux-1.11.2-1.el7.centos wget curl zip unzip ipset

#add overlay storage driver to kernel modules
echo 'overlay'\
>> /etc/modules-load.d/overlay.conf

#docker override to boot with overlay storage driver
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/docker daemon --storage-driver=overlay -H fd://
EOF

#restart docker with overlay driver and new configuration
sudo systemctl stop docker &&\
sudo modprobe overlay && \
sudo systemctl daemon-reload && \
sudo systemctl start docker && \
sudo systemctl enable docker

#Ask for manual intervention if required for docker storage driver change to overlay.
#####################################################################################
if [[ $(docker info | grep "Storage Driver:" | cut -d " " -f 3) != "overlay" ]]; then
  echo "** ${RED}ERROR${NC}: Docker overlay driver couldn't be started automatically."
  echo -e "${BLUE}** Please copy and paste manually the command below and run this installer again."
  echo -e "${RED}systemctl stop docker && systemctl daemon-reload${NC}"
  read -p "** Press Enter to exit..."
  exit 1
else
  #run the installer as we're ready for it
  sudo bash $WORKING_DIR/$BOOTSTRAP_FILE
fi

#Create config directory
########################
sudo mkdir -p $WORKING_DIR/genconf && sudo chmod 777 $WORKING_DIR/genconf

#IP-detect script
#################################################################
#detect if I am running on amazon or local, use corresponding ip-detect script
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
  echo "** Unpacking image and generating password hash (this may take a few minutes) ..."
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

#Add services to startup
#################################################################
echo "** Adding services to startup..."

#create systemd unit file for installer to start at reboot
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
#enable service so that it's run upon reboot
chmod 0755 /etc/systemd/system/$SERVICE_NAME.service
systemctl enable $SERVICE_NAME.service

#run local nginx server to offer installation files to nodes
/usr/bin/docker run -d -p $BOOTSTRAP_PORT:80 -v $WORKING_DIR/genconf/serve:/usr/share/nginx/html:ro \
        --name=$NGINX_NAME nginx

#add to systemd to run at boot time
cat > /etc/systemd/system/$SERVICE_NAME-nginx.service << EOF
[Unit]
Description=$SERVICE_NAME nginx container
Requires=docker.service
After=docker.service
[Service]
Type=forking
Restart=always
RestartSec=5
ExecStart=/usr/bin/docker start -a $NGINX_NAME
ExecStop=/usr/bin/docker stop -t 2 $NGINX_NAME
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
#pretty colours
RED='\033[0;31m'
BLUE='\033[1;34m'
NC='\033[0m' # No Color

#Make sure we're running as root
if [ "$EUID" -ne 0 ]; then
  echo "** Please run as root. Exiting."
  exit
fi

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

#check out if $ROLE has been passed as argument, or defined in a
#previous run, ask otherwise
if [ $# > 1 ]
then
  ROLE="$1"
  if [[ $ROLE != "master" ]] && \
     [[ $ROLE != "slave"  ]] && \
     [[ $ROLE != "slave_public" ]]
  then
     #invalid role passed as an argument
     echo "** Invalid node ROLE detected as argument."
     #delete $ROLE_FILE so that the next loop asks for it
     rm -f $ROLE_FILE
  else
     echo $ROLE > $ROLE_FILE
  fi
fi

#Either a second-run or an invalid role as an argument
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
EOF2

#Update system
sudo cat >> $WORKING_DIR/genconf/serve/$NODE_INSTALLER << 'EOF2'
echo "** Updating system..."
sudo yum update --exclude=docker-engine,docker-engine-selinux --assumeyes --tolerant
EOF2

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

sudo cat >> $WORKING_DIR/genconf/serve/$NODE_INSTALLER << 'EOF2'
#add docker repo
sudo tee /etc/yum.repos.d/docker.repo <<-'EOF'
[dockerrepo]
name=Docker Repository
baseurl=https://yum.dockerproject.org/repo/main/centos/$releasever/
enabled=1
gpgcheck=1
gpgkey=https://yum.dockerproject.org/gpg
EOF

#install docker engine, daemon and service, along with dependencies
sudo yum install -y docker-engine-1.11.2-1.el7.centos docker-engine-selinux-1.11.2-1.el7.centos wget tar xz curl zip unzip ipset &&

#add overlay storage driver
echo 'overlay'\
>> /etc/modules-load.d/overlay.conf

#add docker override so that it starts with overlay storage driver
mkdir -p /etc/systemd/system/docker.service.d
cat > /etc/systemd/system/docker.service.d/override.conf << EOF
[Service]
ExecStart=
ExecStart=/usr/bin/docker daemon --storage-driver=overlay -H fd://
EOF

#restart docker with overlay storage driver
sudo systemctl stop docker && \
sudo modprobe overlay && \
sudo systemctl daemon-reload && \
sudo systemctl start docker && \
sudo systemctl enable docker

#Ask for manual intervention if required for docker storage driver change to overlay.
#####################################################################################
if [[ $(docker info | grep "Storage Driver:" | cut -d " " -f 3) != "overlay" ]]; then
  echo "** ${RED}ERROR${NC}: Docker overlay driver couldn't be started automatically."
  echo -e "${BLUE}** Please copy and paste manually the command below and run this installer again."
  echo -e "${RED}systemctl stop docker && systemctl daemon-reload${NC}"
  read -p "** Press Enter to exit..."
  exit 1
else
  #run the installer
  sudo bash $WORKING_DIR/$BOOTSTRAP_FILE
fi

echo "** Running installer as $ROLE..."
sudo bash /tmp/dcos/dcos_install.sh $ROLE
#catch result, print error if applicable. If the last entry of "dcos-setup" status is failed...

ERROR=$(systemctl status dcos-setup | tail -n1 | grep "Job dcos-setup.service/start failed")
if [[ $ERROR = *[!\ ]* ]]; then
  echo -e "** ${RED}ERROR${NC}: "$ERROR
  echo -e "** Node installation ${RED}FAILED${NC}. This is likely due to download or unpacking glitches. Please ${BLUE}run the installer again${NC}"
  exit 0
else
  echo "** Node installed successfully."
  exit 1
fi
EOF2
# $$ end of node installer
#################################################################

#Install DC/OS
#Interpret that DC/OS is installed if $TEST_FILE exists.
#################################################################
if [ ! -f $TEST_FILE ]; then
    echo "***************************************"
    echo "*** Setting up DC/OS bootstrap node ***"
    echo "***************************************"
    cd $WORKING_DIR
    /bin/bash $WORKING_DIR/$INSTALLER_FILE && \
    sleep 3 && \
    if [ -f $TEST_FILE ]; then
      echo "***************************************"
      echo -e "* ${BLUE}SUCCESS${NC}. DC/OS bootstrap node ${BLUE}READY${NC} *"
      echo "***************************************"
    else
      echo "*******************************************"
      echo -e "***** DC/OS bootstrap install ${RED}FAILED${NC}. *****"
      echo "***** Please run the installer again. *****"
      echo "*******************************************"
    fi
fi

#Add dcos CLI to bootstrap node.
################################
echo -e "** Installing ${BLUE}DC/OS${NC} CLI..."
curl -fLsS --retry 20 -Y 100000 -y 60 $CLI_DOWNLOAD_URL -o dcos &&
 sudo mv dcos /usr/bin &&
 sudo chmod +x /usr/bin/dcos &&
 dcos config set core.dcos_url https://$MASTER_1 &&
 dcos config set core.ssl_verify false &&
 dcos

#Check that installation finished successfully.
#################################################################
sleep 5
if [ -f $TEST_FILE ]; then
  echo -e "** ${BLUE}SUCCESS${NC}. Bootstrap node installed."
  echo -e "** ${BLUE}COPY AND PASTE THE FOLLOWING INTO EACH NODE OF THE CLUSTER TO INSTALL DC/OS:"
  echo -e ""
  echo -e "${RED}sudo su"
  echo -e "cd"
  echo -e "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER ${NC}"
  echo -e ""
  exit 1
else
  echo -e "** Bootstrap node installation ${RED}FAILED${NC}."
  echo "** Deleting temporary files..."
  #remove password hash so that it's calculated again
  rm $PASSWORD_HASH_FILE
  #remove calculated unpacked tar file (assuming decompression/hashing failed)
  rm $UNPACKED_INSTALLER_FILE
  #remove nginx container
  sudo docker rm -f $NGINX_NAME
  #TODO FIXME: possibly also removed downloaded installer (assuming download failed)
  echo -e "** Temporary files deleted. Please ${BLUE}run the installer again${NC}."
  exit 0
fi
