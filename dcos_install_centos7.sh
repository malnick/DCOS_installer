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
NTP_SERVER="pool.ntp.org"
REXRAY_CONFIG_FILE="rexray.yaml"  #relative to /genconf. Currently only Amazon EBS supported
TELEMETRY=true 

#****************************************************************
# These are for internal use and should not need modification
#****************************************************************
SERVICE_NAME=dcos-bootstrap
INSTALLER_FILE=$(basename $DOWNLOAD_URL)
PASSWORD_HASH_FILE=$WORKING_DIR/.pshash
NODE_INSTALLER=node_installer.sh
COMMAND_FILE=node_command.sh
TEST_FILE=$WORKING_DIR/genconf/serve/dcos_install.sh
MASTER_IP_FILE=$WORKING_DIR/.masterip
UNPACKED_INSTALLER_FILE=$WORKING_DIR/"dcos-genconf.*.tar"
NGINX_NAME=dcos_int_nginx
CERT_NAME=domain.crt
KEY_NAME=domain.key
#ELK stack for logging
ELK_CERT_NAME=logstash-forwarder.crt
ELK_KEY_NAME=logstash-forwarder.key
ELK_HOSTNAME=$BOOTSTRAP_IP
ELK_PORT=9200
LOGSTASH_HOSTNAME=$BOOTSTRAP_IP
LOGSTASH_PORT=5044

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

while true; do

echo ""
echo "** Will now install a DC/OS bootstrap node with the following parameters:"
echo ""
echo "*****************************          ****************"
echo "1) Master node private IP(s):          "$MASTER_IP
echo "*****************************          ****************"
echo "2) DC/OS username:                     "$USERNAME
echo "3) DC/OS Password:                     "$PASSWORD
echo "4) Generated Cluster Name:             "$CLUSTERNAME
echo "5) IP for this bootstrap server:       "$BOOTSTRAP_IP
echo "6) TCP port for bootstrap server:      "$BOOTSTRAP_PORT
echo "7) Installation directory:             "$WORKING_DIR
echo "8) NTP server:                         "$NTP_SERVER
echo ""
echo "******************************************************************************"

  read -p "** Are these parameters correct?: (y/n): " REPLY
  case $REPLY in
    [yY]) echo ""
          echo "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER" \
           > $WORKING_DIR/$COMMAND_FILE  #for future use (node additions)
          echo ""
          echo "** Agent installation command saved in $WORKING_DIR/$COMMAND_FILE for future use."
          break
          ;;
    [nN]) read -p "** Enter number of parameter to modify [1-8]: " PARAMETER
          case $PARAMETER in
            [1]) read -p "Enter new value for Master node private IP(s): " MASTER_IP
                 ;;
            [2]) read -p "Enter new value for DC/OS username: " USERNAME
                 ;;
            [3]) read -p "Enter new value for DC/OS password: " PASSWORD
                 ;;
            [4]) read -p "Enter new value for Generated Cluster Name: " CLUSTERNAME
                 ;;
            [5]) read -p "Enter new value for IP for this bootstrap server: " BOOTSTRAP_IP
                 ;;
            [6]) read -p "Enter new value for TCP port for this bootstrap server: " BOOTSTRAP_PORT
                 ;;
            [7]) read -p "Enter new value for Installation Directory: " WORKING_DIR
                 ;;
            [8]) read -p "Enter new value for NTP server: " NTP_SERVER
                 ;;                 
              *) echo "** Invalid input. Please choose an option [1-8]"
                 ;;
          esac
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
sudo yum install -y docker-engine-1.11.2-1.el7.centos docker-engine-selinux-1.11.2-1.el7.centos wget curl zip unzip ipset ntp 

#configure ntp
sudo echo "server $NTP_SERVER" > /etc/ntp.conf && \
sudo systemctl start ntpd && \
sudo systemctl enable ntpd

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

#Generate certificate for docker registry, ELK and others
#################################################################
echo "** Generating a certificate for this domain..."
mkdir -p /etc/pki/tls/
#add your ELK Server's private IP address to the subjectAltName (SAN) field of the SSL certificate that we are about to generate
sudo cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.BAK
#swap out [ v3_ca ] with [ v3_ca ]/nsubjectAltName = IP: $BOOTSTRAP_IP
sudo sed -i -e  's/\[ v3_ca \]/\[ v3_ca \]\\\nsubjectAltName = IP: $BOOTSTRAP_IP/g' /etc/pki/tls/openssl.cnf
openssl req -nodes -config /etc/pki/tls/openssl.cnf -batch -newkey rsa:2048 \
 -keyout $WORKING_DIR/genconf/serve/domain.key -out $WORKING_DIR/genconf/serve/domain.crt \
 -subj "/C=US/ST=NY/L=NYC/O=Mesosphere/OU=SE/CN=registry.marathon.l4lb.thisdcos.directory"
echo "** DEBUG: Certificate generated: "$(ls $WORKING_DIR/genconf/serve/domain*)

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

#generate Rex-ray configuration file for external persistent volumes with Amazon EBS
####################################################################################
echo "** Generating external persistent volumes configuration file for Amazon EBS..."

cat > $WORKING_DIR/genconf/$REXRAY_CONFIG_FILE << EOF
rexray:
  loglevel: info
  storageDrivers:
    - ec2
  volume:
    unmount:
      ignoreusedcount: true
EOF

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
telemetry_enabled: $TELEMETRY
security: $SECURITY_LEVEL
rexray_config_method: file
rexray_config_filename: $REXRAY_CONFIG_FILE
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
   - name: dcos
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
superuser_password_hash: $PASSWORD_HASH
superuser_username: $USERNAME
EOF

#Run local NGINX server and add it as service to startup
#################################################################
echo "** Running local $NGINX_NAME container to serve installation files..."
#remove container if it exists already
sudo docker rm -f $NGINX_NAME
/usr/bin/docker run -d -p $BOOTSTRAP_PORT:80 -v $WORKING_DIR/genconf/serve:/usr/share/nginx/html:ro \
        --name=$NGINX_NAME nginx
sleep 2        
if [ $(docker inspect -f {{.State.Running}} $NGINX_NAME) == "false" ]; then
  echo -e "** Running local $NGINX_NAME container ${RED}FAILED${NC}. Exiting."
  exit 1
fi

echo "** Adding $NGINX_NAME service to startup..."
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
# $$ EOF2 without ticks - "substitute variables on generation"
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

#stop conflicting services
echo "** Stop & disable dnsmasq using port 53 required by spartan ..."
systemctl stop dnsmasq
systemctl disable dnsmasq.service

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

#Update system
echo "** Updating system..."
sudo yum update --exclude=docker-engine,docker-engine-selinux --assumeyes --tolerant
EOF2

sudo cat >>  $WORKING_DIR/genconf/serve/$NODE_INSTALLER << EOF2

echo "** Downloading installer from $BOOTSTRAP_IP..."
curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/dcos_install.sh

#Requirements
sudo groupadd nogroup &&

echo "** Enabling non-TTY sudo"
sudo sed -i -e 's/Defaults    requiretty/#Defaults    requiretty/g' /etc/sudoers

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
sudo yum install -y docker-engine-1.11.2-1.el7.centos docker-engine-selinux-1.11.2-1.el7.centos \
 wget tar xz curl zip unzip ipset ntp 
EOF2

sudo cat >>  $WORKING_DIR/genconf/serve/$NODE_INSTALLER << EOF2
#configure ntp
sudo echo "server $NTP_SERVER" > /etc/ntp.conf && \
sudo systemctl start ntpd && \
sudo systemctl enable ntpd
EOF2

sudo cat >>  $WORKING_DIR/genconf/serve/$NODE_INSTALLER << 'EOF2'
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

#MASTERS and AGENTS : install Filebeat (logstash-forwarder) to send logs to ELK on bootstrap
sudo cat >>  $WORKING_DIR/genconf/serve/$NODE_INSTALLER << EOF2

#copy SSL certificate from bootstrap
sudo mkdir -p /etc/pki/tls/certs
curl -o /etc/pki/tls/certs/$ELK_CERT_NAME http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$CERT_NAME 

#install filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-5.0.0-x86_64.rpm
sudo rpm -vi filebeat-5.0.0-x86_64.rpm

#configure filebeat
#TODO: configure filebeat differently on masters and agents
sudo mv /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.BAK
sudo tee /etc/filebeat/filebeat.yml <<-EOF 
filebeat.prospectors:
  - input_type: log
      paths:
        - "/var/lib/mesos/slave/slaves/*/frameworks/*/executors/*/runs/latest/stdout"
        - "/var/lib/mesos/slave/slaves/*/frameworks/*/executors/*/runs/latest/stderr"
        - /var/log/messages
      document_type: syslog
      tail_files: true

    output:
      ### Logstash as output
      logstash:
        hosts: ["$LOGSTASH_HOSTNAME:$LOGSTASH_PORT"]
      ### Elasticsearch directly as output?
      #elasticsearch:
      # hosts: ["$ELK_HOSTNAME:$ELK_PORT"]

  - input_type: stdin
    #to do "cat /var/*.log | filebeat -e -v -c /etc/filebeat-stdin-dcos.yml
    #likely need to define /etc/filebeat-stdin-dcos.yml
      paths:
        - "-"
        document_type: syslog
        tail_files: true
    output:
      ### Logstash as output
      logstash:
        hosts: ["$LOGSTASH_HOSTNAME:$LOGSTASH_PORT"]
        bulk_max_size: 1024

  tls:
      # List of root certificates for HTTPS server verifications
      certificate_authorities: ["/etc/pki/tls/certs/$ELK_CERT_NAME"]
EOF

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


#Provide a first command to copy&paste so that the nodes can be installed in parallel to ELK on Bootstrap
#########################################################################################################
sleep 3
if [ -f $TEST_FILE ] && [ $(docker inspect -f {{.State.Running}} $NGINX_NAME) == "true" ]; then
  echo -e "** ${BLUE}SUCCESS${NC}. Bootstrap node installed."
  echo -e "** ${BLUE}COPY AND PASTE THE FOLLOWING INTO EACH NODE OF THE CLUSTER TO INSTALL DC/OS:"
  echo -e ""
  echo -e "${RED}sudo su"
  echo -e "cd"
  echo -e "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER ${NC} [ROLE]"
  echo -e ""
  echo -e ""
  echo -e "** This Agent installation command is also saved in $WORKING_DIR/$COMMAND_FILE for future use."
  echo -e "** ${BLUE}Done${NC}."
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


# Install ELK on Bootstrap node:
################################################################################################################################
################################################################################################################################

echo "** Installing ELK..."

#Install Java 8
echo "** Installing Java 8..."
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
sudo yum -y localinstall jdk-8u73-linux-x64.rpm
rm jdk-8u*-linux-x64.rpm

#Install elasticsearch
echo "** Installing Elasticsearch..."
sudo rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
sudo tee /etc/yum.repos.d/elasticsearch.repo <<-EOF 
[elasticsearch-2.x]
name=Elasticsearch repository for 2.x packages
baseurl=http://packages.elastic.co/elasticsearch/2.x/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF
sudo yum -y install elasticsearch
#configure elasticsearch
echo "** Configuring Elasticsearch..."
sudo cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.BAK
#https://gist.github.com/zsprackett/8546403
sudo tee /etc/elasticsearch/elasticsearch.yml <<-EOF
cluster.name: $CLUSTERNAME
node.name: $CLUSTERNAME
node.master: true
node.data: true
index.number_of_shards: 2
index.number_of_replicas: 1
bootstrap.mlockall: true
gateway.recover_after_nodes: 1
gateway.recover_after_time: 10m
gateway.expected_nodes: 1
action.disable_close_all_indices: true
action.disable_delete_all_indices: true
action.disable_shutdown: true
indices.recovery.max_bytes_per_sec: 100mb
EOF
#start elasticsearch
echo "** Starting Elasticsearch..."
sudo systemctl daemon-reload
sudo systemctl start elasticsearch
sudo systemctl enable elasticsearch

#Install Kibana
echo "** Installing Kibana..."
sudo tee /etc/yum.repos.d/kibana.repo <<-EOF
[kibana-4.4]
name=Kibana repository for 4.4.x packages
baseurl=http://packages.elastic.co/kibana/4.4/centos
gpgcheck=1
gpgkey=http://packages.elastic.co/GPG-KEY-elasticsearch
enabled=1
EOF
sudo yum -y install kibana
#configure kibana
#echo "** Configuring Kibana..."
#sudo cp /opt/kibana/config/kibana.yml /opt/kibana/config/kibana.yml.BAK
#start kibana
echo "** Starting Kibana..."
sudo systemctl start kibana
sudo chkconfig kibana on

#Install Logstash
echo "** Installing Logstash..."
#add logstash repo
sudo tee /etc/yum.repos.d/logstash.repo <<-EOF 
[logstash-2.2]
name=logstash repository for 2.2 packages
baseurl=http://packages.elasticsearch.org/logstash/2.2/centos
gpgcheck=1
gpgkey=http://packages.elasticsearch.org/GPG-KEY-elasticsearch
enabled=1
EOF
#install logstash
sudo yum install -y logstash
#configure logstash
echo "** Configuring Logstash..."

#copy bootstrap node's cert and key for ELK use
cp $WORKING_DIR/genconf/$CERT_NAME /etc/pki/tls/certs/$ELK_CERT_NAME
cp $WORKING_DIR/genconf/$KEY_NAME /etc/pki/tls/private/$ELK_KEY_NAME

#Add logstash config
# beats input that listens on 5044 and uses the SSL cert
sudo tee /etc/logstash/conf.d/02-beats-input.conf <<-EOF 
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/tls/$ELK_CERT_NAME"
    ssl_key => "/etc/pki/tls/private/$ELK_KEY_NAME"
  }
}
EOF
#filter looks for logs that are labeled as "syslog" type (by Filebeat), 
#and it will try to use grok to parse incoming syslog logs to make it structured and query-able
sudo tee /etc/logstash/conf.d/10-syslog-filter.conf <<-EOF 
filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
      add_field => [ "received_at", "%{@timestamp}" ]
      add_field => [ "received_from", "%{host}" ]
    }
    syslog_pri { }
    date {
      match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }
}
EOF
#configures Logstash to store the beats data in Elasticsearch which is running at localhost:9200, 
#in an index named after the beat used (filebeat, in our case)
sudo tee /etc/logstash/conf.d/30-elasticsearch-output.conf <<-EOF 
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    sniffing => true
    manage_template => false
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
    document_type => "%{[@metadata][type]}"
  }
}
EOF
echo "** Checking logstash configuration..."
sudo service logstash configtest
echo "** Launching logstash..."
sudo systemctl restart logstash
sudo chkconfig logstash on

#Load Kibana dashboards
echo "** Loading Kibana dashboards..."
mkdir -p $WORKING_DIR/kibana
cd $WORKING_DIR/kibana
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
unzip beats-dashboards-*.zip
cd beats-dashboards-*
./load.sh

#Load Filebeat index template in elasticsearch
echo "** Loading Filebeat index templates..."
mkdir -p $WORKING_DIR/filebeat
cd $WORKING_DIR/filebeat
#get filebeat user template from github
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
#load into localhost's elasticsearch
curl -XPUT 'http://localhost:9200/_template/filebeat?pretty' -d@filebeat-index-template.json


#End of ELK install on bootstrap node
################################################################################################################################
################################################################################################################################

#Final reminder of command: Check that installation finished successfully.
#################################################################
sleep 3
if [ -f $TEST_FILE ] && [ $(docker inspect -f {{.State.Running}} $NGINX_NAME) == "true" ]; then
  echo -e "** ${BLUE}SUCCESS${NC}. Bootstrap node installed."
  echo -e "** ${BLUE}COPY AND PASTE THE FOLLOWING INTO EACH NODE OF THE CLUSTER TO INSTALL DC/OS:"
  echo -e ""
  echo -e "${RED}sudo su"
  echo -e "cd"
  echo -e "curl -O http://$BOOTSTRAP_IP:$BOOTSTRAP_PORT/$NODE_INSTALLER && sudo bash $NODE_INSTALLER ${NC} [ROLE]"
  echo -e ""
  echo -e ""
  echo -e "** This Agent installation command is also saved in $WORKING_DIR/$COMMAND_FILE for future use."
  echo -e "** ${BLUE}Done${NC}."
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


