#/bin/bash
ROLE=$1
CLUSTERNAME='elk-test'
BOOTSTRAP_IP=$(ip addr show $INTERFACE | grep -Eo \
 '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1) #this node's eth0
WORKING_DIR=$HOME"/elk"

echo -e "** Installing ${BLUE}ELK${NC}..."
#Install Java 8
echo "** Installing Java 8..."
wget --no-cookies --no-check-certificate --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com%2F; oraclelicense=accept-securebackup-cookie" "http://download.oracle.com/otn-pub/java/jdk/8u73-b02/jdk-8u73-linux-x64.rpm"
sudo yum -y localinstall jdk-8u73-linux-x64.rpm
rm -f jdk-8u*-linux-x64.rpm
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
network.host: $BOOTSTRAP_IP
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
echo "** Configuring Kibana..."
sudo cp /opt/kibana/config/kibana.yml /opt/kibana/config/kibana.yml.BAK
sudo tee /opt/kibana/config/kibana.yml  <<-EOF
elasticsearch.url: "http://$BOOTSTRAP_IP:9200"
EOF
#start kibana
echo "** Starting Kibana..."
sudo systemctl start kibana
sudo chkconfig kibana on

#Load Kibana dashboards
echo "** Loading Kibana dashboards..."
mkdir -p $WORKING_DIR/kibana
cd $WORKING_DIR/kibana
curl -L -O https://download.elastic.co/beats/dashboards/beats-dashboards-1.1.0.zip
unzip beats-dashboards-*.zip
cd beats-dashboards-*
#modify load.sh to point to Elasticsearch on numbered interface
sudo sed -i -e "s/ELASTICSEARCH=http:\/\/localhost:9200/ELASTICSEARCH=http:\/\/$ELK_HOSTNAME:$ELK_PORT/g" ./load.sh
./load.sh

#Load Filebeat index template in elasticsearch
echo "** Loading Filebeat index templates..."
mkdir -p $WORKING_DIR/filebeat
cd $WORKING_DIR/filebeat
#get filebeat user template from github
curl -O https://gist.githubusercontent.com/thisismitch/3429023e8438cc25b86c/raw/d8c479e2a1adcea8b1fe86570e42abab0f10f364/filebeat-index-template.json
#load into localhost's elasticsearch
curl -XPUT "http://$BOOTSTRAP_IP:9200/_template/filebeat?pretty" -d@filebeat-index-template.json

if [[ $ROLE == 'master' ]]; then
  sudo tee /etc/systemd/system/$FILEBEAT_JOURNALCTL_SERVICE<<-EOF 
[Unit]
Description=DCOS journalctl parser to filebeat
Wants=filebeat.service
After=filebeat.service
[Service]
Restart=always
RestartSec=5
ExecStart=/bin/sh -c '/usr/bin/journalctl --no-tail -f \
  -u dcos-3dt.service \
  -u dcos-3dt.socket \
  -u dcos-adminrouter-reload.service \
  -u dcos-adminrouter-reload.timer   \
  -u dcos-adminrouter.service        \
  -u dcos-bouncer.service            \
  -u dcos-ca.service                 \
  -u dcos-cfn-signal.service         \
  -u dcos-cosmos.service             \
  -u dcos-download.service           \
  -u dcos-epmd.service               \
  -u dcos-exhibitor.service          \
  -u dcos-gen-resolvconf.service     \
  -u dcos-gen-resolvconf.timer       \
  -u dcos-history.service            \
  -u dcos-link-env.service           \
  -u dcos-logrotate-master.timer     \
  -u dcos-marathon.service           \
  -u dcos-mesos-dns.service          \
  -u dcos-mesos-master.service       \
  -u dcos-metronome.service          \
  -u dcos-minuteman.service          \
  -u dcos-navstar.service            \
  -u dcos-networking_api.service     \
  -u dcos-secrets.service            \
  -u dcos-setup.service              \
  -u dcos-signal.service             \
  -u dcos-signal.timer               \
  -u dcos-spartan-watchdog.service   \
  -u dcos-spartan-watchdog.timer     \
  -u dcos-spartan.service            \
  -u dcos-vault.service              \
  -u dcos-logrotate-master.service  \
  > /var/log/dcos/dcos.log 2>&1'
ExecStartPre=/usr/bin/journalctl --vacuum-size=10M
[Install]
WantedBy=multi-user.target
EOF

elif [[ $ROLE == 'agent' ]]; then
  sudo tee /etc/systemd/system/$FILEBEAT_JOURNALCTL_SERVICE<<-EOF 
[Unit]
Description=DCOS journalctl parser to filebeat
Wants=filebeat.service
After=filebeat.service
[Service]
Restart=always
RestartSec=5
ExecStart=/bin/sh -c '/usr/bin/journalctl --no-tail -f      \
  -u dcos-3dt.service                      \
  -u dcos-logrotate-agent.timer            \
  -u dcos-3dt.socket                       \
  -u dcos-mesos-slave.service              \
  -u dcos-adminrouter-agent.service        \
  -u dcos-minuteman.service                \
  -u dcos-adminrouter-reload.service       \
  -u dcos-navstar.service                  \
  -u dcos-adminrouter-reload.timer         \
  -u dcos-rexray.service                   \
  -u dcos-cfn-signal.service               \
  -u dcos-setup.service                    \
  -u dcos-download.service                 \
  -u dcos-signal.timer                     \
  -u dcos-epmd.service                     \
  -u dcos-spartan-watchdog.service         \
  -u dcos-gen-resolvconf.service           \
  -u dcos-spartan-watchdog.timer           \
  -u dcos-gen-resolvconf.timer             \
  -u dcos-spartan.service                  \
  -u dcos-link-env.service                 \
  -u dcos-vol-discovery-priv-agent.service \
  -u dcos-logrotate-agent.service          \
  > /var/log/dcos/dcos.log 2>&1'
ExecStartPre=/usr/bin/journalctl --vacuum-size=10M
[Install]
WantedBy=multi-user.target
EOF
fi

sudo chmod 0755 /etc/systemd/system/$FILEBEAT_JOURNALCTL_SERVICE
sudo systemctl daemon-reload
sudo systemctl start $FILEBEAT_JOURNALCTL_SERVICE
sudo chkconfig $FILEBEAT_JOURNALCTL_SERVICE on
sudo systemctl start filebeat
sudo chkconfig filebeat on
