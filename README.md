# DC/OS installer

This is a script to install DC/OS on baremetal nodes or VM instances. It downloads all dependencies, checks for configuration parameters, autogenerates all required configuration files and finally completes the bootstrap node installation.
It also generates another script to be ran (copied and pasted) in all other nodes in the cluster (master/slave/public_slave). This downloads all dependencies and completes the node installation automatically.

Installation should only require running a single command in the bootstrap node, and copying & pasting the resulting command in each additional node of the cluster.

## Installation

Download the script, and edit the first section according to the desired cluster configuration. This includes:

- Adding the adequate download link for the desired version (default: latest Open DC/OS testing version available)
- Modifying the default bootstrap username/password (default: bootstrapuser/deleteme)
- Adjusting the security level (default: disabled)
- Optionally, adjust the cluster name, the bootstrap's node IP address to be used, or the directory for the installer to use as storage (all these default to valid values -- modify only if required)

Run the script in the node that will be used as bootstrap by copying and pasting the "curl" command below.
The script requires to have open connectivity for the ports required for the download (configurable in the script) and for DC/OS to work properly.
The script assumes some default values. If you wish to modify these parameters, edit the first section of the script and re-run.

## Usage

IMPORTANT: Run as root in the bootstrap node. Do "sudo su", "cd", then run the commands.
Do NOT "sudo command" instead.

Login as root to the bootstrap node, and download and run the script:

```
sudo su
cd
source <(curl https://raw.githubusercontent.com/fernandosanchezmunoz/DCOS_installer/master/dcos_install_centos7.sh)
```
IMPORTANT: The script will install the latest "testing" Open Source DC/OS branch. For other versions/releases, edit the script before running it and update the download link:
```
sudo su
cd
curl -O https://raw.githubusercontent.com/fernandosanchezmunoz/DCOS_installer/master/dcos_install_centos7.sh
vi dcos_install_centos7.sh +15
```


The script will provide a command during the installation process pointing to the node installer script in the bootstrap node, to be copied & pasted in the cluster nodes for installation. The format will be:

```curl -O http://BOOTSTRAP_NODE_IP:PORT/node_installer.sh && sudo bash node_installer.sh ```

All nodes will likely have to be rebooted as part of the installation process for the dependencies to launch at startup.
The bootstrap node will automatically launch the installation process and required services upon reboot, so once it's rebooted it will be ready to proceed. All other nodes will require a second run of the installer once the first run has satisfied the missing dependencies and forced a reboot.

NOTE: The installation process can be faulty at times. If something fails, it may be due to some decompression/download failing. If that happens, just run the same installer command again (both in the bootstrap and in other nodes).

NOTE2: To know whether the installation was successful after the bootstrap node has rebooted, run:

```docker ps```

You should see an nginx container running on the bootstrap node. Otherwise, simply run the installer again.

## Contributing

1. Fork it!
2. Create your feature branch: ```git checkout -b my-new-feature```
3. Commit your changes: ```git commit -am 'Add some feature'```
4. Push to the branch: ```git push origin my-new-feature```
5. Submit a pull request :D

## License

TODO: Write license
