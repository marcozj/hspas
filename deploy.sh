#!/bin/bash

function prepare()
{
    # Change followings according to your setup
    SUBNET="192.168.18.0/24" # Hosts within this subnet are allowed to communicate with each Postgres node for replication. Used in Patroni configuration
    VIP="192.168.18.20" # Virtual IP address of Postgres and Redis. Used in Keepalived configuration
    INTERFACE="ens33" # Physical interface name of each VM. Used in Keepalived configuration
    NODE1_IP="192.168.18.21" # IP address of node1. Used in ETCD and HAProxy configuration
    NODE2_IP="192.168.18.22" # IP address of node2. Used in ETCD and HAProxy configuration
    NODE3_IP="192.168.18.23" # IP address of node3. Used in ETCD and HAProxy configuration
    NODE1_NAME="node1" # Node1 name. This is NOT the VM hostname but used in ETCD configuration to indicate cluster node name
    NODE2_NAME="node2" # Node2 name. This is NOT the VM hostname but used in ETCD configuration to indicate cluster node name
    NODE3_NAME="node3" # Node2 name. This is NOT the VM hostname but used in ETCD configuration to indicate cluster node name
    REDIS_MASTER_NODE_IP=$NODE2_IP # Initial Redis master node IP address. Used in Sentinel configuration. Change this if you want Redis master running on another node by default
    PLV8_ENABLED="yes" # Install PLV8 extension for Postgres 12
    POSTGRES_PASSWORD="Passw0rd!" # Postgres user password. Used in Patroni configuration

    # Turn on SSL for PostgreSQL and Redis
    ENABLE_POSTGRES_SSL="yes" # To turn on SSL for PostgreSQL, set to yes
    ENABLE_REDIS_SSL="yes" # To turn on SSL for Redis, set to yes
    OPENSSL_CNF="/etc/ssl/myssl.cnf" # Generated OpenSSL configuration file name for creating self-signed certificates. Used in generation of SSL certificates for Postgres and Redis
    ROOT_CERT_NAME="Self-Signed CA" # Common name of self-signed CA certificate
    POSTGRES_CERT_NAME="PostgreSQL Certificate" # Common name of PostgreSQL certificate
    POSTGRES_CERT_ALTNAME="DNS:pgsql.demo.lab,DNS:*.demo.lab" # PostgreSQL certificate alternative name. Make sure DNS is resolved to VIP. Update it according to your domain and hostname
    REDIS_CERT_NAME="Redis Certificate" # Common name of Redis certificate
    REDIS_CERT_ALTNAME="DNS:redis.demo.lab,DNS:*.demo.lab" # Redis certificate alternative name. Make sure DNS is resolved to VIP. Update it according to your domain and hostname
    CA_CERT_DIR="/etc/ssl/myca" # Directory where CA certificate and key are saved
    POSTGRES_CERT_DIR="/etc/ssl/pgsql" # Directory where PostgresQL certificate and key are saved
    REDIS_CERT_DIR="/etc/ssl/redis" # Directory where Redis certificate and key are saved
    HAPROXY_CERT_DIR="/etc/ssl/haproxy" # Directory where HAProxy certificate is saved
    CRL_URL="https://raw.githubusercontent.com/marcozj/hspas/main/server.crl" # URL of CRL. After running this script, upload /etc/ssl/myca/server.crl to URL that is reachable by all the HSPAS nodes
    
    # Various ports
    POSTGRES_LOCAL_PORT=5433 # Actual Postgres port in each node. Used in Patroni configuration
    POSTGRES_VIP_PORT=5432 # Postgres port bind to VIP. Used in HAProxy configuration
    PATRONI_RESTAPI_PORT=8008 # Patroni REST API port.
    HAPROXY_STATS_PORT=7000 # HAProxy stats port. Used in HAProxy configuration
    REDIS_LOCAL_PORT=6378 # Actual Redis port in each node. Used in Redis, Sentinel and HAProxy configuration
    REDIS_VIP_PORT=6379 # Redis port bind to VIP. Used in HAProxy configuration
    SENTINEL_LOCAL_PORT=26378 # Actual Sentinel port in each node. Used in Sentinel configuration
    SENTINEL_VIP_PORT=26379 # Sentinel portal bind to VIP. Not in use

    # Prompt for selection of current node
    echo "Which node is this host?"
    select n in node1 node2 node3
    do
        case $n in
        "node1")            
            NODE_NAME=$NODE1_NAME
            NODE_IP=$NODE1_IP
            PRIORITY="99"
            break
            ;;
        "node2")
            NODE_NAME=$NODE2_NAME
            NODE_IP=$NODE2_IP
            PRIORITY="100"
            break
            ;;
        "node3")
            NODE_NAME=$NODE3_NAME
            NODE_IP=$NODE3_IP
            PRIORITY="101"
            break
            ;;
        *)
            echo "Invalid entry."
            exit 1
            ;;
        esac
    done

    echo "This node name:       $NODE_NAME"
    echo "This node IP address: $NODE_IP"
    echo "Interface for VIP:    $INTERFACE"
    echo "VIP:                  $VIP"
    echo "This node priority:   $PRIORITY"

    while true; do
        read -p "Are these correct (Y/N)?" yn
        case $yn in
            [Yy]* ) break;;
            [Nn]* ) exit;;
            * ) echo "Please answer yes or no.";;
        esac
    done

    return 0
}

function detect_os()
{
    basic_type=`uname -s`
    if [ "$basic_type" != "Linux" ];then
        echo "Cannot support the OS $basic_type"
        return 1
    fi

    if [ -f /etc/centos-release ];then
        if grep -w 'CentOS' /etc/centos-release >/dev/null ;then
            OS_NAME=centos
            OS_VERSION=`awk '{printf("%s",$4)}' /etc/centos-release`
            if [ "$OS_VERSION" = "" ];then
                echo "$Detect OS version failed according to /etc/centos-release"
                return 1
            fi
        else
            echo "Detect OS type failed according to /etc/centos-release"
            return 1
        fi
    elif [ -f /etc/SuSE-release ];then
        if grep -w 'SUSE' /etc/SuSE-release >/dev/null;then
            OS_NAME='sles'
            OS_VERSION=`grep 'VERSION =' /etc/SuSE-release | cut -d ' ' -f 3`
            if [ "$OS_VERSION" = "" ];then
                echo "Detect OS version failed according to /etc/SuSE-release"
                return 1
            fi
        else
            echo "Detect OS type failed according to /etc/SuSE-release"
            return 1
        fi
    elif [ -f /etc/redhat-release ];then
        if grep -w 'Red Hat' /etc/redhat-release >/dev/null ;then
            OS_NAME=rhel
            OS_VERSION=`sed -n 's/^[^0-9]*\(\([0-9]\+\.*[0-9]*\)\+\)[^0-9]*$/\1/p' /etc/redhat-release`
            if [ "$OS_VERSION" = "" ];then
                echo "Detect OS version failed according to /etc/redhat-release"
                return 1
            fi
        else
            echo "Detect OS type failed according to /etc/redhat-release"
            return 1
        fi
    elif [ -f /etc/system-release ]; then
        if grep 'Amazon Linux' /etc/system-release >/dev/null ;then
            OS_NAME='amzn'
            OS_VERSION=`awk -F ':' '{i=NF-1;printf("%s:%s", $i,$NF)}' /etc/system-release-cpe`
            if [ "$OS_VERSION" = "" ];then
                echo "Detect OS version failed according to /etc/system-release"
                return 1
            fi
        else
            echo "Detect OS type failed according to /etc/system-release"
            return 1
        fi
    elif [ -f /etc/lsb-release ];then
        if grep 'Ubuntu' /etc/lsb-release >/dev/null ;then
            OS_NAME='ubuntu'
            OS_VERSION=`grep 'DISTRIB_RELEASE' /etc/lsb-release | cut -d '=' -f 2`
            if [ "$OS_VERSION" = "" ];then
                echo "Detect OS version failed according to /etc/lsb-release"
                return 1
            fi
        else
            echo "Detect OS type failed according to /etc/lsb-release"
            return 1
        fi
    else
        echo "Detect OS type failed and can currently be detected OS is: RedHat CentOS SuSE AmazonLinux"
        return 1
    fi
    OS_BIT=`getconf LONG_BIT`  
    if [ "$OS_BIT" = "" ];then
        echo "Detect OS 32/64 bit failed"
        return 1
    fi

    echo "Detected OS $OS_NAME-$OS_VERSION"
    return 0
}

function check_supported_os()
{
    r=1
    case "$OS_NAME" in
        rhel|centos)
            case "$OS_VERSION" in
                8.*)
                    #OPENSSL_CNF="/etc/pki/tls/openssl.cnf"
                    r=0
                    ;;
                *)
                    r=1
                    echo "Doesn't support the OS $OS_NAME-$OS_VERSION currently"
                    ;;
            esac
            ;;
        ubuntu)
            case "$OS_VERSION" in
                20.*)
                    #OPENSSL_CNF="/etc/ssl/openssl.cnf"
                    r=0
                    ;;
                *)
                    r=1
                    echo "Doesn't support the OS $OS_NAME-$OS_VERSION currently"
                    ;;
            esac
            ;;
        *)
            r=1
            echo "Doesn't support the OS $OS_NAME-$OS_VERSION currently"
            ;;
    esac

    return $r
}

function create_rootcert()
{
    # Only create certificate at node1 and manually copy them to node2 and node3
    if [ "$ENABLE_POSTGRES_SSL" = "yes" ] || [ "$ENABLE_REDIS_SSL" = "yes" ];then
        if [ "$NODE_NAME" = "node1" ]; then
            mkdir $CA_CERT_DIR
            # Create custom openssl configuration file
            cat >${OPENSSL_CNF}<<END
[ ca ]
default_ca      = CA_default            # The default ca section

[ CA_default ]
database        = ${CA_CERT_DIR}/index.txt
default_md      = sha256
default_crl_days = 30

[req]
distinguished_name = req_distinguished_name

[req_distinguished_name]

[ v3_ca ]
basicConstraints = CA:true
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
keyUsage = digitalSignature, cRLSign, keyCertSign

[ usr_cert ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = \$ENV::ALTNAME
crlDistributionPoints=@crl_section

[ crl_section ]
URI.0 = ${CRL_URL}
END
            # Create self-singed CA certificate request
            touch ${CA_CERT_DIR}/index.txt
            export ALTNAME=$REDIS_CERT_ALTNAME
            openssl req -new -nodes -text -out ${CA_CERT_DIR}/root.csr -keyout ${CA_CERT_DIR}/root.key -subj "/CN=${ROOT_CERT_NAME}" -config ${OPENSSL_CNF}
            chmod og-rwx ${CA_CERT_DIR}/root.key
            # Sign the request with the key to create a root certificate authority
            openssl x509 -req -in ${CA_CERT_DIR}/root.csr -text -days 3650 -extfile ${OPENSSL_CNF} -extensions v3_ca -signkey ${CA_CERT_DIR}/root.key -out ${CA_CERT_DIR}/root.crt
            openssl dhparam -out $CA_CERT_DIR/dhparams.pem 2048
            # Generate CRL. Redis SSL certificate seems to require this
            openssl ca -gencrl -keyfile ${CA_CERT_DIR}/root.key -cert ${CA_CERT_DIR}/root.crt -out ${CA_CERT_DIR}/server.crl -config ${OPENSSL_CNF}
        fi
    fi

    return 0
}

function create_postgres_sslcert()
{
    # If turn on SSL, create self-signed server certificates
    if [ "$ENABLE_POSTGRES_SSL" = "yes" ];then
        echo "Creating SSL certificate for PostgreSQL..."
        if [ "$NODE_NAME" = "node1" ];then
            mkdir $POSTGRES_CERT_DIR
            # Create a server certificate signed by the new root certificate authority
            export ALTNAME=$POSTGRES_CERT_ALTNAME
            openssl req -new -nodes -text -out ${POSTGRES_CERT_DIR}/server.csr -keyout ${POSTGRES_CERT_DIR}/server.key -subj "/CN=${POSTGRES_CERT_NAME}" -config ${OPENSSL_CNF}
            chmod og-rwx ${POSTGRES_CERT_DIR}/server.key
            openssl x509 -req -in ${POSTGRES_CERT_DIR}/server.csr -text -days 1825 -CA ${CA_CERT_DIR}/root.crt -CAkey ${CA_CERT_DIR}/root.key -CAcreateserial -out ${POSTGRES_CERT_DIR}/server.crt -extfile ${OPENSSL_CNF} -extensions usr_cert
        fi
        chown -R postgres:postgres ${POSTGRES_CERT_DIR}
    fi
    return 0
}

function create_redis_sslcert()
{
    # If turn on SSL, create self-signed server certificate
    if [ "$ENABLE_REDIS_SSL" = "yes" ];then
        echo "Creating SSL certificate for Redis..."
        if [ "$NODE_NAME" = "node1" ];then
            mkdir $REDIS_CERT_DIR
            # Create a server certificate signed by the new root certificate authority
            export ALTNAME=$REDIS_CERT_ALTNAME
            openssl req -new -nodes -text -out ${REDIS_CERT_DIR}/server.csr -keyout ${REDIS_CERT_DIR}/server.key -subj "/CN=${REDIS_CERT_NAME}" -config ${OPENSSL_CNF}
            chmod og-rwx ${REDIS_CERT_DIR}/server.key
            openssl x509 -req -in ${REDIS_CERT_DIR}/server.csr -text -days 1825 -CA ${CA_CERT_DIR}/root.crt -CAkey ${CA_CERT_DIR}/root.key -CAcreateserial -out ${REDIS_CERT_DIR}/server.crt -extfile ${OPENSSL_CNF} -extensions usr_cert
        fi
        chown -R redis:redis ${REDIS_CERT_DIR}
    fi
    return 0
}

function install_etcd()
{
    echo "Installing ETCD 3.5 ..."
    ETCD_VER=v3.5.0
    DOWNLOAD_URL=https://github.com/etcd-io/etcd/releases/download
    curl -L ${DOWNLOAD_URL}/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz -o /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
    tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
    mv etcd-${ETCD_VER}-linux-amd64/etcd* /usr/local/bin
    mkdir -p /etc/etcd /var/lib/etcd
    groupadd --system etcd
    useradd -s /sbin/nologin --system -g etcd etcd
    chown -R etcd:etcd /var/lib/etcd

    # Create ETCD service file
    echo "Creating ETCD service systemd unit file..."
    cat >/etc/systemd/system/etcd.service <<END
[Unit]
Description=etcd service
Documentation=https://github.com/etcd-io/etcd
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
User=etcd
ExecStart=/usr/local/bin/etcd \\
    --name ${NODE_NAME} \\
    --data-dir /var/lib/etcd \\
    --initial-advertise-peer-urls http://${NODE_IP}:2380 \\
    --listen-peer-urls http://${NODE_IP}:2380 \\
    --listen-client-urls http://${NODE_IP}:2379,http://127.0.0.1:2379 \\
    --advertise-client-urls http://${NODE_IP}:2379 \\
    --initial-cluster-token etcd-cluster-0 \\
    --initial-cluster ${NODE1_NAME}=http://${NODE1_IP}:2380,${NODE2_NAME}=http://${NODE2_IP}:2380,${NODE3_NAME}=http://${NODE3_IP}:2380 \\
    --initial-cluster-state new \\
    --enable-v2=true

[Install]
WantedBy=multi-user.target
END

    # Open port 2379 and 2380
    echo "Configuring ETCD firewall ports..."
    case "$OS_NAME" in
        rhel|centos)
            firewall-cmd --add-port={2379,2380}/tcp --permanent
            firewall-cmd --reload
            # Configuration to allow ETCD to listen on port with SELinux
            /sbin/restorecon -v /usr/local/bin/etcd
            ;;
        ubuntu)
            ufw allow 2379/tcp comment 'ETCD client port'
            ufw allow 2380/tcp comment 'ETCD advertise port'
            ;;
    esac

    return 0
}

function install_postgres()
{
    echo "Installing Postgres 12 ..."
    case "$OS_NAME" in
        rhel|centos)
            # https://www.postgresql.org/download/linux/redhat/
            dnf -y install https://download.postgresql.org/pub/repos/yum/reporpms/EL-8-x86_64/pgdg-redhat-repo-latest.noarch.rpm
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of pgdg-redhat-repo-latest.noarch.rpm package unsuccessfully"
                return $r
            fi

            # CentOS 8 default postgresql module points to v11 so let's disable it
            dnf -qy module disable postgresql
            r=$?
            if [ $r -ne 0 ];then
                echo "Failed to disable postgresql module"
                return $r
            fi

            # Install Postgresql 12 but do not init it, let Patroni handle initdb
            dnf -y install postgresql12 postgresql12-server postgresql12-contrib
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of postgresql12 postgresql12-server postgresql12-contrib packages unsuccessfully"
                return $r
            fi
            ;;
        ubuntu)
            # Install Postgresql 12 but do not init it, let Patroni handle initdb
            apt -y install postgresql-12 postgresql-client-12 postgresql-contrib
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of postgresql-12 postgresql-client-12 postgresql-contrib packages unsuccessfully"
                return $r
            fi
            # Stop and disable Postgres system service and let Patroni to handle it
            systemctl stop postgresql
            systemctl disable postgresql
            ;;
    esac

    return 0
}

function install_plv8()
{
    # Install PLV8
    # Pre-built package https://www.xtuple.com/en/knowledge/installing-plv8
    # How to build PLV8
    # https://plv8.github.io
    # https://github.com/plv8/plv8/issues/383
    # https://gitmemory.com/issue/plv8/plv8/370/549635976
    if [ "$PLV8_ENABLED" = "yes" ];then
        echo "Installing PLV8..."
        case "$OS_NAME" in
            rhel|centos)
                export PATH=$PATH:/usr/pgsql-12/bin
                dnf -y install llvm
                r=$?
                if [ $r -ne 0 ];then
                    echo "Installation of libc++-dev llvm packages unsuccessfully"
                    return $r
                fi
                # libcxx package is required however only CentOS 7 package is available. Use it for CentOS 8 as well
                curl -s https://download-ib01.fedoraproject.org/pub/epel/7/x86_64/Packages/l/libcxx-3.8.0-3.el7.x86_64.rpm -o libcxx-3.8.0-3.el7.x86_64.rpm
                rpm -Uvh libcxx-3.8.0-3.el7.x86_64.rpm

                curl -s https://raw.githubusercontent.com/marcozj/hspas/main/plv8/plv8_2.3.15_pg12_centos.tar.gz -o plv8_2.3.15_pg12.tar.gz
                ;;
            ubuntu)
                apt -y install libc++-dev llvm
                r=$?
                if [ $r -ne 0 ];then
                    echo "Installation of libc++-dev llvm packages unsuccessfully"
                    return $r
                fi
                curl -s https://raw.githubusercontent.com/marcozj/hspas/main/plv8/plv8_2.3.15_pg12_ubuntu.tar.gz -o plv8_2.3.15_pg12.tar.gz
                ;;
        esac

        tar zxvf plv8_2.3.15_pg12.tar.gz
        cd plv8_2.3.15_pg12 && ./install_plv8.sh
        if [ $r -ne 0 ];then
            echo "Installation of PLV8 unsuccessfully"
            return $r
        fi
    fi

    return 0
}

function install_patroni()
{
    echo "Installing Patroni..."
    case "$OS_NAME" in
        rhel|centos)
            dnf -y install gcc python36-devel.x86_64 postgresql12-devel
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of gcc python36-devel.x86_64 postgresql12-devel packages unsuccessfully"
                return $r
            fi

            export PATH=$PATH:/usr/pgsql-12/bin
            pip3 install psycopg2-binary patroni[etcd]
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of psycopg2-binary patroni[etcd] packages unsuccessfully"
                return $r
            fi
            PGSQL_DATA_DIR="/var/lib/pgsql/12/data"
            PGSQL_BIN_DIR="/usr/pgsql-12/bin"

             # Open Patroni port and REST API port 
            echo "Enable Patroni restapi and Postgres firewall ports..."
            firewall-cmd --add-port=${PATRONI_RESTAPI_PORT}/tcp --permanent
            firewall-cmd --add-port=${POSTGRES_LOCAL_PORT}/tcp --permanent
            firewall-cmd --reload
            ;;
        ubuntu)
            apt-get install python3-pip python3-dev libpq-dev -y
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of python3-pip python3-dev libpq-dev packages unsuccessfully"
                return $r
            fi
            # Create a symlink of /usr/lib/postgresql/12/bin/ to /usr/sbin as it contains some tools used for Patroni
            ln -s /usr/lib/postgresql/12/bin/* /usr/sbin/
            pip install patroni python-etcd psycopg2
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of patroni python-etcd psycopg2 packages unsuccessfully"
                return $r
            fi
            PGSQL_DATA_DIR="/data/patroni"
            PGSQL_BIN_DIR="/usr/lib/postgresql/12/bin"
            mkdir -p /data/patroni
            chown postgres:postgres /data/patroni
            chmod 700 /data/patroni

            # Open Patroni port and REST API port 
            echo "Enable Patroni restapi and Postgres firewall ports..."
            ufw allow ${PATRONI_RESTAPI_PORT}/tcp comment 'Patroni Rest API port'
            ufw allow ${POSTGRES_LOCAL_PORT}/tcp comment 'Patroni local port'
            ;;
    esac

    # Create Patroni configuration file
    echo "Creating Patroni configuration file..."
    mkdir /etc/patroni
    cat >/etc/patroni/config.yml <<END
scope: batman
#namespace: /service/
name: ${NODE_NAME}

log:
  dir: /var/log/patroni

restapi:
  listen: ${NODE_IP}:${PATRONI_RESTAPI_PORT}
  connect_address: ${NODE_IP}:${PATRONI_RESTAPI_PORT}
#  certfile: /etc/ssl/certs/ssl-cert-snakeoil.pem
#  keyfile: /etc/ssl/private/ssl-cert-snakeoil.key
#  authentication:
#    username: username
#    password: password

# ctl:
#   insecure: false # Allow connections to SSL sites without certs
#   certfile: /etc/ssl/certs/ssl-cert-snakeoil.pem
#   cacert: /etc/ssl/certs/ssl-cacert-snakeoil.pem

etcd3:
  #Provide host to do the initial discovery of the cluster topology:
  host: ${NODE_IP}:2379
  #Or use "hosts" to provide multiple endpoints
  #Could be a comma separated string:
  #hosts: host1:port1,host2:port2
  #or an actual yaml list:
  #hosts:
  #- host1:port1
  #- host2:port2
  #Once discovery is complete Patroni will use the list of advertised clientURLs
  #It is possible to change this behavior through by setting:
  #use_proxies: true

#raft:
#  data_dir: .
#  self_addr: 127.0.0.1:2222
#  partner_addrs:
#  - 127.0.0.1:2223
#  - 127.0.0.1:2224

bootstrap:
  # this section will be written into Etcd:/<namespace>/<scope>/config after initializing new cluster
  # and all other cluster members will use it as a global configuration
  dcs:
    ttl: 30
    loop_wait: 10
    retry_timeout: 10
    maximum_lag_on_failover: 1048576
#    master_start_timeout: 300
#    synchronous_mode: false
    #standby_cluster:
      #host: 127.0.0.1
      #port: 1111
      #primary_slot_name: patroni
    postgresql:
      use_pg_rewind: true
#      use_slots: true
      parameters:
#        wal_level: hot_standby
#        hot_standby: "on"
#        max_connections: 100
#        max_worker_processes: 8
#        wal_keep_segments: 8
#        max_wal_senders: 10
#        max_replication_slots: 10
#        max_prepared_transactions: 0
#        max_locks_per_transaction: 64
#        wal_log_hints: "on"
#        track_commit_timestamp: "off"
#        archive_mode: "on"
#        archive_timeout: 1800s
#        archive_command: mkdir -p ../wal_archive && test ! -f ../wal_archive/%f && cp %p ../wal_archive/%f
#      recovery_conf:
#        restore_command: cp ../wal_archive/%f %p

  # some desired options for 'initdb'
  initdb:  # Note: It needs to be a list (some options need values, others are switches)
  - encoding: UTF8
  - data-checksums

  pg_hba:  # Add following lines to pg_hba.conf after running 'initdb'
  # For kerberos gss based connectivity (discard @.*$)
  #- host replication replicator 127.0.0.1/32 gss include_realm=0
  #- host all all 0.0.0.0/0 gss include_realm=0
  - host replication replicator ${SUBNET} md5
  - host replication replicator 127.0.0.1/32 md5
  - host all all 0.0.0.0/0 md5
  - hostssl all all 0.0.0.0/0 md5

  # Additional script to be launched after initial cluster creation (will be passed the connection URL as parameter)
# post_init: /usr/local/bin/setup_cluster.sh

  # Some additional users users which needs to be created after initializing new cluster
  # Create user options https://www.postgresql.org/docs/12/app-createuser.html
  users:
    dbadmin:
      password: ${POSTGRES_PASSWORD}
      options:
        - superuser

postgresql:
  listen: ${NODE_IP}:${POSTGRES_LOCAL_PORT}
  connect_address: ${NODE_IP}:${POSTGRES_LOCAL_PORT}
  data_dir: ${PGSQL_DATA_DIR}
  bin_dir: ${PGSQL_BIN_DIR}
#  config_dir:
  pgpass: /tmp/pgpass0
  authentication:
    replication:
      username: replicator
      password: ${POSTGRES_PASSWORD}
    superuser:
      username: admin
      password: ${POSTGRES_PASSWORD}
    rewind:  # Has no effect on postgres 10 and lower
      username: rewind_user
      password: ${POSTGRES_PASSWORD}
  # Server side kerberos spn
#  krbsrvname: postgres
  parameters:
    logging_collector: on
    log_directory: /var/log/postgresql
    log_filename: postgresql-%Y-%m-%d_%H%M%S.log 
END

    # If turn on SSL, insert SSL related parameters
    if [ "$ENABLE_POSTGRES_SSL" = "yes" ];then
        cat >>/etc/patroni/config.yml <<END
    ssl: on
    #ssl_ca_file:
    ssl_cert_file: ${POSTGRES_CERT_DIR}/server.crt
    #ssl_crl_file:
    ssl_key_file: ${POSTGRES_CERT_DIR}/server.key
    #ssl_ciphers:
    #ssl_prefer_server_ciphers: on
    #ssl_ecdh_curve: prime256v1
    #ssl_min_protocol_version: TLSv1
    #ssl_max_protocol_version:
    #ssl_dh_params_file:
    #ssl_passphrase_command:
    #ssl_passphrase_command_supports_reload: off
END
    fi

    # Continue from previous content
    cat >>/etc/patroni/config.yml <<END
    # Fully qualified kerberos ticket file for the running user
    # same as KRB5CCNAME used by the GSS
#   krb_server_keyfile: /var/spool/keytabs/postgres
    unix_socket_directories: '.'
  # Additional fencing script executed after acquiring the leader lock but before promoting the replica
  #pre_promote: /path/to/pre_promote.sh

#watchdog:
#  mode: automatic # Allowed values: off, automatic, required
#  device: /dev/watchdog
#  safety_margin: 5

tags:
    nofailover: false
    noloadbalance: false
    clonefrom: false
    nosync: false
END

    # Create Patroni log directory
    mkdir /var/log/patroni
    chown postgres:postgres /var/log/patroni

    # Create Patroni systemd service file
    echo "Creating Patroni service systemd unit file..."
    cat >/etc/systemd/system/patroni.service <<END
[Unit]
Description=High availability PostgreSQL Cluster
After=syslog.target network.target

[Service]
Type=simple
User=postgres
Group=postgres
ExecStart=/usr/local/bin/patroni /etc/patroni/config.yml
KillMode=process
TimeoutSec=30
Restart=no

[Install]
WantedBy=multi-user.target
END

    # Create Postgres log directory
    if [ ! -d "/var/log/postgresql" ];then
        mkdir /var/log/postgresql
        chown postgres:postgres /var/log/postgresql 
    fi

    # If turn on SSL, create self-signed server certificates
    create_postgres_sslcert
    r=$? 
    [ $r -ne 0 ] && echo "Failed to create PostgreSQL SSL certificate [exit code=$r]" && exit $r

    # Install PLV8 after required packages are installed
    install_plv8
    r=$? 
    [ $r -ne 0 ] && echo "Failed to install PLV8 [exit code=$r]" && exit $r

    return 0
}

function install_redis()
{
    echo "Installing Redis 6..."
    case "$OS_NAME" in
        rhel|centos)
            REDIS_CONF="/etc/redis.conf"
            SENTINEL_CONF="/etc/redis-sentinel.conf"
            dnf -y module reset redis
            dnf -y module enable redis:6
            dnf -y install redis
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of Redis package unsuccessfully"
                return $r
            fi
             # Make sure network interface is up before starting Redis and Sentinel
            echo "Update Redis and Sentinel service files..."
            /bin/sed -i 's/^After=network.target/After=network-online.target/g' /usr/lib/systemd/system/redis.service
            /bin/sed -i 's/^After=network.target/After=network-online.target/g' /usr/lib/systemd/system/redis-sentinel.service

            echo "Allow /usr/bin/redis-server to bind to network port with SELinux enabled..."
            semanage port -a -t redis_port_t -p tcp $REDIS_LOCAL_PORT
            semanage port -a -t redis_port_t -p tcp $SENTINEL_LOCAL_PORT

            # Open Redis port and Sentinel port
            echo "Enable Redis firewall ports..."
            firewall-cmd --add-port=${REDIS_LOCAL_PORT}/tcp --permanent
            firewall-cmd --add-port=${SENTINEL_LOCAL_PORT}/tcp --permanent
            firewall-cmd --reload
            ;;
        ubuntu)
            REDIS_CONF="/etc/redis/redis.conf"
            SENTINEL_CONF="/etc/redis/sentinel.conf"
            # Use PPA repository maintained by Redis Development to install Redis 6
            add-apt-repository ppa:redislabs/redis -y
            apt-get install redis redis-sentinel -y
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of Redis package unsuccessfully"
                return $r
            fi
            # Make sure network interface is up before starting Redis and Sentinel
            echo "Update Redis and Sentinel service files..."
            /bin/sed -i 's/^After=network.target/After=network-online.target/g' /lib/systemd/system/redis.service
            /bin/sed -i 's/^After=network.target/After=network-online.target/g' /lib/systemd/system/redis-sentinel.service

            # Open Redis port and Sentinel port
            echo "Enable Redis firewall ports..."
            ufw allow ${REDIS_LOCAL_PORT}/tcp comment 'Redis local port'
            ufw allow ${SENTINEL_LOCAL_PORT}/tcp comment 'Redis Sentinel local port'
            ;;
    esac

    # Create Redis configuration file
    echo "Creating Redis configuraiton file..."
    cp -r ${REDIS_CONF} ${REDIS_CONF}_bak
    cat >${REDIS_CONF} <<END
bind ${NODE_IP}
logfile /var/log/redis/redis.log
dir /var/lib/redis
protected-mode no
supervised systemd
# small tunning
tcp-keepalive 0
maxmemory-policy volatile-lru
END

    # Handle SSL enable case to create different configuration file
    if [ "$ENABLE_REDIS_SSL" = "yes" ]; then
        cat >>${REDIS_CONF} <<END
port 0
tls-port ${REDIS_LOCAL_PORT}
tls-cert-file ${REDIS_CERT_DIR}/server.crt
tls-key-file ${REDIS_CERT_DIR}/server.key
tls-ca-cert-file ${CA_CERT_DIR}/root.crt
tls-auth-clients no
tls-replication yes
tls-dh-params-file /etc/ssl/myca/dhparams.pem
END
    else
        cat >>${REDIS_CONF} <<END
port ${REDIS_LOCAL_PORT}
END
    fi

    if [ "$REDIS_MASTER_NODE_IP" != "$NODE_IP" ]; then
        echo "replicaof ${REDIS_MASTER_NODE_IP} ${REDIS_LOCAL_PORT}" >> ${REDIS_CONF}
    fi

    # Create Sentinel configuration file
    echo "Creating Redis Sentinel configuraiton file..."
    cp -r ${SENTINEL_CONF} ${SENTINEL_CONF}_bak
    cat >${SENTINEL_CONF} <<END
# Do NOT include loopback IP otherwise Sentinel can not detect each other
bind ${NODE_IP}
logfile "/var/log/redis/sentinel.log"
dir "/var/lib/redis"
# "redis-cluster" is the name of our cluster
# each sentinel process is paired with a redis-server process
sentinel monitor redis-cluster ${REDIS_MASTER_NODE_IP} ${REDIS_LOCAL_PORT} 2
sentinel down-after-milliseconds redis-cluster 5000
sentinel failover-timeout redis-cluster 60000
sentinel parallel-syncs redis-cluster 1
protected-mode no
supervised systemd
END

    # Handle SSL enable case to create different configuration file
    if [ "$ENABLE_REDIS_SSL" = "yes" ]; then
        cat >>${SENTINEL_CONF} <<END
port 0
tls-port ${SENTINEL_LOCAL_PORT}
tls-cert-file ${REDIS_CERT_DIR}/server.crt
tls-key-file ${REDIS_CERT_DIR}/server.key
tls-ca-cert-file ${CA_CERT_DIR}/root.crt
tls-auth-clients no
tls-replication yes
END
    else
        cat >>${SENTINEL_CONF} <<END
port ${SENTINEL_LOCAL_PORT}
END
    fi

    # If turn on SSL, create self-signed server certificate
    create_redis_sslcert
    r=$? 
    [ $r -ne 0 ] && echo "Failed to create Redis SSL certificate [exit code=$r]" && exit $r

    echo "Configuring OS performing tunning for Redis..."
    # WARNING: The TCP backlog setting of 511 cannot be enforced because /proc/sys/net/core/somaxconn is set to the lower value of 128.
    sysctl -w net.core.somaxconn=65535
    echo 'net.core.somaxconn=65535' >> /etc/sysctl.conf
    # WARNING overcommit_memory is set to 0! Background save may fail under low memory condition. To fix this issue add 'vm.overcommit_memory = 1' to /etc/sysctl.conf and then reboot or run the command 'sysctl vm.overcommit_memory=1' for this to take effect.
    sysctl -w vm.overcommit_memory=1
    echo 'vm.overcommit_memory=1' >> /etc/sysctl.conf
    # WARNING you have Transparent Huge Pages (THP) support enabled in your kernel. This will create latency and memory usage issues with Redis. To fix this issue run the command 'echo never > /sys/kernel/mm/transparent_hugepage/enabled' as root, and add it to your /etc/rc.local in order to retain the setting after a reboot. Redis must be restarted after THP is disabled
    echo never > /sys/kernel/mm/transparent_hugepage/enabled
    echo 'echo never > /sys/kernel/mm/transparent_hugepage/enabled' >> /etc/rc.local
    chmod +x /etc/rc.local
    systemctl enable rc-local

    return 0
}

function install_haproxy()
{
    echo "Installing HAProxy..."
    case "$OS_NAME" in
        rhel|centos)
            dnf install -y haproxy
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of haproxy package unsuccessfully"
                return $r
            fi
            # Configuration to allow rsyslogd access on the directory haproxy with SELinux
            cat >/tmp/rsyslog-haproxy.te <<END
module rsyslog-haproxy 1.0;

require {
    type syslogd_t;
    type haproxy_var_lib_t;
    class dir { add_name remove_name search write };
    class sock_file { create setattr unlink };
}

#============= syslogd_t ==============
allow syslogd_t haproxy_var_lib_t:dir { add_name remove_name search write };
allow syslogd_t haproxy_var_lib_t:sock_file { create setattr unlink };
END
            checkmodule -M -m /tmp/rsyslog-haproxy.te -o /tmp/rsyslog-haproxy.mod
            semodule_package -o /tmp/rsyslog-haproxy.pp -m /tmp/rsyslog-haproxy.mod
            semodule -i /tmp/rsyslog-haproxy.pp

            systemctl restart rsyslog
            if [ $r -ne 0 ];then
                echo "Failed to restart Rsyslog"
                return $r
            fi

            # Configuration to allow HAProxy to listen on port with SELinux
            setsebool -P haproxy_connect_any 1

            echo "Enable Postgres proxy, Redis and HAProxy stats firewall ports..."
            firewall-cmd --add-port=${POSTGRES_VIP_PORT}/tcp --permanent
            firewall-cmd --add-port=${REDIS_VIP_PORT}/tcp --permanent
            firewall-cmd --add-port=${HAPROXY_STATS_PORT}/tcp --permanent
            firewall-cmd --reload
            ;;
        ubuntu)
            apt-get install haproxy -y
            if [ $r -ne 0 ];then
                echo "Installation of haproxy package unsuccessfully"
                return $r
            fi
            echo "Enable Postgres proxy, Redis and HAProxy stats firewall ports..."
            ufw allow ${POSTGRES_VIP_PORT}/tcp comment 'PostgreSQL VIP port'
            ufw allow ${REDIS_VIP_PORT}/tcp comment 'Redis VIP port'
            ufw allow ${HAPROXY_STATS_PORT}/tcp comment 'HAProxy stats port'
            ;;
    esac

    # Create HAProxy configuration file
    echo "Creating HAProxy configuraiton file..."
    cp -r /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg_bak
    cat >/etc/haproxy/haproxy.cfg <<END
global
    log         /dev/log local0
    chroot      /var/lib/haproxy
    pidfile     /var/run/haproxy.pid
    maxconn     4000
    user        haproxy
    group       haproxy
    daemon
END

    if [ "$ENABLE_POSTGRES_SSL" = "yes" ] || [ "$ENABLE_REDIS_SSL" = "yes" ];then
        cat >>/etc/haproxy/haproxy.cfg <<END
    ssl-dh-param-file /etc/ssl/myca/dhparams.pem
END
    fi

    cat >>/etc/haproxy/haproxy.cfg <<END
defaults
    log global
    mode tcp
    retries 2
    timeout client 30m
    timeout connect 4s
    timeout server 30m
    timeout check 5s

listen stats
    mode http
    bind *:${HAPROXY_STATS_PORT}
    stats enable
    stats uri /

listen postgres_primary
    bind *:${POSTGRES_VIP_PORT}
    option httpchk OPTIONS /master
    http-check expect status 200
    default-server inter 3s fall 3 rise 2 on-marked-down shutdown-sessions
    server postgresql_node1_${POSTGRES_LOCAL_PORT} ${NODE1_IP}:${POSTGRES_LOCAL_PORT} maxconn 100 check port 8008
    server postgresql_node2_${POSTGRES_LOCAL_PORT} ${NODE2_IP}:${POSTGRES_LOCAL_PORT} maxconn 100 check port 8008
    server postgresql_node3_${POSTGRES_LOCAL_PORT} ${NODE3_IP}:${POSTGRES_LOCAL_PORT} maxconn 100 check port 8008

END

    if [ "$ENABLE_REDIS_SSL" = "yes" ]; then
        cat >>/etc/haproxy/haproxy.cfg <<END
frontend ft_redis
    bind *:${REDIS_VIP_PORT} crt /etc/ssl/haproxy/server.crt ca-file ${CA_CERT_DIR}/root.crt ssl verify none
    default_backend redis_master

backend redis_master
    mode tcp 
    option tcp-check 
    #tcp-check send AUTH\ somepassword\r\n 
    #tcp-check expect string +OK 
    tcp-check send PING\r\n 
    tcp-check expect string +PONG 
    tcp-check send info\ replication\r\n 
    tcp-check expect string role:master 
    tcp-check send QUIT\r\n 
    tcp-check expect string +OK 
    server redis_node1_${REDIS_LOCAL_PORT} ${NODE1_IP}:${REDIS_LOCAL_PORT} maxconn 4096 check inter 3s check-ssl ca-file ${CA_CERT_DIR}/root.crt ssl verify none
    server redis_node2_${REDIS_LOCAL_PORT} ${NODE2_IP}:${REDIS_LOCAL_PORT} maxconn 4096 check inter 3s check-ssl ca-file ${CA_CERT_DIR}/root.crt ssl verify none
    server redis_node3_${REDIS_LOCAL_PORT} ${NODE3_IP}:${REDIS_LOCAL_PORT} maxconn 4096 check inter 3s check-ssl ca-file ${CA_CERT_DIR}/root.crt ssl verify none

END
        # If turn on SSL, copy Redis self-signed server certificate and private key for use in frontend ft_redis binding
        # Assuming Redis installation is done first
        if [ "$NODE_NAME" = "node1" ];then
            mkdir $HAPROXY_CERT_DIR
            cp ${REDIS_CERT_DIR}/server.crt $HAPROXY_CERT_DIR
            cat ${REDIS_CERT_DIR}/server.key >> ${HAPROXY_CERT_DIR}/server.crt
            chmod og-rwx ${HAPROXY_CERT_DIR}/server.crt
        fi
        chown -R haproxy:haproxy ${HAPROXY_CERT_DIR}
    else
        cat >>/etc/haproxy/haproxy.cfg <<END
frontend ft_redis
    bind *:${REDIS_VIP_PORT}
    default_backend redis_master

backend redis_master
    mode tcp 
    option tcp-check 
    #tcp-check send AUTH\ somepassword\r\n 
    #tcp-check expect string +OK 
    tcp-check send PING\r\n 
    tcp-check expect string +PONG 
    tcp-check send info\ replication\r\n 
    tcp-check expect string role:master 
    tcp-check send QUIT\r\n 
    tcp-check expect string +OK 
    server redis_node1_${REDIS_LOCAL_PORT} ${NODE1_IP}:${REDIS_LOCAL_PORT} maxconn 4096 check inter 3s 
    server redis_node2_${REDIS_LOCAL_PORT} ${NODE2_IP}:${REDIS_LOCAL_PORT} maxconn 4096 check inter 3s 
    server redis_node3_${REDIS_LOCAL_PORT} ${NODE3_IP}:${REDIS_LOCAL_PORT} maxconn 4096 check inter 3s
END
    fi

    # Enable HAProxy logging
    # https://www.digitalocean.com/community/tutorials/how-to-configure-haproxy-logging-with-rsyslog-on-centos-8-quickstart
    echo "Configuring HAProxy logging..."
    if [ -d "/var/lib/haproxy/dev" ] 
    then
        mkdir /var/lib/haproxy/dev
    fi
    cat >/etc/rsyslog.d/99-haproxy.conf <<END
\$AddUnixListenSocket /var/lib/haproxy/dev/log

# Send HAProxy messages to a dedicated logfile
:programname, startswith, "haproxy" {
    /var/log/haproxy.log
    stop
}
END

    return 0
}

function install_keepalived()
{
    echo "Installing Keepalived..."
    case "$OS_NAME" in
        rhel|centos)
            yum install -y keepalived
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of Keepalived package unsuccessfully"
                return $r
            fi
            # Add firewall rule to allow multicast and vrrp protocol
            echo "Make sure firewall is configured to accept accept multicast and vrrp protocol (IP Protocol # 112)"
            firewall-cmd --add-rich-rule='rule protocol value="vrrp" accept' --permanent
            firewall-cmd --reload
            ;;
        ubuntu)
            apt install keepalived -y
            r=$?
            if [ $r -ne 0 ];then
                echo "Installation of Keepalived package unsuccessfully"
                return $r
            fi
            # Add firewall rule to allow multicast and vrrp protocol
            echo "Make sure firewall is configured to accept accept multicast and vrrp protocol (IP Protocol # 112)"
            ufw allow to 224.0.0.18 comment 'VRRP Broadcast'
            ufw allow from ${NODE_IP} comment 'VRRP Router'
            ;;
    esac

    # Create Keepalived configuration file
    echo "Creating Keepalived configuration file..."
    cp -r /etc/keepalived/keepalived.conf /etc/keepalived/keepalived.conf_bak
    cat >/etc/keepalived/keepalived.conf <<END
global_defs {
    router_id ${NODE_NAME}
}
vrrp_script chk_haproxy { # Requires keepalived-1.1.13
    script "/usr/bin/killall -0 haproxy"
    interval 2 # check every 2 seconds
    weight 2 # add 2 points of prio if OK
}
vrrp_instance VI_1 {
    interface ${INTERFACE}
    state MASTER
    priority ${PRIORITY}
    advert_int 1
    virtual_router_id 51
    virtual_ipaddress {
        ${VIP}/24
    }
    track_script {
        chk_haproxy
    }
}
END

    return 0
}

start_services()
{
    case "$OS_NAME" in
        rhel|centos)
            REDIS_SERVICE="redis"
            ;;
        ubuntu)
            REDIS_SERVICE="redis-server"
            ;;
    esac

    echo "Starting ETCD..."
    systemctl start etcd
    if [ $r -ne 0 ];then
        echo "Failed to start ETCD"
        return $r
    fi
    echo "Starting Patroni and PostgreSQL..."
    systemctl start patroni
    if [ $r -ne 0 ];then
        echo "Failed to start Patroni and PostgreSQL"
        return $r
    fi

    echo "Starting Redis and Sentinel..."
    systemctl start $REDIS_SERVICE
    if [ $r -ne 0 ];then
        echo "Failed to start Redis"
        return $r
    fi
    systemctl start redis-sentinel
    if [ $r -ne 0 ];then
        echo "Failed to start Sentinel"
        return $r
    fi

    echo "Starting HAProxy..."
    systemctl start haproxy
    if [ $r -ne 0 ];then
        echo "Failed to start HAProxy"
        return $r
    fi
    echo "Starting Keepalived..."
    systemctl start keepalived
    if [ $r -ne 0 ];then
        echo "Failed to start Keepalived"
        return $r
    fi
}

enable_services()
{
    case "$OS_NAME" in
        rhel|centos)
            REDIS_SERVICE="redis"
            ;;
        ubuntu)
            REDIS_SERVICE="redis-server"
            ;;
    esac

    systemctl daemon-reload
    r=$?
    if [ $r -ne 0 ];then
        echo "Failed to reload daemon services"
        return $r
    fi

    echo "Enable services..."
    systemctl enable etcd
    systemctl enable patroni
    systemctl enable $REDIS_SERVICE
    systemctl enable redis-sentinel
    systemctl enable keepalived
    systemctl enable haproxy
}

########### Start the program #################
if [ "$DEBUG_SCRIPT" = "yes" ];then
    set -x
fi

prepare
r=$? 
[ $r -ne 0 ] && echo "Failed to prepare input vaules [exit code=$r]" && exit $r

detect_os
r=$? 
[ $r -ne 0 ] && echo "Detect OS failed [exit code=$r]" && exit $r

check_supported_os
r=$? 
[ $r -ne 0 ] && echo "Current OS is not supported [exit code=$r]" && exit $r

create_rootcert
r=$? 
[ $r -ne 0 ] && echo "Failed to create root certificate [exit code=$r]" && exit $r

install_etcd
r=$? 
[ $r -ne 0 ] && echo "Failed to install ETCD [exit code=$r]" && exit $r

install_postgres
r=$? 
[ $r -ne 0 ] && echo "Failed to install PostgreSQL [exit code=$r]" && exit $r

install_patroni
r=$? 
[ $r -ne 0 ] && echo "Failed to install Patroni [exit code=$r]" && exit $r

install_redis
r=$? 
[ $r -ne 0 ] && echo "Failed to install Redis [exit code=$r]" && exit $r

install_haproxy
r=$? 
[ $r -ne 0 ] && echo "Failed to install HAProxy [exit code=$r]" && exit $r

install_keepalived
r=$? 
[ $r -ne 0 ] && echo "Failed to install Keepalived [exit code=$r]" && exit $r

enable_services
r=$? 
[ $r -ne 0 ] && echo "Failed to enable all services [exit code=$r]" && exit $r

exit $r
