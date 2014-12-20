import hashlib
import os
import fabtools
import pwgen
import logging
import logging.handlers
import time
from pymongo import MongoClient
from pymongo.errors import AutoReconnect, ConnectionFailure
from contextlib import contextmanager
from fabric.api import *
from fabric.colors import green
from fabric.contrib.files import sed


## Global Variable which can be changed for future versions change
env.host = ['127.0.0.1']
graylog2 = "/opt/graylog2-server-0.90.0"
graylog2_pkg = "graylog2-server-0.90.0.tgz"
grayweb_pkg = "graylog2-web-interface-0.90.0.tgz"
grayweb = "/opt/graylog2-web-interface"
elasticsearch_pkg = "elasticsearch-0.90.10.deb"
ip_bind = "127.0.0.1"

## Logging Implementation for future and present use
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='/tmp/Graylog2.log',
                    filemode='w')

# define a Handler which writes INFO messages or higher to the sys.stderr
console = logging.StreamHandler()
console.setLevel(logging.INFO)

# set a format which is simpler for console use
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')

# tell the handler to use this format
console.setFormatter(formatter)
# add the handler to the root logger
logging.getLogger('').addHandler(console)


@contextmanager
def rollbackwrap():
    try:
        yield
    except SystemExit:
        logging.debug('Something has been failed !')
        abort("Fail!")


@task
def deploy():
    with rollbackwrap():
        chk_sys()
        cfg_files()
        deb_pkg()
        src_get()
        elastics()
        mongo_inst()
        g_conf()
        rsyslog_conf()
        gweb_conf()
        mongodb_check_conn()
        start_up()


# Verify The OS
def chk_sys():
    if fabtools.system.distrib_codename() != 'precise' and fabtools.system.distrib_id == 'Ubuntu':
        print (green('Created and tested Only On Ubuntu 12.04 LTS Server'))

        abort(u"Distribution Is Not Supported")


# Copy the necessary Configuration files into the relative destinations
def cfg_files():
    print(green('Disabling CD Sources and Updating Apt Packages'))
    sed('/etc/apt/sources.list', 'deb cdrom:', '# deb cdrom:', backup='.bak', use_sudo=True)
    sudo('apt-get -qq update')
    time.sleep(2)
    retval = os.getcwd()
    print (green('Copying some configuration files into the relative paths'))
    sudo('cp {0}/32-graylog2.conf /etc/rsyslog.d/'.format(retval))
    sudo('cp {0}/graylog2 /etc/init.d/'.format(retval))
    sudo('cp {0}/graylog2-web /etc/init.d'.format(retval))
    time.sleep(3)


# Install the dependencies
def deb_pkg():
    print (green('Installing The Dependencies ...'))
    with settings(use_sudo=True):
        fabtools.deb.install([
            'git',
            'curl',
            'build-essential',
            'openjdk-7-jre',
            'pwgen',
            'wget',
        ])
        time.sleep(3)


# Function to Download The necessary Packages
def src_get():
    print (green('Downloading The Tarball ... '))
    sudo('wget --directory-prefix=/opt '
         'https://download.elasticsearch.org/elasticsearch/elasticsearch/elasticsearch-0.90.10.deb')
    sudo('wget --directory-prefix=/opt '
         'http://packages.graylog2.org/releases/graylog2-server/graylog2-server-0.90.0.tgz')
    sudo('wget --directory-prefix=/opt '
         'http://packages.graylog2.org/releases/graylog2-web-interface/graylog2-web-interface-0.90.0.tgz')
    with cd('/opt'):
        print(green('Extracting The Tarball ...'))
        sudo('tar zxvf {0}'.format(graylog2_pkg))
        sudo('tar zxvf {0}'.format(grayweb_pkg))
        time.sleep(2)
        print(green('Installing Elastic Search ...'))
        sudo('dpkg -i {0}'.format(elasticsearch_pkg))
        print(green('Creating The necessary Symbolic Links ...'))
        sudo('ln -s graylog2-server-0.9*/ graylog2-server')
        sudo('ln -s graylog2-web-interface-0.9*/ graylog2-web-interface')
    time.sleep(3)


# Function which modify the elasticsearch.yml file as needed
def elastics():
    print(green('Setting up Elastic Search ...'))
    sed('/etc/elasticsearch/elasticsearch.yml', before='# cluster.name: elasticsearch',
        after='cluster.name: graylog2', use_sudo=True, backup='')
    sudo('update-rc.d elasticsearch defaults 95 10')
    fabtools.service.restart('elasticsearch')
    time.sleep(3)


# Function which install the MongoDB Pkg
def mongo_inst():
    print (green('Downloading MongoDB ...'))
    if not fabtools.deb.apt_key_exists('7F0CEB10'):
        fabtools.deb.add_apt_key(keyid='7F0CEB10', keyserver='hkp://keyserver.ubuntu.com:80')
        sudo('echo deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen '
             '> /etc/apt/sources.list.d/10gen.list')
        print (green('Installing Mongo DB ...'))
        fabtools.deb.update_index(quiet=True)
        fabtools.deb.install('mongodb-10gen', with_settings(use_sudo=True))
    print (green('Changing some value for MongoDB ...'))
    sudo('mv /etc/security/limits.conf /etc/security/limits.bak')
    sudo('grep -Ev "# End of file" /etc/security/limits.bak > /etc/security/limits.conf')
    sudo('echo "elasticsearch soft nofile 32000" >> /etc/security/limits.conf')
    sudo('echo "elasticsearch hard nofile 32000" >> /etc/security/limits.conf')
    sudo('echo "# End of file" >> /etc/security/limits.conf')
    time.sleep(5)


# Function used to get an input from user and encode it through the sha256
def gethash(mypass):
    m = hashlib.sha256()
    m.update(mypass)
    pass_enc = m.hexdigest()
    return m.hexdigest()


# Function which Configure the Graylog2
def g_conf():
    sudo('chown -R root:root /opt/graylog2*')
    sudo('mv {0}/graylog2.conf.example {0}/graylog2.conf'.format(graylog2))
    root_pass = prompt(green("Enter a password to use for the admin account to login to the Graylog2 webUI: "))
    secret_pwd = pwgen.pwgen(96, no_symbols=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='root_password_sha2 =',
        after='root_password_sha2 = {0}'.format(gethash(root_pass)), use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='password_secret =',
        after='password_secret = {0}'.format(secret_pwd), use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='elasticsearch_shards = 4',
        after='elasticsearch_shards = 1', use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='mongodb_useauth = true',
        after='mongodb_useauth = false', use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='#elasticsearch_discovery_zen_ping_multicast_enabled = false',
        after='elasticsearch_discovery_zen_ping_multicast_enabled = false', use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='#elasticsearch_discovery_zen_ping_unicast_hosts '
                                                     '= 192.168.1.203:9300',
        after='elasticsearch_discovery_zen_ping_unicast_hosts = 127.0.0.1:9300', use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='retention_strategy = delete',
        after='retention_strategy = close', use_sudo=True)
    sed('{0}/graylog2.conf'.format(graylog2), before='#rest_transport_uri = http://192.168.1.1:12900/',
        after='rest_transport_uri = http://127.0.0.1:12900/', use_sudo=True)
    sudo('mv {0}/graylog2.conf /etc/'.format(graylog2))
    sudo('chmod +x /etc/init.d/graylog2')
    sudo('update-rc.d graylog2 defaults')
    time.sleep(3)


# Function which apport the necessary changes to rsyslog.conf file
def rsyslog_conf():
    print (green('Changing the Rsyslog Configuration file to forward the necessary Data to Graylog'))
    sed('/etc/rsyslog.conf', before='#$ModLoad imudp',
        after='$ModLoad imudp', use_sudo=True, backup='')
    sed('/etc/rsyslog.conf', before='#$UDPServerRun 514',
        after='$UDPServerRun 514', use_sudo=True)
    sed('/etc/rsyslog.conf', before='#$ModLoad imtcp',
        after='$ModLoad imtcp', use_sudo=True)
    sed('/etc/rsyslog.conf', before='#$InputTCPServerRun 514',
        after='$InputTCPServerRun 514', use_sudo=True)
    sed('/etc/rsyslog.d/50-default.conf', before='\*.*;auth,authpriv.none',
        after='#*.*;auth,authpriv.none', use_sudo=True, backup='')
    print(green('Restartin The Rsync Service ...'))
    fabtools.service.restart('rsyslog')
    time.sleep(3)


# Function which Configures The Graylog2 Web
def gweb_conf():
    print(green('Configuring the Graylog2-Web Interface ...'))
    secret_pwd = pwgen.pwgen(96, no_symbols=True)
    sed('{0}/conf/graylog2-web-interface.conf'.format(grayweb), before='graylog2-server.uris=""',
        after='graylog2-server.uris="http://127.0.0.1:12900/"', use_sudo=True, backup='')
    sed('{0}/conf/graylog2-web-interface.conf'.format(grayweb), before='application.secret=""',
        after='application.secret="{0}"'.format(secret_pwd), use_sudo=True)
    sudo('chown root:root /etc/init.d/graylog2-web')
    sudo('chmod 755 /etc/init.d/graylog2-web')
    sudo('update-rc.d graylog2-web defaults')
    time.sleep(3)


# Check the connection to the MongoDB
def mongodb_check_conn():
    deadline = time.time()+10
    while time.time() < deadline:
        try:
            MongoClient('/tmp/mongodb-27017.sock')
            print (green('Successfully connected to database ...'))
        except AutoReconnect:
            print (green("Could not connect to database. Waiting a little bit."))
            time.sleep(2)
        except ConnectionFailure:
            logging.info("Could Not Connect To MongoDB", exc_info=True)
            logging.debug("Could Not Connect To MongoDB")
            exit(0)


# Start The Services in the right order waiting a little bit between one start and the other one
# Starting all the services without a sleep time it causes a KO to me
def start_up():
    print(green('Starting All The Necessary Services ...'))
    fabtools.service.restart('elasticsearch')
    time.sleep(10)
    fabtools.service.start('graylog2')
    time.sleep(12)
    fabtools.service.start('graylog2-web')
    current_interface = fabtools.network.address('eth0')
    print (green('Installation Has Been Completed !!'))
    print (green('You Can Now Browse to The IP Address %s:9000' % current_interface))
    print (green('Login With Username: "admin" and the password you have been put before'))
