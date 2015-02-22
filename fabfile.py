from fabric.api import *
import fabric.contrib.files
import json
import StringIO
import os
env.use_ssh_config = True

def install(recipient=None,mx_user=None,mx_password=None,mx_sender=None,mx_host=None,hostname=None):
    if not hostname:
        hostname = run('hostname').strip()
    print 'using hostname %s'%mx_host
    sudo('apt-get -q -y install git python-geoip')
    with cd('/usr/local'):
        if not fabric.contrib.files.exists('authwatcher'):
            sudo('git clone http://github.com/guyromm/authwatcher.git')
        with cd('authwatcher'):
            sudo('git pull')
    args = {'recipient':recipient,
            'mx_user':mx_user,
            'mx_password':mx_password,
            'mx_sender':mx_sender,
            'mx_host':mx_host,
            'hostname':hostname}
    if (os.path.exists('authwatcher.json')):
        jsonconf = open('authwatcher.json','r').read()
    else:
        assert args['recipient']
        jsonconf = open('authwatcher.json.example','r').read()%args
    assert json.loads(jsonconf)
    put(StringIO.StringIO(jsonconf),'/etc/authwatcher.json.install',use_sudo=True)
    with settings(warn_only=True):
        if sudo('diff %s %s'%('/etc/authwatcher.json',
                             '/etc/authwatcher.json.install')):
            print 'installing new authwatcher.json'
            sudo('cp /etc/authwatcher.json.install /etc/authwatcher.json')
    with cd('/usr/local/share'):
        if not fabric.contrib.files.exists('GeoLiteCity.dat'):
            sudo("wget 'http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz' && sudo gzip -d GeoLiteCity.dat.gz")
        
    if not fabric.contrib.files.exists('/etc/init/authwatcher.conf'):
        put('authwatcher.conf','/etc/init/',use_sudo=True)
    with settings(warn_only=True):
        sudo('initctl stop authwatcher')
    sudo('initctl start authwatcher')
