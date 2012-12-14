"""
Adds current IP address to security group and will update and remove
old rules from previous IP addresses
"""

import os
import pickle
import urllib2
from datetime import datetime
from boto.ec2.connection import EC2Connection

def load_old_ip():
    """
    Get the old IP from a file and return it.
    """
    try:
        file = open('prev_ips.dat')
        old_ip = pickle.load(file)
        file.close()
    except:
        old_ip = None

    return old_ip


def save_old_ip(ip):
    try:
        file = open('prev_ips.dat', 'w')
        pickle.dump(ip, file)
        file.close()
    except Exception, e:
        print "Failed to save old IP"

# Some defaults
DONT_TOUCH = ('40.0.61.128', '74.93.92.201')
PARENT_NAME = 'dev'
OPEN_PORTS = (('tcp', '80', '80'),
              ('tcp', '443', '443'),
              ('tcp', '22', '22'),
              ('tcp', '5672', '5672'),
              ('tcp', '55672', '55672'))
# import local defaults
from defaults import *

# default credentials
AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''

# import local credentials
from credentials import *

conn = EC2Connection(AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
sgs = conn.get_all_security_groups()

parent_sg = None

for sg in sgs:
    if sg.name == PARENT_NAME:
        parent_sg = sg
sg = None

if parent_sg is None:
    print "The parent security group %s was not found." % (PARENT_NAME)
    exit()

old_ip = load_old_ip()
if old_ip is not None:
    old_grant = old_ip + '/32'
else:
    old_grant = None

headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0'}
req = urllib2.Request(
    'http://automation.whatismyip.com/n09230945.asp', None, headers)
ext_ip = urllib2.urlopen(req).read()
save_old_ip(ext_ip)
new_grant = ext_ip + '/32'

if ext_ip in DONT_TOUCH:
    print "You shouldn't be using this script from this location. You're current external IP is in the list of IPs that shouldn't be changing."
    exit()

if old_grant == new_grant:
    print "Your IP hasn't changed...try again later."
    exit()

# Clear out all the old rules in this group.
if not old_ip is None:
    print "Clearing old grants..."
    sgrules = parent_sg.rules
    for sgrule in sgrules:
        for grant in sgrule.grants:
            if grant.cidr_ip == old_grant:
                print "Revoking %s for %s" % (sgrule, grant)
                parent_sg.revoke(ip_protocol=sgrule.ip_protocol,
                                 from_port=sgrule.from_port,
                                 to_port=sgrule.to_port,
                                 cidr_ip=grant)

# Authorize new ports at current IP
print "Adding new grants..."
for prot, fp, tp in OPEN_PORTS:
    print "Authorizing %s on ports %s-%s for %s" % (prot, fp, tp, new_grant)
    parent_sg.authorize(
        ip_protocol=prot, from_port=fp, to_port=tp, cidr_ip=new_grant)
