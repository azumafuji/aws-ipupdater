"""
Adds current IP address to security group and will update and remove
old rules from previous IP addresses
"""

import os
import pickle
import urllib2
from datetime import datetime
from boto.ec2.connection import EC2Connection
import json

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

## Some defaults
# IPs that we should not change
DONT_TOUCH = ('40.0.61.128', '74.93.92.201')

# The security group we want to update
PARENT_NAME = 'dev'

# typical ports that we need to be using
OPEN_PORTS = (('tcp', '80', '80'),
              ('tcp', '443', '443'),
              ('tcp', '22', '22'))

# import local defaults
from defaults import *

# default credentials - we get these from a file called credentials.py 
AWS_ACCESS_KEY_ID = ''
AWS_SECRET_ACCESS_KEY = ''

# import local credentials
from credentials import *

conn = EC2Connection(AWS_ACCESS_KEY_ID, 
                     AWS_SECRET_ACCESS_KEY)
                     
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

req = urllib2.Request('http://jsonip.com', 
                      headers = {'Content-Type': 'application/json'})
ext_ip = json.loads(urllib2.urlopen(req).read())['ip']

new_grant = ext_ip + '/32'

if ext_ip in DONT_TOUCH:
    print "You shouldn't be using this script from this location. You're current external IP is in the list of IPs that shouldn't be changing."
    exit()

if old_grant == new_grant:
    response = raw_input("Your IP hasn't changed. Do you want to update anyway? (y/n)?")
    if str(response) != "y":
        exit()

# Save the new external IP
save_old_ip(ext_ip)


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
