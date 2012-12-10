
=============
aws-ipupdater
=============

This script will add new grants to an AWS security group based on your current IP.  This is useful if you are using DHCP connections or move around frequently and want to keep access to your AWS instances to a minimum.  The script stores the last known IP used, checks to make sure it isn't still in use (by you in the same location) and will clean up the old IPs if you run the script from a new location. There are options to make sure you don't overwrite or remove IPs that should not be modified, and you can specify a list of ports and protocols to grant access to.


Usage
=====

You'll need boto 2.5 or newer installed.  It may work with an older version, but has not been tested.

    python aws-ipupdate


defaults.py
-----------
Contains default settings.  This is where you want to put any other options you need.  There settings in here are as follows.

DONT_TOUCH
    A tuple of IPs that should not be altered by this script.  This will prevent the script from accidentally changing grants that should not be changed.

PARENT_NAME
    The name of the security group to make the changes to.

OPEN_PORTS
    A tuple of tuples that contain the protocols and ports that should be open.

credentials.py
--------------
The credentials that should be used for connecting to and operating on the security group specified in the defaults.py. If you don't have access to update the security groups with these credentials, the script will fail.

AWS_ACCESS_KEY_ID
    Access key ID from AWS

AWS_SECRET_ACCESS_KEY
    Secret key corresponding to the access key for AWS

