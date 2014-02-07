## Some defaults
# IPs that we should not change
DONT_TOUCH = ('40.0.61.128', '74.93.92.201')
# The security group we want to update
PARENT_NAME = 'dev'
OPEN_PORTS = (('tcp', '80', '80'),  # HTTP
              ('tcp', '443', '443'), # HTTPs
              ('tcp', '22', '22'),  #SSH
              ('tcp', '5672', '5672'),   #RabbitMQ
              ('tcp', '55672', '55672'))  #RabbitMQ management plug-in


