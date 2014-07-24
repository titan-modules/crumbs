#!/usr/bin/env python
"""
This is a Titan module

- AnalyzeCrumbs returns paths back
  to a centralized server

To use:

    sudo pip install --upgrade titantools

"""

import json
import logging
from socket import gethostbyaddr
from urllib2 import urlopen,URLError
from sys import argv, exit, path

# Titan includes
from titantools.orm import TiORM
from titantools.data_science import DataScience
from titantools.system import execute_command as shell_out

from time import time, gmtime, strftime
from os.path import dirname,basename,isfile,realpath
from os import chmod
#from titantools.decorators import run_every_5

# Set Logging Status
logging_enabled = False

# Set datastore directory
DATASTORE = argv[1]

#@run_every_5
class AnalyzeCrumbs(object):
    """ AnalyzeCrumbs """

    def __init__(self):
      self.message = type(self).__name__
      self.status = 0
      self.datastore = []

      # Create config file
      config_file = '%s/config.json' % dirname(realpath(__file__))

      # Check if config exists
      if isfile(config_file):
        with open(config_file) as config_file:   
          self.config = json.load(config_file)

    def get_crumbs(self):
      """
      Find network interesting information
      """

      # First detect a connection
      try:
        response=urlopen('%s' % self.config['connectivity_target'],timeout=1)
  
        # First get public IP
        response = urlopen('%s' % self.config['externalip_target'])
        public_ip = response.read().rstrip()

        # Get PTR
        reversed_dns = gethostbyaddr(public_ip)[0]
        
        # Next get default route gateway
        dgw_ip = shell_out("netstat -anr | grep default |awk '{print $2}'").strip().split('\n')
        dgw_mac = []

        # Grap ARPs to use as name attribute
        arps = shell_out("arp -a").split('\n')

        # Loop through gateways
        for gwip in dgw_ip:
          # Create ARP filter based on gw ip
          arp_filter = "(%s)" % gwip

          # Loop through ARP responses
          for arp in arps:
            if arp_filter in arp:
              dgw_mac.append(arp.split()[3])

        # Get traceroute
        traceroute = shell_out('traceroute -n -w 3 -q 1 -m 16 %s' % self.config['traceroute_target'])

        # Append to master
        self.datastore.append({
            "name": ', '.join(dgw_mac),
            "gateway": ', '.join(dgw_ip),
            "public_ip": public_ip,
            "reverse_dns": reversed_dns,
            "traceroute": traceroute,
            "date": exec_date
          })

        # Set Message
        self.message = "ip: %s, gwip: %s, gwmac: %s" % (public_ip, ', '.join(dgw_ip), ', '.join(dgw_mac))

        # If no issues, return 0
        self.status = 0

      # Not internet connection available 
      except URLError as err:

        # Set Message
        self.message = "No internet connectivity"

        # If no issues, return 0
        self.status = 1

    def analyze(self):
      """
      This is the 'main' method that launches all of the other checks
      """
      self.get_crumbs()

      return json.JSONEncoder().encode({"status": self.status, "message": self.message})

    # Store data in datastore
    def store(self):

      # Don't bother if there was an issue
      if self.status is 0:
        # the table definitions are stored in a library file. this is instantiating
        # the ORM object and initializing the tables
        module_schema_file = '%s/schema.json' % dirname(__file__)

        # Is file
        if isfile(module_schema_file):
          with open(module_schema_file) as schema_file:   
            schema = json.load(schema_file)

          # ORM 
          ORM = TiORM(DATASTORE)
          if isfile(DATASTORE):
              chmod(DATASTORE, 0600)

          for k, v in schema.iteritems():
            ORM.initialize_table(k, v)
          
          data_science = DataScience(ORM, self.datastore, 'crumbs')
          data_science.get_new_entries()

if __name__ == "__main__":

    start = time()

    # the "exec_date" is used as the "date" field in the datastore
    exec_date = strftime("%a, %d %b %Y %H:%M:%S-%Z", gmtime())

    ###########################################################################
    # Gather data
    ###########################################################################
    try:
        a = AnalyzeCrumbs()
        if a is not None:
            output = a.analyze()
            a.store()
            print output

    except Exception, error:
        print error

    end = time()

    # to see how long this module took to execute, launch the module with
    # "--log" as a command line argument
    if "--log" in argv[1:]:
      logging_enabled = True
      logging.basicConfig(format='%(message)s', level=logging.INFO)
    
    logging.info("Execution took %s seconds.", str(end - start))
