#!/usr/bin/env python
#
# Modifies filter or delivery interface names on the Big Tap controller.
#
# 2015/5/5 Nobo Akiya - initial version

import sys
import argparse
import re
import pybsn

# Global vars to control the output chattiness
g_info = True
g_debug = True
g_error = True

# Global vars to simplify access to BCF REST paths
g_rest_core = None
g_rest_app_bigtap = None

# Print functions
def print_info(string):
  if g_info:
    print "INFO:", string

def print_debug(string):
  if g_debug:
    print "DEBUG:", string

def print_error(string):
  if g_error:
    print "ERROR:", string

# Switch class
# Contains a dictionary of Interface class objects { name : object }
class Switch:
  """ Switch class """
  def __str__(self):
    return "Switch " + self.dpid
  def __init__(self, dpid, alias=None):
    self.dpid = str(dpid)
    if (alias == None):
      self.alias = alias
    else:
      self.alias = str(alias)
    self.interfaces = {}
    print_info(str(self) + ": created")
  def interface_add(self, interface):
    if (interface.name in self.interfaces):
      print_error(str(self) + ": already contains Interface " + interface.name)
    else:
      self.interfaces[interface.name] = interface
      print_info(str(self) + ": Interface " + interface.name + " added")
 
# Interface class
# Has a back pointer to Switch class object
# Has a back pointer to dictionary of IntfGroup class objects { name : object }
# Has a back pointer to dictionary of Policy class objects { name : object }
class Interface:
  """ Interface class """
  def __str__(self):
    return "Interface " + self.name
  def __init__(self, switch, name, role=None, iname=None, rewrite=-1, analytics=True):
    if ((role != None) and (role != "filter" and role != "delivery" and role != "service")):
      raise("Unexpected role specified")
    if ((role != None) and (iname == None)):
      raise("Interface name must be supplied for a filter/delivery/service interface")
    self.name = str(name)
    if (role == None):
      self.role = role
    else:
      self.role = str(role)
    if (iname == None):
      self.iname = iname
    else:
      self.iname = str(iname)
    self.rewrite = rewrite
    self.analytics = analytics
    switch.interface_add(self)
    self.ptr_switch = switch
    self.ptr_intfgroups = {}
    self.ptr_policies = {}
    print_info(str(self) + ": created")
  def intfgroup_add(self, intfgroup):
    self.ptr_intfgroups[intfgroup.name] = intfgroup
    print_info(str(self) + ": IntfGroup " + intfgroup.name + " added")
  def policy_add(self, policy):
    self.ptr_policies[policy.name] = policy
    print_info(str(self) + ": Policy " + policy.name + " added")

# Interface Group class
# Contains a dictionary of Interface class objects { name : object }
# Has a back pointer to dictionary of Policy class objects { name : object }
class IntfGroup:
  """ Interface Group class """
  def __str__(self):
    if (self.is_filter == True):
      return "IntGroup(F) " + self.name
    else:
      return "IntGroup(D) " + self.name
  def __init__(self, name, is_filter):
    self.name = str(name)
    self.is_filter = is_filter
    self.interfaces = {}
    self.ptr_policies = {}
    print_info(str(self) + ": created")
  def interface_add(self, interface):
    if (interface.name in self.interfaces):
      print_error(str(self) + ": interface " + interface.name + " already exists")
    else:
      if ((self.is_filter == True) and (interface.role != "filter")):
        print_error(str(self) + ": interface " + interface.name + " is not a filter interface")
      elif ((self.is_filter == False) and (interface.role != "delivery")):
        print_error(str(self) + ": interface " + interface.name + " is not a delivery interface")
      else:
        self.interfaces[interface.name] = interface
        print_info(str(self) + ": interface " + interface.name + " added")
    interface.intfgroup_add(self)
  def policy_add(self, policy):
    self.ptr_policies[policy.name] = policy
    print_info(str(self) + ": policy " + policy.name + " added")

# Policy class
# Contains a dictionary of Interface class objects { name : object }
# Contains a dictionary of IntfGroup class objects { name : object }
class Policy:
  """ Policy class """
  def __str__(self):
    return "Policy " + self.name
  def __init__(self, name):
    self.name = str(name)
    self.interfaces = {}
    self.intfgroups = {}
    print_info(str(self) + ": created")
  def interface_add(self, interface):
    if ((interface.role != "filter") and (interface.role != "delivery")):
      print_error(str(self) + ": interface " + interface.name + " is not filter/delivery role")
    elif (interface.name in self.interfaces):
      print_error(str(self) + ": interface " + interface.name + " already exists")
    else:
      self.interfaces[interface.name] = interface
      interface.policy_add(self)
    print_info(str(self) + ": interface " + interface.name + " added")
  def intfgroup_add(self, intfgroup):
    if (intfgroup.name in self.intfgroups):
      print_error(str(self) + ": intfgroup " + intfgroup.name + " already exists")
    else:
      self.intfgroups[intfgroup.name] = intfgroup
      intfgroup.policy_add(self)
    print_info(str(self) + ": intfgroup " + intfgroup.name + " added")

# Main start

# Parse arguments
parser = argparse.ArgumentParser(description='Test REST APIs')
parser.add_argument('--host', '-H', type=str, default="127.0.0.1", help="Controller IP/Hostname to connect to")
parser.add_argument('--user', '-u', type=str, default="admin", help="Username")
parser.add_argument('--password', '-p', type=str, default="adminadmin", help="Password")
parser.add_argument('--oldname', '-o', type=str, default=None, help="Old Interface Name")
parser.add_argument('--newname', '-n', type=str, default=None, help="New Interface Name")
args = parser.parse_args()
if ((args.oldname == None) or (args.newname == None)):
  print_error("Old and new interface must be supplied ...")
  parser.print_help()
  exit(-1)
namecheck = re.compile("^[a-zA-Z][-.0-9a-zA-Z_:]*$")
if (not((namecheck.match(args.newname)))):
  print_error("New interface must be in format '[a-zA-Z][-.0-9a-zA-Z_:]*' ...")
  exit(-1)
print_info("Arguments parsed ...")

# Connect to the controller
bigtap = pybsn.connect(args.host, args.user, args.password)
g_rest_core = bigtap.root.core
g_rest_app_bigtap = bigtap.root.applications.bigtap
print_info("Connected to " + args.host + " ...")

print_info("Loading existing configurations ...")

# Load all switches from existing configuration
switches = {}

conf_orig_switches = g_rest_core.switch.get()
for switch in conf_orig_switches:
  sw = Switch(switch['dpid'])
  switches[sw.dpid] = sw

# Load all interfaces from existing configuration
interfaces_alias = {}

conf_orig_interfaces = g_rest_app_bigtap.interface_config.get()
for interface in conf_orig_interfaces:
  if ('rewrite-vlan' in interface.keys()):
    intf = Interface(switches[interface['switch']], interface['interface'], interface['role'], interface['name'], interface['rewrite-vlan'], interface['analytics'])
  else:
    intf = Interface(switches[interface['switch']], interface['interface'], interface['role'], interface['name'], analytics=interface['analytics'])
  interfaces_alias[intf.iname] = intf

# Load all interface groups from existing configuration
intfgroups = {}

conf_orig_f_intfgroups = g_rest_app_bigtap.filter_interface_group.get()
for intfgroup in conf_orig_f_intfgroups:
  intg = IntfGroup(intfgroup['name'], True)
  for filtergroup in intfgroup['filter-group']:
    if (not(str(filtergroup['name']) in interfaces_alias.keys())):
      print_error("Found interface " + str(filtergroup['name']) + " in filter interface group " + intg.name + " but the interface does not exist ...")
      exit(-1)
    intg.interface_add(interfaces_alias[str(filtergroup['name'])])
  intfgroups[intg.name] = intg

conf_orig_d_intfgroups = g_rest_app_bigtap.delivery_interface_group.get()
for intfgroup in conf_orig_d_intfgroups:
  intg = IntfGroup(intfgroup['name'], False)
  for filtergroup in intfgroup['delivery-group']:
    if (not(str(filtergroup['name']) in interfaces_alias.keys())):
      print_error("Found interface " + str(filtergroup['name']) + " in delivery interface group " + intg.name + " but the interface does not exist ...")
      exit(-1)
    intg.interface_add(interfaces_alias[str(filtergroup['name'])])
  intfgroups[intg.name] = intg

# Load all policies from existing configuration
conf_orig_policies = g_rest_app_bigtap.view.policy.get()
for policy in conf_orig_policies:
  po = Policy(policy['name'])  
  if ('filter-group' in policy.keys()):
    objs = policy['filter-group']
    for obj in objs:
      if (not(str(obj['name']) in interfaces_alias.keys())):
        print_error("Found interface " + str(obj['name']) + " in policy " + po.name + " but the interface does not exist ...")
        exit(-1)
      po.interface_add(interfaces_alias[str(obj['name'])])
  if ('filter-intf-group' in policy.keys()):
    objs = policy['filter-intf-group']
    for obj in objs:
      if (not(str(obj['name']) in intfgroups.keys())):
        print_error("Found interface group " + str(obj['name']) + " in policy " + po.name + " but the interface group does not exist ...")
        exit(-1)
      po.intfgroup_add(intfgroups[str(obj['name'])])
  if ('delivery-group' in policy.keys()):
    objs = policy['delivery-group']
    for obj in objs:
      if (not(str(obj['name']) in interfaces_alias.keys())):
        print_error("Found interface " + str(obj['name']) + " in policy " + po.name + " but the interface does not exist ...")
        exit(-1)
      po.interface_add(interfaces_alias[str(obj['name'])])
  if ('delivery-intf-group' in policy.keys()):
    objs = policy['delivery-intf-group']
    for obj in objs:
      if (not(str(obj['name']) in intfgroups.keys())):
        print_error("Found interface group " + str(obj['name']) + " in policy " + po.name + " but the interface group does not exist ...")
        exit(-1)
      po.intfgroup_add(intfgroups[str(obj['name'])])

# Find the interface with arg.oldname
if (not((args.oldname in interfaces_alias.keys()))):
  print_error("Cannot find interface name " + args.oldname + " in existing configuration ...")
  exit(-1)
interface = interfaces_alias[args.oldname]
print_info("Found interface " + args.oldname + " in existing configuration ...")

# Unconfigure the old interface name from interface group(s)
count_intfgroup = 0
print_info("Cleaning up interface groups ...")
for intfgroup in interface.ptr_intfgroups.itervalues():
  if (intfgroup.is_filter):
    g_rest_app_bigtap.filter_interface_group.match(name=intfgroup.name).filter_group.match(name=interface.iname).delete()
  else:
    g_rest_app_bigtap.delivery_interface_group.match(name=intfgroup.name).delivery_group.match(name=interface.iname).delete()
  print_info("Removed " + interface.iname + " from interface group " + intfgroup.name + " ...")
  count_intfgroup += 1

# Unconfigure the old interface name from policy(s)
count_policy = 0
print_info("Cleaning up policies ...")
for policy in interface.ptr_policies.itervalues():
  if (interface.role == "filter"):
    g_rest_app_bigtap.view.policy.match(name=policy.name).filter_group.match(name=interface.iname).delete()
  else:
    g_rest_app_bigtap.view.policy.match(name=policy.name).delivery_group.match(name=interface.iname).delete()
  print_info("Removed " + interface.iname + " from policy " + policy.name + " ...")
  count_policy += 1

# Unconfigure the old interface name from switch->interface
print_info("Cleaning up switch->interface ...")
switch = interface.ptr_switch
g_rest_app_bigtap.interface_config.match(interface=interface.name, switch=switch.dpid).delete()
print_info("Removed 'bigtap role' from switch " + switch.dpid + " interface " + interface.name)

# Update the interface name to newly provided one
interface.iname = args.newname

# Configure the new interface name into switch->interface
print_info("Updating switch->interface ...")
switch = interface.ptr_switch
if (interface.role == "filter"):
  if (interface.rewrite == -1):
    g_rest_app_bigtap.interface_config.match(interface=interface.name, switch=switch.dpid).put({
      'interface' : interface.name,
      'switch' : switch.dpid,
      'role' : interface.role,
      'name' : interface.iname,
      'analytics' : interface.analytics,
    })
  else:
    g_rest_app_bigtap.interface_config.match(interface=interface.name, switch=switch.dpid).put({
      'interface' : interface.name,
      'switch' : switch.dpid,
      'role' : interface.role,
      'name' : interface.iname,
      'rewrite-vlan' : interface.rewrite,
      'analytics' : interface.analytics,
    })
else:
  g_rest_app_bigtap.interface_config.match(interface=interface.name, switch=switch.dpid).put({
    'interface' : interface.name,
    'switch' : switch.dpid,
    'role' : interface.role,
    'name' : interface.iname,
  })
print_info("Added 'bigtap role' into switch " + switch.dpid + " interface " + interface.name)

# Configure the new interface name into policy(s)
print_info("Updating policies ...")
for policy in interface.ptr_policies.itervalues():
  if (interface.role == "filter"):
    g_rest_app_bigtap.view.policy.match(name=policy.name).filter_group.match(name=interface.iname).put({
      'name' : interface.iname,
    })
  else:
    g_rest_app_bigtap.view.policy.match(name=policy.name).delivery_group.match(name=interface.iname).put({
      'name' : interface.iname,
    })
  print_info("Added " + interface.iname + " into policy " + policy.name + " ...")

# Configure the new interface name into interface group(s)
print_info("Updating interface groups ...")
for intfgroup in interface.ptr_intfgroups.itervalues():
  if (intfgroup.is_filter):
    g_rest_app_bigtap.filter_interface_group.match(name=intfgroup.name).filter_group.match(name=interface.iname).put({
      'name' : interface.iname,
    })
  else:
    g_rest_app_bigtap.delivery_interface_group.match(name=intfgroup.name).delivery_group.match(name=interface.iname).put({
      'name' : interface.iname,
    })
  print_info("Added " + interface.iname + " into interface group " + intfgroup.name + " ...")

# Completed!!
print_info(str(count_intfgroup) + " interface group configuration(s) updated ...")
print_info(str(count_policy) + " policy configuration(s) updated ...")
print_info("Conversion from " + args.oldname + " to " + args.newname + " completed ...")

