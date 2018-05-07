from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Integer, String, Text, Binary, Column
import sys, paramiko, time
import logging
import logging.handlers

# neutron network ID to watch for changes
# TODO: support multiple networks
NETWORK_TO_SYNC = 'your-neutron-network-id'

# ssh key to use to log in to hypervisors
SSH_KEY = '/opt/neutron-l3-distributor/id_rsa'

# mysql connection information
# TODO: support selecting TCP vs unix socket
MYSQL_HOST = 'localhost'
MYSQL_USERNAME='foo'
MYSQL_PASSWORD='bar'

# these magic constants come from neutron
BRIDGE_NAME_PREFIX = "brq"
RESOURCE_ID_LENGTH = 11

engine = create_engine('mysql://' + MYSQL_USERNAME + ':' + MYSQL_PASSWORD + '@' + MYSQL_HOST + '/neutron?unix_socket=/var/run/mysqld/mysqld.sock', echo=False)
Base = declarative_base(engine)

logger = logging.getLogger('MyLogger')
logger.setLevel(logging.DEBUG)
handler = logging.handlers.SysLogHandler(address = '/dev/log')
default_formatter = logging.Formatter("l3-bgp-distributor: %(asctime)s %(levelname)s %(message)s")
handler.setFormatter(default_formatter)
logger.addHandler(handler)

# the bridge name calculation comes from neutron
def get_bridge_name(network_id = NETWORK_TO_SYNC):
    bridge_name = BRIDGE_NAME_PREFIX + \
    network_id[:RESOURCE_ID_LENGTH]
    return bridge_name

def get_current_ips_for_host(host, network = NETWORK_TO_SYNC):
    return map(lambda x: x.split(' ')[0], run_command(host, "ip route show dev " + get_bridge_name(network) + " table 10"))

def run_command(host, command):
    try:
      client = paramiko.SSHClient()
      client.load_system_host_keys()
      client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
      client.connect(host, port=22, username="root", key_filename=SSH_KEY, timeout=5)
      stdin, stdout, stderr = client.exec_command(command)
      return stdout.readlines()
    except Exception as e:
      logger.error('run_command error occured: ' + str(e))
      return ""

def loadSession():
    metadata = Base.metadata
    Session = sessionmaker(bind=engine)
    session = Session()
    return session

class IPHypervisorBinding(Base):
  __tablename__ = 'l3_ip_allocations_per_hypervisor'
  __table_args__ = {'autoload': True}
  
  ip_address = Column(String, primary_key=True) 

  def __str__(self):
    return 'IPHypervisorBinding(IP: ' + self.ip_address + ', host: ' + self.host + ')'

def add_host_inventory(host, inventory):
  if host not in inventory:
    logger.debug('fetching IP routing information from host ' + host)
    inventory[host] = set(get_current_ips_for_host(host))
    logger.debug('IPs on host ' + host + ': ' + str(inventory[host]))

def add_desired_host_entry(host, ip, inventory):
  if host not in inventory:
    inventory[host] = set()
  inventory[host].add(ip)

def add_ip_on_host(ip, host, network = NETWORK_TO_SYNC):
  logger.debug('adding ' + ip + ' on ' + host + ' as it is in neutron\'s database but not present on the host')
  run_command(host, 'ip route add ' + ip + ' dev ' + get_bridge_name(network) + ' table 10')

def remove_ip_on_host(ip, host, network = NETWORK_TO_SYNC):
  logger.debug('removing ' + ip + ' on ' + host  + ' as it is no longer in neutron\'s database')
  run_command(host, 'ip route del ' + ip + ' dev ' + get_bridge_name(network) + ' table 10')

if __name__ == "__main__":
  logger.info('L3 routing info distributor starting up!')
  previous_hosts = set()
  while True:
    ips_on_hosts = dict()
    desired_state = dict()

    session = loadSession()
    logger.info('fetching data from neutron\'s database')
    neutron_data = session.query(IPHypervisorBinding).filter(IPHypervisorBinding.network_id == NETWORK_TO_SYNC).all()
    logger.info('neutron\'s database had ' + str(len(neutron_data)) + ' entries')
    logger.info('fetching data from each host')
    for entry in neutron_data:
      add_host_inventory(entry.host, ips_on_hosts)
      add_desired_host_entry(entry.host, entry.ip_address, desired_state)

    empty_hosts = previous_hosts - set(desired_state.keys())

    if len(empty_hosts) > 0:
      logger.debug('the following hosts got empty: ' + str(empty_hosts))
      for host in empty_hosts:
        add_host_inventory(host, ips_on_hosts)
      for host in empty_hosts:
        for ip in ips_on_hosts[host]:
          remove_ip_on_host(ip, host)
      previous_hosts.clear()

    logger.info('correcting the routing mismatches')
    for host in desired_state:
      previous_hosts.add(host)
      missing_ips = desired_state[host] - ips_on_hosts[host]
      extra_ips = ips_on_hosts[host] - desired_state[host]

      for ip in missing_ips:
        add_ip_on_host(ip, host)

      for ip in extra_ips:
        remove_ip_on_host(ip, host)

    session.close()
    time.sleep(5)
