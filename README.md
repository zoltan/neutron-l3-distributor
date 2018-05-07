The daemon syncs neutron's per-hypervisor IP view on the actual hypervisors. For each IP that neutron hands out to a VM it makes a /32 on-link entry into routing table 10 on each hypervisor.

First you need to create a view for the daemon to use:

create view l3_ip_allocations_per_hypervisor as select ipallocations.ip_address,ipallocations.network_id,ml2_port_bindings.host from ipallocations inner join ml2_port_bindings on ml2_port_bindings.port_id=ipallocations.port_id

Then change all the constants at the beginning of the daemon (ssh key, host, network...)

It also presumes that on the hypervisors you redistribute the contents of table 10 to your BGP/OSPF/etc fabric.
