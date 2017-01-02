#!/usr/bin/env python3

import sys, argparse, ipaddress as IP


def decodeBits(net: [IP.IPv4Interface, IP.IPv6Interface]) -> str:
	if net.network.is_multicast:   return 'Multicast'
	if net.network.is_private:     return 'Private'
	if net.network.is_unspecified: return 'Unspecified'
	if net.network.is_loopback:    return 'Loopback'
	if net.network.is_link_local:  return 'Link local'
	return 'Global'


def printKeyVal(key: str, value: object, pre: str = '') -> None:
	print('{pre}{key: <{padding}} - {value}'.format(
		pre = pre,
		padding = 15,
		key = str(key),
		value = str(value))
	)


def displayNetwork(net: [IP.IPv4Interface, IP.IPv6Interface]) -> None:
	v = {'version': net.version, 'type': decodeBits(net)}
	print('[IPv{version} Network] {type} address'.format(**v))
	printKeyVal('IP address', net.ip)
	printKeyVal('Network address', net.network)

	if net.version == 4:  # never used for IPv6
		printKeyVal('Subnet mask'.format(**v), net.netmask, pre = '\n')
		printKeyVal('Wildcard mask'.format(**v), net.hostmask)

	if net.network.num_addresses > 2:
		printKeyVal('Network range', (net.network.network_address).exploded, pre = '\n')
		printKeyVal('', (net.network.broadcast_address).exploded)
	else:
		printKeyVal('Network range', 'Literally one address', pre = '\n')

	if net.network.num_addresses > 2:
		printKeyVal('Usable range', (net.network.network_address + 1).exploded, pre = '\n')
		printKeyVal('', (net.network.broadcast_address - 1).exploded)
	else:
		printKeyVal('Usable range', 'Same as Network range due to network size', pre = '\n')


def listAllIPs(net: [IP.IPv4Interface, IP.IPv6Interface], force: bool) -> None:
	if net.network.num_addresses > 2 ** 8 and force == False:
		sys.stderr.write('> 2^8 (256) addresses, refusing to print, force with --force')
		sys.exit(2)

	for ip in net.network:
		print(ip)


if __name__ == '__main__':
	try:
		parser = argparse.ArgumentParser(
			description = 'Parse an IP address of any version and display useful information about it.')
		parser.add_argument('ip', nargs = '*', help = 'An IPv4 or IPv6 address or subnet')
		parser.add_argument('--list', '-l', action = 'store_true', help = 'Just list all the IPs in the subnet')
		parser.add_argument('--force', action = 'store_true', help = 'Force list all ips for large subnets')
		args = parser.parse_args()
	except SystemExit:  # just to make sure it exits uncleanly on -h
		sys.exit(3)

	arg = '/'.join(args.ip)

	try:
		ipaddr = IP.ip_interface(arg)
	except ValueError as e:
		sys.stderr.write(str(e))
		sys.exit(1)

	if args.list:
		listAllIPs(ipaddr, args.force)
	else:
		displayNetwork(ipaddr)
