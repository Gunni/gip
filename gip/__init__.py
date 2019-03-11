#!/usr/bin/env python3

import sys, argparse, ipaddress as IP
from colorclass import Color

class TooManyException(ValueError):
	def __init__(self) -> ValueError:
		super(TooManyException, self).__init__('> 2^8 (256) addresses, refusing to print, force with --force')

class CannotParseIPException(ValueError):
	def __init__(self, message) -> ValueError:
		super(CannotParseIPException, self).__init__(message)

def decodeBits(net: [IP.IPv4Interface, IP.IPv6Interface]) -> str:
	if net.network.is_multicast:   return 'Multicast'
	if net.network.is_unspecified: return 'Unspecified'
	if net.network.is_loopback:    return 'Loopback'
	if net.network.is_link_local:  return 'Link local'
	if net.network.is_private:     return 'Private'
	return 'Global'

def formatKeyVal(key: str, value: object, pre: str = '') -> str:
	return '{pre}{key: <{padding}} - {value}\n'.format(
		pre = pre,
		padding = 15,
		key = str(key),
		value = Color('{red}{}{/red}').format(value)
	)

def format_network(net: [IP.IPv4Interface, IP.IPv6Interface]) -> str:
	res = ''

	if net.version == 4:
		colored_version = Color('{magenta}4{/magenta}')
	else:
		colored_version = Color('{green}6{/green}')

	res += '[IPv{version} Network] {type} address\n'.format(version = colored_version, type = decodeBits(net))
	res += formatKeyVal('IP address', net.ip)
	res += formatKeyVal('Network address', net.network)

	if net.version == 4:  # never used for IPv6
		res += formatKeyVal('Subnet mask', net.netmask, pre = '\n')
		res += formatKeyVal('Wildcard mask', net.hostmask)

	if net.network.num_addresses > 2:
		res += formatKeyVal('Network range', (net.network.network_address).exploded, pre = '\n')
		res += formatKeyVal('', (net.network.broadcast_address).exploded)
	else:
		res += formatKeyVal('Network range', 'Literally one address', pre = '\n')

	if net.network.num_addresses > 2:
		res += formatKeyVal('Usable range', (net.network.network_address + 1).exploded, pre = '\n')
		res += formatKeyVal('', (net.network.broadcast_address - 1).exploded)
	else:
		res += formatKeyVal('Usable range', 'Same as Network range due to network size', pre = '\n')

	return res

def list_ips(net: [IP.IPv4Interface, IP.IPv6Interface], force: bool) -> [IP.IPv4Network, IP.IPv6Network]:
	if net.network.num_addresses > 2 ** 8 and force == False:
		raise TooManyException()

	return net.network

def parse_args(args):
	parser = argparse.ArgumentParser(
		description = 'Parse an IP address of any version and display useful information about it.')
	parser.add_argument('ip', nargs = '+', help = 'An IPv4 or IPv6 address or subnet')
	parser.add_argument('--list', '-l', action = 'store_true', help = 'Just list all the IPs in the subnet')
	parser.add_argument('--force', action = 'store_true', help = 'Force list all ips for large subnets')

	return parser.parse_args(args[1:])


def combine_args(values) -> str:
	return '/'.join(values)


def parse_ip(arg: str) -> [IP.IPv4Interface, IP.IPv6Interface]:
	try:
		return IP.ip_interface(arg)
	except ValueError as e:
		raise CannotParseIPException(str(e)) from e
