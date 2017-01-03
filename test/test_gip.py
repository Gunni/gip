import pytest as test
import gip
import re
from typing import Any, List
from termcolor import colored
import ipaddress as IP


def _bits(net, expected) -> None:
	n = IP.ip_interface(net)
	r = gip.decodeBits(n)
	assert r is not None
	assert r == expected


def test_bits() -> None:
	_bits('224.0.0.0', 'Multicast')
	_bits('ff01::1', 'Multicast')

	_bits('0.0.0.0', 'Unspecified')
	_bits('::', 'Unspecified')

	_bits('127.0.0.1', 'Loopback')
	_bits('::1', 'Loopback')

	_bits('fe80::1', 'Link local')

	_bits('10.0.0.0', 'Private')
	_bits('fc00::1', 'Private')

	_bits('1.0.0.1', 'Global')
	_bits('1::1', 'Global')


def _key_val(inputA: str, inputB: object, inputC: str, expected: str) -> None:
	n = gip.formatKeyVal(inputA, inputB, inputC)
	assert n is not None
	assert n == expected


def _key_val_color(value: str) -> str:
	return colored(str(value), 'red', attrs = ['bold'])


def test_format_key_val() -> None:
	_key_val('a', 'b', '', 'a{}- {}\n'.format(' ' * 15, _key_val_color('b')))
	_key_val('asd', 'b', '', 'asd{}- {}\n'.format(' ' * 13, _key_val_color('b')))
	_key_val('asd', 'bnm', '', 'asd{}- {}\n'.format(' ' * 13, _key_val_color('bnm')))


def test_list_ips_v4() -> None:
	n = gip.list_ips(IP.ip_interface('192.0.2.0/30'), False)
	assert n is not None
	assert n[0] == IP.ip_address('192.0.2.0')
	assert n[1] == IP.ip_address('192.0.2.1')
	assert n[2] == IP.ip_address('192.0.2.2')
	assert n[3] == IP.ip_address('192.0.2.3')
	with test.raises(IndexError, message = 'Should be out of bounds'):
		n[4]

	try:
		gip.list_ips(IP.ip_interface('192.0.2.0/23'), False)
	except gip.TooManyException:
		pass

	n = gip.list_ips(IP.ip_interface('192.0.2.0/23'), True)
	assert n is not None
	assert n[0] == IP.ip_address('192.0.2.0')
	assert n[511] == IP.ip_address('192.0.3.255')


def test_list_ips_v6() -> None:
	n = gip.list_ips(IP.ip_interface('2001:db8::/126'), False)
	assert n is not None
	assert n[0] == IP.ip_address('2001:db8::')
	assert n[1] == IP.ip_address('2001:db8::1')
	assert n[2] == IP.ip_address('2001:db8::2')
	assert n[3] == IP.ip_address('2001:db8::3')
	with test.raises(IndexError, message = 'Should be out of bounds'):
		n[4]

	with test.raises(gip.TooManyException):
		gip.list_ips(IP.ip_interface('2001:db8::/64'), False)

	n = gip.list_ips(IP.ip_interface('2001:db8::/119'), True)
	assert n is not None
	assert n[0] == IP.ip_address('2001:db8::')
	assert n[511] == IP.ip_address('2001:db8::1ff')

	with test.raises(IndexError, message = 'Should be out of bounds'):
		n[512]


def _parse_args(expectedList: bool, expectedForce: bool, expectedIP: List[str], args: List[Any]) -> None:
	l = ['A:/Development/gip/gip.py']
	l += args
	n = gip.parse_args(l)
	assert n is not None
	assert n.ip == expectedIP
	assert n.list == expectedList
	assert n.force == expectedForce

	n2 = gip.combine_args(n.ip)
	assert n2 is not None
	assert n2 == '/'.join(expectedIP)


def test_parse_args_empty(capsys) -> None:
	with test.raises(SystemExit):
		_parse_args(args = [], expectedIP = [], expectedList = False, expectedForce = False)

	out, err = capsys.readouterr()
	capsys.disabled()

	assert err is not None
	assert err == 'usage: pytestrunner.py [-h] [--list] [--force] ip [ip ...]\n' \
	              'pytestrunner.py: error: the following arguments are required: ip\n'


def test_parse_args() -> None:
	_parse_args(expectedList = False, expectedForce = False, expectedIP = ['::1'], args = ['::1'])
	_parse_args(expectedList = True, expectedForce = False, expectedIP = ['::1'], args = ['-l', '::1'])
	_parse_args(expectedList = True, expectedForce = True, expectedIP = ['::1'], args = ['-l', '--force', '::1'])

	_parse_args(expectedList = False, expectedForce = False, expectedIP = ['192.0.2.1', '255.255.255.0'],
	            args = ['192.0.2.1', '255.255.255.0'])


def _parse_ip(value: str, expectedIP: [IP.IPv4Interface, IP.IPv6Interface]) -> None:
	n = gip.parse_ip(value)
	assert n is not None
	assert n == expectedIP


def test_parse_ip() -> None:
	_parse_ip('::1', IP.ip_interface('::1'))
	with test.raises(gip.CannotParseIPException):
		_parse_ip('beikon', IP.ip_interface('::1'))

	_parse_ip('192.0.2.0/255.255.255.0', IP.ip_interface('192.0.2.0/24'))
	_parse_ip('192.0.2.0/24', IP.ip_interface('192.0.2.0/255.255.255.0'))


def _clean_color(value: str) -> str:
	ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -\/]*[@-~]')
	return ansi_escape.sub('', value)


def _format_network(value: str, expectedOutput: str) -> None:
	i = IP.ip_interface(value)
	n = gip.format_network(i)

	n = _clean_color(n)

	assert n is not None
	assert n == expectedOutput


def test_format_network() -> None:
	s = '[IPv4 Network] Private address\n' \
	    'IP address      - 192.0.2.42\n' \
	    'Network address - 192.0.2.0/24\n' \
	    '\n' \
	    'Subnet mask     - 255.255.255.0\n' \
	    'Wildcard mask   - 0.0.0.255\n' \
	    '\n' \
	    'Network range   - 192.0.2.0\n' \
	    '                - 192.0.2.255\n' \
	    '\n' \
	    'Usable range    - 192.0.2.1\n' \
	    '                - 192.0.2.254\n'
	_format_network('192.0.2.42/24', s)

	s = '[IPv6 Network] Private address\n' \
	    'IP address      - 2001:db8::1337\n' \
	    'Network address - 2001:db8::/64\n' \
	    '\n' \
	    'Network range   - 2001:0db8:0000:0000:0000:0000:0000:0000\n' \
	    '                - 2001:0db8:0000:0000:ffff:ffff:ffff:ffff\n' \
	    '\n' \
	    'Usable range    - 2001:0db8:0000:0000:0000:0000:0000:0001\n' \
	    '                - 2001:0db8:0000:0000:ffff:ffff:ffff:fffe\n'
	_format_network('2001:db8::1337/64', s)

	s = '[IPv6 Network] Private address\n' \
	    'IP address      - 2001:db8::1337\n' \
	    'Network address - 2001:db8::1337/128\n' \
	    '\n' \
	    'Network range   - Literally one address\n' \
	    '\n' \
	    'Usable range    - Same as Network range due to network size\n'
	_format_network('2001:db8::1337', s)
