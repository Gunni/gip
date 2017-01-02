import gip
import ipaddress as IP


def bits(net, expected) -> None:
	n = IP.ip_interface(net)
	r = gip.decodeBits(n)
	assert r is not None
	assert r == expected


def test_bits() -> None:
	bits('224.0.0.0', 'Multicast')
	bits('ff01::1', 'Multicast')

	bits('0.0.0.0', 'Unspecified')
	bits('::', 'Unspecified')

	bits('127.0.0.1', 'Loopback')
	bits('::1', 'Loopback')

	bits('fe80::1', 'Link local')

	bits('10.0.0.0', 'Private')
	bits('fc00::1', 'Private')

	bits('1.0.0.1', 'Global')
	bits('1::1', 'Global')
