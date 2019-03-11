# gIP

Just a very simple but useful subnetting helper for IPs.

## Examples

Input: `192.0.2.0/24`

    [IPv4 Network] Private address
    IP address      - 192.0.2.0
    Network address - 192.0.2.0/24

    Subnet mask     - 255.255.255.0
    Wildcard mask   - 0.0.0.255

    Network range   - 192.0.2.0
                    - 192.0.2.255

    Usable range    - 192.0.2.1
                    - 192.0.2.254

Input: `2001:db8::abcd:1234`

    [IPv6 Network] Private address
    IP address      - 2001:db8::abcd:1234
    Network address - 2001:db8::/64

    Network range   - 2001:0db8:0000:0000:0000:0000:0000:0000
                    - 2001:0db8:0000:0000:ffff:ffff:ffff:ffff

    Usable range    - 2001:0db8:0000:0000:0000:0000:0000:0001
                    - 2001:0db8:0000:0000:ffff:ffff:ffff:fffe

Other alternate supported inputs:

- `192.0.2.0` (works like a /32)
- `192.0.2.0 255.255.255.0`
- `192.0.2.0/255.255.255.0`
- `2001:db8::` (works like a /128)
- `2001:db8::/64`
- `-l 192.0.2.0/28` (just lists all the IPs in the subnet (handy for loops))

## Exit codes

* 0: Clean exit
* 1: Cannot parse IP
* 2: List called with more than 2^8 IPs and not --force
* 3: Called with -h (help)

## Tests

Run using `python3 -m pytest`
