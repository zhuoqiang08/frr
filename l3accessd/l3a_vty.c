#include "lib/zebra.h"

#include "lib/command.h"
#include "lib/vty.h"

#include "l3a.h"

#include "l3a_vty_clippy.c"

DEFPY(l3a_route_main,
      l3a_route_cmd,
      "ipv6 l3access route X:X::X:X/M lifetime (0-4294967295) via X:X::X:X interface IFACE",
      IPV6_STR
      "L3 access protocols\n"
      "Set up route\n"
      "Prefix\n"
      "Lifetime\n"
      "Lifetime (milliseconds)\n"
      "Nexthop\n"
      "Nexthop\n"
      "Interface\n"
      "Interface\n")
{
	union g_addr nexthop;
	nexthop.ipv6 = via;

	l3a_route_update(route, lifetime, &nexthop, iface, NULL, 0);
	return CMD_SUCCESS;
}

DEFPY(l3a_dhcpv6_main,
      l3a_dhcpv6_cmd,
      "ipv6 l3access dhcp-snoop IFACE",
      IPV6_STR
      "L3 access protocols\n"
      "DHCPv6 snooping\n"
      "Interface\n")
{
	l3a_dhcpv6_snoop(l3a_if_get_byname(iface));
	return CMD_SUCCESS;
}

void l3a_vty_init(void)
{
	install_element(ENABLE_NODE, &l3a_route_cmd);
	install_element(ENABLE_NODE, &l3a_dhcpv6_cmd);
}
