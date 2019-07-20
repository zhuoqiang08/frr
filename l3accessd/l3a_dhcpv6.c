#include "lib/zebra.h"

#include "lib/typesafe.h"
#include "lib/log.h"
#include "lib/privs.h"
#include "lib/thread.h"
#include "lib/network.h"
#include "lib/table.h"
#include "lib/prefix.h"
#include "lib/nexthop.h"

#include "l3a.h"

#include <net/ethernet.h>
#include <netpacket/packet.h>

#include <linux/filter.h>

/* 'ip6 and udp and (port 546 or port 547)' */
static struct sock_filter dhcpv6filter[] = {
	{ 0x28, 0, 0, 0x0000000c },
	{ 0x15, 0, 9, 0x000086dd },
	{ 0x30, 0, 0, 0x00000014 },
	{ 0x15, 0, 7, 0x00000011 },
	{ 0x28, 0, 0, 0x00000036 },
	{ 0x15, 4, 0, 0x00000222 },
	{ 0x15, 3, 0, 0x00000223 },
	{ 0x28, 0, 0, 0x00000038 },
	{ 0x15, 1, 0, 0x00000222 },
	{ 0x15, 0, 1, 0x00000223 },
	{ 0x6, 0, 0, 0x00040000 },
	{ 0x6, 0, 0, 0x00000000 },
};

static struct sock_fprog dhcpv6bpf = {
	.len = array_size(dhcpv6filter),
	.filter = dhcpv6filter,
};

extern struct zebra_privs_t l3a_privs;
extern struct thread_master *master;

static int l3a_dhcpv6_read(struct thread *t)
{
	struct l3a_if *l3a_if = THREAD_ARG(t);
	struct sockaddr_ll sll;
	socklen_t slen = sizeof(sll);
	uint8_t buf[65536];
	ssize_t nread;

	thread_add_read(master, l3a_dhcpv6_read, l3a_if, l3a_if->snoop_fd,
			&l3a_if->snoop_thread);

	nread = recvfrom(l3a_if->snoop_fd, buf, sizeof(buf), 0,
			 (struct sockaddr *)&sll, &slen);
	if (nread <= 0) {
		zlog_warn("read from %s failed (%zd): %m",
			  l3a_if->ifp->name, nread);
		return 0;
	}

	zlog_info("DHCPv6 packet on %s", l3a_if->ifp->name);
	return 0;
}

void l3a_dhcpv6_snoop(struct l3a_if *l3a_if)
{
	int fd;

	if (l3a_if->ifp->ifindex == IFINDEX_INTERNAL) {
		zlog_warn("cannot snoop %s - does not exist", l3a_if->ifp->name);
		return;
	}
	if (l3a_if->snoop_fd != -1) {
		zlog_warn("already snooping %s", l3a_if->ifp->name);
		return;
	}

	frr_elevate_privs (&l3a_privs) {
		struct sockaddr_ll sll;
		struct packet_mreq mr;

		fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
		if (fd < 0) {
			zlog_warn("socket(PF_PACKET) failed: %m");
			return;
		}

		if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER,
			       &dhcpv6bpf, sizeof(dhcpv6bpf))) {
			zlog_warn("SO_ATTACH_FILTER failed: %m");
			close(fd);
			return;
		}

		memset(&sll, 0, sizeof(sll));
		sll.sll_family = AF_PACKET;
		sll.sll_protocol = htons(ETH_P_ALL);
		sll.sll_ifindex = l3a_if->ifp->ifindex;

		if (bind(fd, (struct sockaddr *)(&sll), sizeof(sll))) {
			zlog_warn("bind(PF_PACKET) failed: %m");
			close(fd);
			return;
		}

		memset(&mr, 0, sizeof(mr));
		mr.mr_ifindex = l3a_if->ifp->ifindex;
		mr.mr_type = PACKET_MR_PROMISC;

		if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP,
			       &mr, sizeof(mr))) {
			zlog_warn("PACKET_ADD_MEMBERSHIP failed: %m");
			close(fd);
			return;
		}
	}
	set_nonblocking(fd);

	l3a_if->snoop_fd = fd;

	thread_add_read(master, l3a_dhcpv6_read, l3a_if, fd,
			&l3a_if->snoop_thread);
	zlog_info("iface %s snoopfd %d", l3a_if->ifp->name, fd);
}
