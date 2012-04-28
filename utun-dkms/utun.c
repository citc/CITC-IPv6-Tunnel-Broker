/*
 # Copyright (C) CITC, Communications and Information Technology Commission,
 # Kingdom of Saudi Arabia.
 #
 # Developed by CITC Tunnel Broker team, tunnelbroker@citc.gov.sa.
 #
 # This software is released to public domain under GNU General Public License
 # version 2, June 1991. Please see file 'LICENSE' in source code repository
 # root.
 */

#define DRV_NAME        "utun"
#define DRV_VERSION     "1.0"
#define DRV_DESCRIPTION "IPv6 over UDP/IPv4 tunnel driver"
#define DRV_COPYRIGHT   "(C) Communications and Information Technology Commission, www.citc.gov.sa"
#define DRV_AUTHOR      "tunnelbroker@citc.gov.sa"
#define TSP_NIBBLE      ((unsigned char)0xF0)

#define IPHDR_SIZE      (sizeof(struct iphdr))
#define UDPHDR_SIZE     (sizeof(struct udphdr))
#define ENCAPHDR_SIZE   (IPHDR_SIZE + UDPHDR_SIZE)

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>
#include <linux/init.h>

#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/if_ether.h>    /* For the statistics structure. */
#include <linux/if_arp.h>      /* For ARPHRD_ETHER */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/percpu.h>
#include <net/net_namespace.h>
#include <net/udp.h>
#include <net/route.h>
#include <net/ipv6.h>
#include <linux/netfilter_ipv6.h>

struct utun_struct {
    struct net_device *dev;
    struct iphdr iph;
    struct udphdr udp_header;
    char   source_mac[16];
    int    init;
};

static netdev_tx_t utun_xmit(struct sk_buff *skb, struct net_device *dev)
{
    int len, retval;
    struct iphdr *iph;
    struct udphdr *udp_header;
    struct sk_buff *skb_new = NULL;
    struct in_device *our_in_device;
    struct in_ifaddr *our_in_ifaddr;

    struct utun_struct *utun = netdev_priv(dev);

    if (!utun->init) {
        if (!skb->dev) return NETDEV_TX_BUSY; 

        our_in_device = (struct in_device *)skb->dev->ip_ptr;
        if (!our_in_device) return NETDEV_TX_BUSY;

        our_in_ifaddr = our_in_device->ifa_list;
        if (!our_in_ifaddr) return NETDEV_TX_BUSY;

        memcpy((void *)&(utun->iph.saddr), (const void *)&(our_in_ifaddr->ifa_local), 4);
        utun->iph.id = ~(utun->udp_header.dest);
        utun->init = 1;
        printk(KERN_INFO "%s: init with self: %d.%d.%d.%d:%d, peer: %d.%d.%d.%d:%d, dev->ifindex %p.\n", skb->dev->name, NIPQUAD(utun->iph.saddr), ntohs(utun->udp_header.source), NIPQUAD(utun->iph.daddr), ntohs(utun->udp_header.dest), (void *)dev->ifindex );
    }

    iph = ip_hdr(skb);
    udp_header = (struct udphdr *)(skb->data + ip_hdrlen(skb));

    /*
     * If this is IPv4, we gain 28 bytes (at least) using skb_pull so there 
     * should be no need to skb_alloc a new skb and then memcpy. 
     * ip6_route_me_harder seems to avoid netif_receive_skb panicing.
     */

    /* XXX: check if length and other sanity check are required */
    if (iph->version == 4) {   
        len  = ip_hdrlen(skb) + 8;
        if ( (TSP_NIBBLE & *(skb->data + len)) == TSP_NIBBLE ) {
            if ( likely((retval = netif_receive_skb(skb)) == NET_RX_SUCCESS) ) {
                dev->stats.rx_bytes += skb->len;
                dev->stats.rx_packets++;
            } else {
                dev->stats.rx_dropped++;
            }

        } else {

            skb_pull(skb, len);
            skb->protocol = htons(ETH_P_IPV6);
            skb->pkt_type = PACKET_HOST;
            (skb_dst(skb))->hh = NULL;
            skb_reset_mac_header(skb);
            skb_reset_network_header(skb);
            skb_reset_transport_header(skb);

            /* we must drop non-IPv6 traffic, until we handle it 
             * properly here 
             */
            iph = ip_hdr(skb);
            if (iph->version != 6)
                goto out;

/* If there are no IPv6 addressed interfaces or IPv6
   routes, netif_rx and subsequent calls cause panic,
   so return value from ip6_route_me_harder() must be
   checked.
*/

            if ((retval = ip6_route_me_harder(skb)) != 0) {
                dev->stats.rx_dropped++;
                goto out;
            }

            if ( likely((retval = netif_rx(skb)) == NET_RX_SUCCESS) ) {
                dev->stats.rx_bytes += skb->len;
                dev->stats.rx_packets++;
            } else {
                dev->stats.rx_dropped++;
            }
        }

        goto out;
    }

    /* 
     * If we have incoming IPv6 packet, it must be for our point-to-point 
     * peer (routing dictates this) so we'll encapsulate and send it. 
     * skbs are initialized with 16 bytes of headroom but we need at least 
     * 20 (IP header), so skb_alloc + memcpy is probably right thing to do here.
     */

    if (iph->version == 6) {
        if ( !(skb_new = dev_alloc_skb(skb->len + ENCAPHDR_SIZE + NET_IP_ALIGN)) ) {
            printk("%s: Could not alloc_skb for packet encapsulation.\n", skb->dev->name);
            dev->stats.tx_dropped++;
            goto out;
        }
        utun->udp_header.len = htons(UDPHDR_SIZE + skb->len);
        utun->iph.tot_len = htons(ntohs(utun->udp_header.len) + IPHDR_SIZE);
        skb_reserve(skb_new, NET_IP_ALIGN);
        skb_put(skb_new, skb->len + ENCAPHDR_SIZE);
        memcpy((void *)(skb_new->data), (const void *)&(utun->iph), IPHDR_SIZE);
        memcpy((void *)(skb_new->data + IPHDR_SIZE), (const void *)&(utun->udp_header), UDPHDR_SIZE);
        memcpy((void *)(skb_new->data + ENCAPHDR_SIZE), (const void *)(skb->data), skb->len);

        skb_new->protocol = htons(ETH_P_IP);
        skb_new->pkt_type = PACKET_HOST;
        skb_new->dev = utun->dev;
        skb_reset_network_header(skb_new);
        skb_new->mark = skb->mark;

        dev_kfree_skb(skb);

        iph = (struct iphdr *)skb_network_header(skb_new);
        iph->check = 0;
        iph->check = ip_fast_csum((unsigned char *)iph, (unsigned int)iph->ihl);
        ip_route_input(skb_new, iph->daddr, iph->saddr, iph->tos, utun->dev);

        if ( likely((retval = netif_rx(skb_new)) == NET_RX_SUCCESS) ) {
            // Don't count encapsulation overhead
            dev->stats.tx_bytes += skb_new->len - ENCAPHDR_SIZE;
            dev->stats.tx_packets++;
        } else {
            dev_kfree_skb(skb_new);
            dev->stats.tx_dropped++;
        }
    }

out:
    return NETDEV_TX_OK;
}

static u32 always_on(struct net_device *dev)
{
    return 1;
}

/*
static int utun_set_mac_address(struct net_device *dev, void* addr)
{
    struct sockaddr *address = addr;

    if (!is_valid_ether_addr(address->sa_data))
    return -EADDRNOTAVAIL;

    memcpy(dev->dev_addr, address->sa_data, dev->addr_len);
    printk("%s: MAC address set to %02x:%02x:%02x:%02x:%02x:%02x.\n", dev->name, *dev->dev_addr, *(dev->dev_addr + 1), *(dev->dev_addr + 2), *(dev->dev_addr + 3), *(dev->dev_addr + 4), *(dev->dev_addr + 5));

    return 0;
}
*/

static const struct ethtool_ops utun_ethtool_ops = {
    .get_link        = always_on,
    .set_tso         = ethtool_op_set_tso,
    .get_tx_csum     = always_on,
    .get_sg          = always_on,
    .get_rx_csum     = always_on,
};

static int utun_dev_init(struct net_device *dev)
{
    struct utun_struct *utun;
    char utun_devname[9];
    char *devname = dev->name;
    int i;
    char **endp = NULL;

    i = 0;
    utun = netdev_priv(dev);

    for (i = 0; *(devname + i) != '\0' && *(devname + i) != '_' && i < 8; i++) {
        utun_devname[i] = *(devname + i);
    }
    // i is set past separator after encoded IP address
    utun_devname[i++] = '\0'; 

    memset((void *)&utun->iph, 0, sizeof(utun->iph));
    memset((void *)&utun->udp_header, 0, sizeof(utun->udp_header));
    utun->iph.daddr = htonl(simple_strtoul(utun_devname, endp, 16));
    utun->udp_header.dest = htons(simple_strtoul(devname + i, endp, 10));

    utun->dev                = dev;
    utun->iph.ihl            = 5;
    utun->iph.version        = 4;
    utun->iph.ttl            = 0x42;
    utun->iph.protocol       = 17;          // UDP
    utun->udp_header.source  = htons(3653); // TSP port (RFC5572)
    utun->init               = 0;

    // random_ether_addr(dev->dev_addr);
    // random_ether_addr(utun->source_mac);

    printk(KERN_INFO "%s: ifname '%s', address %02x:%02x:%02x:%02x:%02x:%02x:00:00:00:00:00:00:00:00:00:00, source port %04d, remote = %d.%d.%d.%d:%04d, utun @ addr %p.\n", dev->name, devname, *dev->dev_addr, *(dev->dev_addr + 1), *(dev->dev_addr + 2), *(dev->dev_addr + 3), *(dev->dev_addr + 4), *(dev->dev_addr + 5), ntohs(utun->udp_header.source), NIPQUAD(utun->iph.daddr), ntohs(utun->udp_header.dest), utun);
    return 0;
}

static void utun_dev_free(struct net_device *dev)
{
    free_netdev(dev);
}

static const struct net_device_ops utun_netdev_ops = {
    .ndo_init            = utun_dev_init,
    .ndo_start_xmit      = utun_xmit,
    // .ndo_set_mac_address = utun_set_mac_address,
    // .ndo_validate_addr   = utun_validate_addr,
};

static void utun_setup(struct net_device *dev)
{
    /* 1280 for IPv6 + 28 (IPv4 header + 8 byte UDP header) */
    dev->mtu               = 1308;
    dev->hard_header_len   = ETH_HLEN;         /* 14 */
    dev->addr_len          = ETH_ALEN;         /* 6  */
    dev->tx_queue_len      = 0;
    dev->type              = ARPHRD_NONE;
    dev->flags             = IFF_POINTOPOINT | IFF_NOARP;
    dev->priv_flags       &= ~IFF_XMIT_DST_RELEASE;

    /* dev->features = * NETIF_F_SG 
     * | NETIF_F_FRAGLIST
     * | NETIF_F_TSO 
     * | NETIF_F_NO_CSUM
     * | NETIF_F_HIGHDMA
     * | NETIF_F_LLTX
     * | NETIF_F_NETNS_LOCAL;
    */

    dev->features          = NETIF_F_IP_CSUM | NETIF_F_NETNS_LOCAL;
    dev->ethtool_ops       = &utun_ethtool_ops;
    dev->netdev_ops        = &utun_netdev_ops;
    dev->destructor        = utun_dev_free;
}

static struct rtnl_link_ops utun_link_ops __read_mostly = {
    .kind      = DRV_NAME,
    .priv_size = sizeof(struct utun_struct),
    .setup     = utun_setup,
    /* .validate  = utun_validate, */
};

static int __init utun_init(void)
{
    int ret = 0;

    printk(KERN_INFO "utun: %s, %s\n", DRV_DESCRIPTION, DRV_VERSION);
    printk(KERN_INFO "utun: %s\n", DRV_COPYRIGHT);

    ret = rtnl_link_register(&utun_link_ops);
    if (ret) {
        printk(KERN_ERR "utun: Can't register link_ops\n");
        goto err_linkops;
    }

    return  0;
    rtnl_link_unregister(&utun_link_ops);

err_linkops:
    return ret;
}

static void utun_cleanup(void)
{
    rtnl_link_unregister(&utun_link_ops);
}

module_init(utun_init);
module_exit(utun_cleanup);
MODULE_DESCRIPTION(DRV_DESCRIPTION);
MODULE_AUTHOR(DRV_COPYRIGHT);
MODULE_LICENSE("GPL");
