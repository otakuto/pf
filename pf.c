#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>

MODULE_LICENSE("GPL");
static int const PROXY_PORT = 15080;
static int const PROXY_ADDR = 0xAC10043C;

static unsigned handle_hook_out_raw(const struct nf_hook_ops * ops,
				struct sk_buff * skb,
				const struct net_device * in,
				const struct net_device * out,
				int (*okfn)(struct sk_buff*))
{
	struct iphdr * iph;
	iph = ip_hdr(skb);
	if (!iph)
	{
		return NF_ACCEPT;
	}
	if (iph->protocol != IPPROTO_TCP)
	{
		return NF_ACCEPT;
	}
	struct tcphdr * tcph;
	tcph = tcp_hdr(skb);

	if (be16_to_cpu(tcph->dest) == 80)
	{
		skb->mark = iph->daddr;
		iph->daddr = htonl(PROXY_ADDR);
		tcph->dest = htons(PROXY_PORT);
		int head_len = (iph->ihl + tcph->doff) << 2;
		int data_len = skb->len - head_len;
		printk(KERN_DEBUG "len skb:%d:head:%d:data:%d\n", skb->len, head_len, data_len);
		if (data_len && false)
		{
			char s[INET_ADDRSTRLEN + 7];
			int ret = snprintf(s, INET_ADDRSTRLEN + 7, "http://%pI4", &skb->mark);
			if (ret < 0)
			{
				return NF_DROP;
			}
			/*if (head_len < data_len)
			{
				char * data = skb->data;
				skb_push(skb, ret);
				memmove(skb->data, data, head_len);
				strncpy(skb->data + head_len, s, ret);
				iph = ip_hdr(skb);
				tcph = tcp_hdr(skb);
			}
			else*/
			{
				/*
				char * tail = skb->tail;
				skb_put(skb, ret);
				memmove(skb->tail - data_len, tail - data_len, data_len);
				strncpy(tail - data_len, s, ret);
				*/
				skb_put(skb, ret);
				//memmove(skb->tail - data_len + ret, skb->tail - data_len, data_len);
				//strncpy(skb->tail - data_len, s, ret);
				printk(KERN_DEBUG "%s:%d\n", s, ret);
				//printk(KERN_DEBUG "%c:\n", *(skb->data + head_len + 4));
				memmove(skb->data + head_len + ret + 4, skb->data + head_len + 4, data_len - 4);
				memcpy(skb->data + head_len + 4, s, ret);
			}
			iph->tot_len = htons(ntohs(iph->tot_len) + ret);
		}

		enum ip_conntrack_info ctinfo;
		struct nf_conn * ct;
		ct = nf_ct_get(skb, &ctinfo);
		if (ct)
		{
			printk(KERN_DEBUG "raw ct\n");
		}
		//skb->data[(iph->ihl + tcph->doff) << 2] = 'E';
		//calc check sum
		int tcplen = skb->len - (iph->ihl << 2);
		tcph->check = 0;
		tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,
						csum_partial((unsigned char *)tcph, tcplen, 0));
		skb->ip_summed = CHECKSUM_NONE;
		iph->check = 0;
		ip_send_check(iph);
	}
	else if (be16_to_cpu(tcph->dest) == 443)
	{
		printk(KERN_DEBUG "https\n");
		skb->mark = iph->daddr;
		iph->daddr = htonl(PROXY_ADDR);
		tcph->dest = htons(PROXY_PORT);

		int tcplen = skb->len - (iph->ihl << 2);
		tcph->check = 0;
		tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,
						csum_partial((unsigned char *)tcph, tcplen, 0));
		skb->ip_summed = CHECKSUM_NONE;
		iph->check = 0;
		ip_send_check(iph);
	}

	return NF_ACCEPT;
}
static unsigned handle_hook_out(const struct nf_hook_ops * ops,
				struct sk_buff * skb,
				const struct net_device * in,
				const struct net_device * out,
				int (*okfn)(struct sk_buff*))
{
	struct iphdr * iph = ip_hdr(skb);
	if (!iph)
	{
		return NF_ACCEPT;
	}
	if (iph->protocol != IPPROTO_TCP)
	{
		return NF_ACCEPT;
	}
	struct tcphdr * tcph = tcp_hdr(skb);

	if (be16_to_cpu(tcph->dest) == PROXY_PORT)
	{
		enum ip_conntrack_info ctinfo;
		struct nf_conn * ct;
		ct = nf_ct_get(skb, &ctinfo);
		if (!ct)
		{
			return NF_ACCEPT;
		}

		printk(KERN_DEBUG "status:%d\n", ct->status);
		if (skb->mark)
		{
			ct->mark = skb->mark;
			char s[INET_ADDRSTRLEN];
			snprintf(s, INET_ADDRSTRLEN, "%pI4", &ct->mark);
			printk(KERN_DEBUG "daddr:%s\n", s);
			nf_conntrack_event_cache(IPCT_MARK, ct);
		}
	}

	return NF_ACCEPT;
}

static unsigned handle_hook_in(const struct nf_hook_ops * ops,
				struct sk_buff * skb,
				const struct net_device * in,
				const struct net_device * out,
				int (*okfn)(struct sk_buff*))
{
	struct iphdr * iph = ip_hdr(skb);
	if (!iph)
	{
		return NF_ACCEPT;
	}
	if (iph->protocol != IPPROTO_TCP)
	{
		return NF_ACCEPT;
	}
	enum ip_conntrack_info ctinfo;
	struct nf_conn * ct;
	ct = nf_ct_get(skb, &ctinfo);
	if (!ct)
	{
		return NF_ACCEPT;
	}
	iph->saddr = ct->mark;
	printk(KERN_DEBUG "in ct mark:%d\n", ct->mark);
	struct tcphdr * tcph = tcp_hdr(skb);
	//tcph->source = htons(80);
	//tcph->source = htons(443);
	int tcplen = (skb->len - (iph->ihl << 2));
	tcph->check = 0;
	tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr,
					csum_partial((unsigned char *)tcph, tcplen, 0));
	skb->ip_summed = CHECKSUM_NONE;
	iph->check = 0;
	ip_send_check(iph);

	char s[INET_ADDRSTRLEN];
	snprintf(s, INET_ADDRSTRLEN, "%pI4", &ct->mark);
	printk(KERN_DEBUG "daddr:%s\n", s);
	return NF_ACCEPT;
}

static struct nf_hook_ops hook_ops_out_raw = {
	.hook = handle_hook_out_raw,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_RAW,
};

static struct nf_hook_ops hook_ops_out = {
	.hook = handle_hook_out,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FILTER,
};

static struct nf_hook_ops hook_ops_in = {
	.hook = handle_hook_in,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FILTER,
};

int init_module()
{
	int err = nf_register_hook(&hook_ops_out);
	if (err < 0)
	{
		return err;
	}
	err = nf_register_hook(&hook_ops_out_raw);
	if (err < 0)
	{
		return err;
	}
	err = nf_register_hook(&hook_ops_in);
	if (err < 0)
	{
		return err;
	}
	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&hook_ops_out);
	nf_unregister_hook(&hook_ops_out_raw);
	nf_unregister_hook(&hook_ops_in);
}

