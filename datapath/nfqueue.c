/*
 * Copyright (c) 2017 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/kconfig.h>
#include <linux/version.h>

//#if IS_ENABLED(CONFIG_NETFILTER_NETLINK_QUEUE)

#include <linux/module.h>
#include <linux/openvswitch.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/sctp.h>
#include <net/ip.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_queue.h>
#include <uapi/linux/netfilter_bridge.h>

#include "datapath.h"
#include "nfqueue.h"
#include "flow.h"
#include "flow_netlink.h"
#include "gso.h"

struct ovs_nfqueue_len_tbl {
	int maxlen;
	int minlen;
};

/* NFQueue action context for execution. */
struct ovs_nfqueue_info {
	u16 nfqueue;
};



/* This is called to initialize CT key fields possibly coming in from the local
 * stack.
 */
void ovs_nfqueue_fill_key(const struct sk_buff *skb, struct sw_flow_key *key)
{
	//TODO ANSIS
}

int ovs_nfqueue_put_key(const struct sw_flow_key *swkey,
		   const struct sw_flow_key *output, struct sk_buff *skb)
{
	if (nla_put_u16(skb, OVS_KEY_ATTR_NFQUEUE_ID, output->nfqueue))
		return -EMSGSIZE;

	return 0;
}


static const struct ovs_nfqueue_len_tbl ovs_nfqueue_attr_lens[OVS_NFQUEUE_ATTR_MAX + 1] = {
	[OVS_NFQUEUE_ATTR_QUEUE_ID]	= { .minlen = sizeof(u16),
					    .maxlen = sizeof(u16) }
};

static int parse_nfqueue(const struct nlattr *attr, struct ovs_nfqueue_info *info,
			 bool log)
{
	struct nlattr *a;
	int rem;

	nla_for_each_nested(a, attr, rem) {
		int type = nla_type(a);
		int maxlen = ovs_nfqueue_attr_lens[type].maxlen;
		int minlen = ovs_nfqueue_attr_lens[type].minlen;

		if (type > OVS_NFQUEUE_ATTR_MAX) {
			OVS_NLERR(log,
				  "Unknown nfqueue attr (type=%d, max=%d)",
				  type, OVS_NFQUEUE_ATTR_MAX);
			return -EINVAL;
		}
		if (nla_len(a) < minlen || nla_len(a) > maxlen) {
			OVS_NLERR(log,
				  "NFQUEUE attr type has unexpected length (type=%d, length=%d, expected=%d)",
				  type, nla_len(a), maxlen);
			return -EINVAL;
		}

		switch (type) {
		case OVS_NFQUEUE_ATTR_QUEUE_ID:
			info->nfqueue = nla_get_u16(a);
			break;
		default:
			OVS_NLERR(log, "Unknown nfqueue attr (%d)",
				  type);
			return -EINVAL;
		}
	}

	if (rem > 0) {
		OVS_NLERR(log, "NFqueue attr has %d unknown bytes", rem);
		return -EINVAL;
	}

	return 0;
}

bool ovs_nfqueue_verify(struct net *net, enum ovs_key_attr attr)
{
	if (attr == OVS_KEY_ATTR_NFQUEUE_ID)
		return true;

	return false;
}




int ovs_nfqueue_copy_action(struct net *net, const struct nlattr *attr,
		       const struct sw_flow_key *key,
		       struct sw_flow_actions **sfa,  bool log)
{
	struct ovs_nfqueue_info nfqueue_info;
	int err;

	memset(&nfqueue_info, 0, sizeof(nfqueue_info));
	//nfqueue_info.nfqueue = family;

	//nf_ct_zone_init(&ct_info.zone, NF_CT_DEFAULT_ZONE_ID,
	//		NF_CT_DEFAULT_ZONE_DIR, 0);

	err = parse_nfqueue(attr, &nfqueue_info, log);
	if (err)
		return err;

	err = ovs_nla_add_action(sfa, OVS_ACTION_ATTR_NFQUEUE, &nfqueue_info,
				 sizeof(nfqueue_info), log);
	if (err)
		return err;

	return 0;
}

int ovs_nfqueue_action_to_attr(const struct ovs_nfqueue_info *nfqueue_info,
			  struct sk_buff *skb)
{
	struct nlattr *start;

	start = nla_nest_start(skb, OVS_ACTION_ATTR_NFQUEUE);
	if (!start)
		return -EMSGSIZE;

	if (nla_put_u16(skb, OVS_NFQUEUE_ATTR_QUEUE_ID, nfqueue_info->nfqueue))
		return -EMSGSIZE;
	nla_nest_end(skb, start);

	return 0;
}

int okfn(struct net *net, struct sock *sk, struct sk_buff *skb) {
  return 0;
}

/* Returns 0 on success, -EINPROGRESS if 'skb' is stolen, or other nonzero
 * value if 'skb' is freed.
 */
int ovs_nfqueue_execute(struct net *net, struct sk_buff *skb,
		   struct sw_flow_key *key,
		   const struct ovs_nfqueue_info *info)
{
	int err = 0;
	struct nf_queue_entry *queue_entry = NULL;
	const struct nf_afinfo *afinfo = NULL;
	struct nf_hook_state hook_state;
	int nh_ofs;
	unsigned short pf = NFPROTO_IPV4;
	int hook = NF_INET_PRE_ROUTING;

	nf_hook_state_init(&hook_state, //nf_hook_state *p
		   &net->nf.hooks[pf][hook], //list_head *hook_list
		   hook, //unsigned int hook
		   INT_MIN, //int thresh
		   pf, //u_int8_t pf
		   skb->dev, //net_device *indev
		   NULL, //net_device *outdev
		   NULL, //sock *sk
		   net, //net *net
		   okfn); //int (*okfn)(struct net *, struct sock *, struct sk_buff *))

	/* The nfqueue module expects to be working at L3. */
	nh_ofs = skb_network_offset(skb);
	skb_pull_rcsum(skb, nh_ofs);


	afinfo = nf_get_afinfo(hook_state.pf);
	if (!afinfo) {
		printk(KERN_ERR " afinfo==%p for %u \n", afinfo, hook_state.pf);
		return err;
	}

	queue_entry = kmalloc(sizeof(*queue_entry) + afinfo->route_key_size,
			      GFP_ATOMIC);
	*queue_entry = (struct nf_queue_entry) {
	      .skb    = skb, //sk_buff;
	      .id     = 0, //unsigned int
	      .elem   = list_entry_rcu(hook_state.hook_list, struct nf_hook_ops, list), //nf_hook_ops*
	      .state  = hook_state, //nf_hook_state
	      .size   = sizeof(*queue_entry) + afinfo->route_key_size,
	};
	afinfo->saveroute(skb, queue_entry);

	nf_reinject(queue_entry, NF_QUEUE);

	return err;
}

void ovs_nfqueue_free_action(const struct nlattr *a)
{

}

//#endif /* CONFIG_NF_CONNTRACK */
