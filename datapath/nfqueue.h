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

#ifndef OVS_NFQUEUE_H
#define OVS_NFQUEUE_H 1

#include <linux/version.h>
#include "flow.h"

struct ovs_nfqueue_info;

/*
TODO: add these for matching

enum ovs_key_attr;
bool ovs_nfqueue_verify(struct net *, enum ovs_key_attr attr);
void ovs_nfqueue_fill_key(const struct sk_buff *skb, struct sw_flow_key *key);
int ovs_nfqueue_put_key(const struct sw_flow_key *swkey,
		   const struct sw_flow_key *output, struct sk_buff *skb);
*/

int ovs_nfqueue_copy_action(struct net *, const struct nlattr *,
			    const struct sw_flow_key *, struct sw_flow_actions **,
			    bool log);
int ovs_nfqueue_action_to_attr(const struct ovs_nfqueue_info *, struct sk_buff *);
int ovs_nfqueue_execute(struct net *, struct sk_buff *, struct sw_flow_key *,
			const struct ovs_nfqueue_info *);
void ovs_nfqueue_free_action(const struct nlattr *a);

#endif /* ovs_nfqueue.h */
