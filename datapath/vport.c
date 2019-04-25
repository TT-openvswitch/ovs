/*
 * Copyright (c) 2007-2015 Nicira, Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/etherdevice.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/jhash.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/rtnetlink.h>
#include <linux/compat.h>
#include <linux/module.h>
#include <linux/if_link.h>
#include <net/net_namespace.h>
#include <net/lisp.h>
#include <net/gre.h>
#include <net/geneve.h>
#include <net/vxlan.h>
#include <net/stt.h>
#include <linux/ktime.h>

#include "datapath.h"
#include "gso.h"
#include "vport.h"
#include "vport-internal_dev.h"
#include "tt.h"

static LIST_HEAD(vport_ops_list);

/* Protected by RCU read lock for reading, ovs_mutex for writing. */
static struct hlist_head *dev_table;
#define VPORT_HASH_BUCKETS 1024

/**
 *	ovs_vport_init - initialize vport subsystem
 *
 * Called at module load time to initialize the vport subsystem.
 */
int ovs_vport_init(void)
{
	int err;

	dev_table = kzalloc(VPORT_HASH_BUCKETS * sizeof(struct hlist_head),
			    GFP_KERNEL);
	if (!dev_table)
		return -ENOMEM;

	err = lisp_init_module();
	if (err)
		goto err_lisp;
	err = ipgre_init();
	if (err)
		goto err_gre;
	err = geneve_init_module();
	if (err)
		goto err_geneve;

	err = vxlan_init_module();
	if (err)
		goto err_vxlan;
	err = ovs_stt_init_module();
	if (err)
		goto err_stt;
	return 0;

err_stt:
	vxlan_cleanup_module();
err_vxlan:
	geneve_cleanup_module();
err_geneve:
	ipgre_fini();
err_gre:
	lisp_cleanup_module();
err_lisp:
	kfree(dev_table);
	return err;
}

/**
 *	ovs_vport_exit - shutdown vport subsystem
 *
 * Called at module exit time to shutdown the vport subsystem.
 */
void ovs_vport_exit(void)
{
	ovs_stt_cleanup_module();
	vxlan_cleanup_module();
	geneve_cleanup_module();
	ipgre_fini();
	lisp_cleanup_module();
	kfree(dev_table);
}

static struct hlist_head *hash_bucket(const struct net *net, const char *name)
{
	unsigned int hash = jhash(name, strlen(name), (unsigned long) net);
	return &dev_table[hash & (VPORT_HASH_BUCKETS - 1)];
}

int __ovs_vport_ops_register(struct vport_ops *ops)
{
	int err = -EEXIST;
	struct vport_ops *o;

	ovs_lock();
	list_for_each_entry(o, &vport_ops_list, list)
		if (ops->type == o->type)
			goto errout;

	list_add_tail(&ops->list, &vport_ops_list);
	err = 0;
errout:
	ovs_unlock();
	return err;
}
EXPORT_SYMBOL_GPL(__ovs_vport_ops_register);

void ovs_vport_ops_unregister(struct vport_ops *ops)
{
	ovs_lock();
	list_del(&ops->list);
	ovs_unlock();
}
EXPORT_SYMBOL_GPL(ovs_vport_ops_unregister);

/**
 *	ovs_vport_locate - find a port that has already been created
 *
 * @name: name of port to find
 *
 * Must be called with ovs or RCU read lock.
 */
struct vport *ovs_vport_locate(const struct net *net, const char *name)
{
	struct hlist_head *bucket = hash_bucket(net, name);
	struct vport *vport;

	hlist_for_each_entry_rcu(vport, bucket, hash_node)
		if (!strcmp(name, ovs_vport_name(vport)) &&
		    net_eq(ovs_dp_get_net(vport->dp), net))
			return vport;

	return NULL;
}

static int ovs_vport_tt_schedule_info_alloc(struct vport *vport)
{
	if (likely(!(vport->tt_schedule_info))) {
		struct tt_schedule_info *schedule_info = tt_schedule_info_alloc(vport);
		if (!schedule_info)
			return -ENOMEM;
		vport->tt_schedule_info = schedule_info;
	}
	return 0;
}

/** hrtimer cancel **/
static void ovs_vport_hrtimer_cancel(struct vport *vport) 
{
	int cancelled = 1;
	if (!(vport->tt_schedule_info))
		return;
	if (1 == vport->tt_schedule_info->hrtimer_flag) {
		vport->tt_schedule_info->hrtimer_flag = 0;
		while (cancelled) {
			cancelled = hrtimer_cancel(&vport->tt_schedule_info->timer);
			pr_info("HRTIMER: hrtimer is running.");
		}
		pr_info("HRTIMER: hrtimer cancelled.");
	}
}

void ovs_vport_finish_tt_schedule(struct vport *vport)
{
	ovs_vport_hrtimer_cancel(vport);
	tt_schedule_info_free(vport->tt_schedule_info);
	vport->tt_schedule_info = NULL; /* after free, should point to NULL */
}

/**
 *	ovs_vport_alloc - allocate and initialize new vport
 *
 * @priv_size: Size of private data area to allocate.
 * @ops: vport device ops
 *
 * Allocate and initialize a new vport defined by @ops.  The vport will contain
 * a private data area of size @priv_size that can be accessed using
 * vport_priv().  vports that are no longer needed should be released with
 * vport_free().
 */
struct vport *ovs_vport_alloc(int priv_size, const struct vport_ops *ops,
			  const struct vport_parms *parms)
{
	struct vport *vport;
	size_t alloc_size;

	alloc_size = sizeof(struct vport);
	if (priv_size) {
		alloc_size = ALIGN(alloc_size, VPORT_ALIGN);
		alloc_size += priv_size;
	}

	vport = kzalloc(alloc_size, GFP_KERNEL);
	if (!vport)
		return ERR_PTR(-ENOMEM);

	vport->dp = parms->dp;
	vport->port_no = parms->port_no;
	vport->ops = ops;
	INIT_HLIST_NODE(&vport->dp_hash_node);

	if (ovs_vport_set_upcall_portids(vport, parms->upcall_portids)) {
		kfree(vport);
		return ERR_PTR(-EINVAL);
	}

	return vport;
}
EXPORT_SYMBOL_GPL(ovs_vport_alloc);

/**
 *	ovs_vport_free - uninitialize and free vport
 *
 * @vport: vport to free
 *
 * Frees a vport allocated with vport_alloc() when it is no longer needed.
 *
 * The caller must ensure that an RCU grace period has passed since the last
 * time @vport was in a datapath.
 */
void ovs_vport_free(struct vport *vport)
{
	/* vport is freed from RCU callback or error path, Therefore
	 * it is safe to use raw dereference.
	 */
	kfree(rcu_dereference_raw(vport->upcall_portids));
	ovs_vport_finish_tt_schedule(vport);
	kfree(vport);
}
EXPORT_SYMBOL_GPL(ovs_vport_free);

static struct vport_ops *ovs_vport_lookup(const struct vport_parms *parms)
{
	struct vport_ops *ops;

	list_for_each_entry(ops, &vport_ops_list, list)
		if (ops->type == parms->type)
			return ops;

	return NULL;
}

/** hrtimer handler **/
static enum hrtimer_restart hrtimer_handler(struct hrtimer *timer) 
{
	u64 global_register_time;
	struct timespec current_time;
	u64 wait_time;
	u32 flow_id;
	u64 offset_send_time;
	u64 send_time;

	struct sk_buff *skb = NULL;
	struct sk_buff *out_skb = NULL;
	struct vport *vport = NULL;
	struct tt_send_info *send_info = NULL;
	struct tt_schedule_info *schedule_info = NULL;
    struct timespec arrive_stamp;

	schedule_info = container_of(timer, struct tt_schedule_info, timer);
	vport = schedule_info->vport;
	send_info = schedule_info->send_info;
	
	global_register_time = global_time_read();  //read register time
	getnstimeofday(&current_time);
	get_next_time(schedule_info, global_register_time, &wait_time, &flow_id, &offset_send_time);
	send_time = TIMESPEC_TO_NSEC(current_time) + offset_send_time;
	
	/* two tt flows send on the same time. */
	if (0 == wait_time) {
		wait_time = offset_send_time + send_info->advance_time; 
	}

	hrtimer_forward_now(timer, ns_to_ktime(wait_time));
	//hrtimer_forward_now(timer, ns_to_ktime(wait_time/2 + offset_send_time));

	if (vport->dp->tt_buffer) {
		skb = vport->dp->tt_buffer[flow_id];
		vport->dp->tt_buffer[flow_id] = NULL;
	}

	getnstimeofday(&current_time);
	if (send_time < TIMESPEC_TO_NSEC(current_time)) {
		pr_info("MISS_ERROR: dispatch error, expect send time less than current time\n");
	}
	else {
		while (send_time > TIMESPEC_TO_NSEC(current_time) && 
				send_time - TIMESPEC_TO_NSEC(current_time) > send_info->advance_time) {   
			getnstimeofday(&current_time);
		}
	
		if (skb) {
			//pr_info("FINISH: vport id %d send flow id %d \n", vport->port_no, flow_id);
			skb_get_timestampns(skb, &arrive_stamp);
			if (TIMESPEC_TO_NSEC(current_time) - TIMESPEC_TO_NSEC(arrive_stamp) <= 
				send_info->macro_period) {
				out_skb = skb_clone(skb, GFP_ATOMIC);
				ovs_vport_send(vport, out_skb);
				kfree(skb);
			}
		}
		else {
			//pr_info("MISS: vport id %d can't send flow id %u\n", vport->port_no, flow_id);
		}
	}

	if (schedule_info->hrtimer_flag)
		return HRTIMER_RESTART;
	else
		return HRTIMER_NORESTART;
}

static bool ovs_vport_check_hrtimer_isready(struct vport *vport) 
{
	return vport->tt_schedule_info && vport->tt_schedule_info->send_info;
}

/** hrtimer start **/
static int ovs_vport_hrtimer_start(struct vport *vport) 
{ 
	u64 global_register_time;
	u64 offset_time;
	struct timespec current_time;
	struct tt_send_info *send_info;
	struct tt_schedule_info *schedule_info;
	
	if (unlikely(!ovs_vport_check_hrtimer_isready(vport)))
		return -EINVAL;

	schedule_info = vport->tt_schedule_info;
	send_info = schedule_info->send_info;
	hrtimer_init(&schedule_info->timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	schedule_info->timer.function = hrtimer_handler;
	schedule_info->hrtimer_flag = 1;

	global_register_time = global_time_read();  //read register time
	getnstimeofday(&current_time);
													 
	offset_time = global_register_time % send_info->macro_period;
	offset_time = send_info->macro_period - offset_time;
	hrtimer_start(&schedule_info->timer, ns_to_ktime(TIMESPEC_TO_NSEC(current_time) \
				+ offset_time - send_info->advance_time), HRTIMER_MODE_ABS); 
	return 0;
}

/**
 *	ovs_vport_add - add vport device (for kernel callers)
 *
 * @parms: Information about new vport.
 *
 * Creates a new vport with the specified configuration (which is dependent on
 * device type).  ovs_mutex must be held.
 */
struct vport *ovs_vport_add(const struct vport_parms *parms)
{
	struct vport_ops *ops;
	struct vport *vport;

	ops = ovs_vport_lookup(parms);
	if (ops) {
		struct hlist_head *bucket;

		if (!try_module_get(ops->owner))
			return ERR_PTR(-EAFNOSUPPORT);

		vport = ops->create(parms);
		if (IS_ERR(vport)) {
			module_put(ops->owner);
			return vport;
		}

		bucket = hash_bucket(ovs_dp_get_net(vport->dp),
				     ovs_vport_name(vport));
		hlist_add_head_rcu(&vport->hash_node, bucket);
		return vport;
	}

	/* Unlock to attempt module load and return -EAGAIN if load
	 * was successful as we need to restart the port addition
	 * workflow.
	 */
	ovs_unlock();
	request_module("vport-type-%d", parms->type);
	ovs_lock();

	if (!ovs_vport_lookup(parms))
		return ERR_PTR(-EAFNOSUPPORT);
	else
		return ERR_PTR(-EAGAIN);
}

/**
 *	ovs_vport_set_options - modify existing vport device (for kernel callers)
 *
 * @vport: vport to modify.
 * @options: New configuration.
 *
 * Modifies an existing device with the specified configuration (which is
 * dependent on device type).  ovs_mutex must be held.
 */
int ovs_vport_set_options(struct vport *vport, struct nlattr *options)
{
	if (!vport->ops->set_options)
		return -EOPNOTSUPP;
	return vport->ops->set_options(vport, options);
}

/**
 *	ovs_vport_del - delete existing vport device
 *
 * @vport: vport to delete.
 *
 * Detaches @vport from its datapath and destroys it.  It is possible to fail
 * for reasons such as lack of memory.  ovs_mutex must be held.
 */
void ovs_vport_del(struct vport *vport)
{
	ASSERT_OVSL();

	hlist_del_rcu(&vport->hash_node);
	module_put(vport->ops->owner);
	vport->ops->destroy(vport);
}

/**
 *	ovs_vport_get_stats - retrieve device stats
 *
 * @vport: vport from which to retrieve the stats
 * @stats: location to store stats
 *
 * Retrieves transmit, receive, and error stats for the given device.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
void ovs_vport_get_stats(struct vport *vport, struct ovs_vport_stats *stats)
{
	const struct rtnl_link_stats64 *dev_stats;
	struct rtnl_link_stats64 temp;

	dev_stats = dev_get_stats(vport->dev, &temp);
	stats->rx_errors  = dev_stats->rx_errors;
	stats->tx_errors  = dev_stats->tx_errors;
	stats->tx_dropped = dev_stats->tx_dropped;
	stats->rx_dropped = dev_stats->rx_dropped;

	stats->rx_bytes	  = dev_stats->rx_bytes;
	stats->rx_packets = dev_stats->rx_packets;
	stats->tx_bytes	  = dev_stats->tx_bytes;
	stats->tx_packets = dev_stats->tx_packets;
}

/**
 *	ovs_vport_get_options - retrieve device options
 *
 * @vport: vport from which to retrieve the options.
 * @skb: sk_buff where options should be appended.
 *
 * Retrieves the configuration of the given device, appending an
 * %OVS_VPORT_ATTR_OPTIONS attribute that in turn contains nested
 * vport-specific attributes to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room, or another
 * negative error code if a real error occurred.  If an error occurs, @skb is
 * left unmodified.
 *
 * Must be called with ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_options(const struct vport *vport, struct sk_buff *skb)
{
	struct nlattr *nla;
	int err;

	if (!vport->ops->get_options)
		return 0;

	nla = nla_nest_start(skb, OVS_VPORT_ATTR_OPTIONS);
	if (!nla)
		return -EMSGSIZE;

	err = vport->ops->get_options(vport, skb);
	if (err) {
		nla_nest_cancel(skb, nla);
		return err;
	}

	nla_nest_end(skb, nla);
	return 0;
}

static void vport_portids_destroy_rcu_cb(struct rcu_head *rcu)
{
	struct vport_portids *ids = container_of(rcu, struct vport_portids,
						 rcu);

	kfree(ids);
}

/**
 *	ovs_vport_set_upcall_portids - set upcall portids of @vport.
 *
 * @vport: vport to modify.
 * @ids: new configuration, an array of port ids.
 *
 * Sets the vport's upcall_portids to @ids.
 *
 * Returns 0 if successful, -EINVAL if @ids is zero length or cannot be parsed
 * as an array of U32.
 *
 * Must be called with ovs_mutex.
 */
int ovs_vport_set_upcall_portids(struct vport *vport, const struct nlattr *ids)
{
	struct vport_portids *old, *vport_portids;

	if (!nla_len(ids) || nla_len(ids) % sizeof(u32))
		return -EINVAL;

	old = ovsl_dereference(vport->upcall_portids);

	vport_portids = kmalloc(sizeof(*vport_portids) + nla_len(ids),
				GFP_KERNEL);
	if (!vport_portids)
		return -ENOMEM;

	vport_portids->n_ids = nla_len(ids) / sizeof(u32);
	vport_portids->rn_ids = reciprocal_value(vport_portids->n_ids);
	nla_memcpy(vport_portids->ids, ids, nla_len(ids));

	rcu_assign_pointer(vport->upcall_portids, vport_portids);

	if (old)
		call_rcu(&old->rcu, vport_portids_destroy_rcu_cb);
	return 0;
}

/**
 *	ovs_vport_get_upcall_portids - get the upcall_portids of @vport.
 *
 * @vport: vport from which to retrieve the portids.
 * @skb: sk_buff where portids should be appended.
 *
 * Retrieves the configuration of the given vport, appending the
 * %OVS_VPORT_ATTR_UPCALL_PID attribute which is the array of upcall
 * portids to @skb.
 *
 * Returns 0 if successful, -EMSGSIZE if @skb has insufficient room.
 * If an error occurs, @skb is left unmodified.  Must be called with
 * ovs_mutex or rcu_read_lock.
 */
int ovs_vport_get_upcall_portids(const struct vport *vport,
				 struct sk_buff *skb)
{
	struct vport_portids *ids;

	ids = rcu_dereference_ovsl(vport->upcall_portids);

	if (vport->dp->user_features & OVS_DP_F_VPORT_PIDS)
		return nla_put(skb, OVS_VPORT_ATTR_UPCALL_PID,
			       ids->n_ids * sizeof(u32), (void *)ids->ids);
	else
		return nla_put_u32(skb, OVS_VPORT_ATTR_UPCALL_PID, ids->ids[0]);
}

/**
 *	ovs_vport_find_upcall_portid - find the upcall portid to send upcall.
 *
 * @vport: vport from which the missed packet is received.
 * @skb: skb that the missed packet was received.
 *
 * Uses the skb_get_hash() to select the upcall portid to send the
 * upcall.
 *
 * Returns the portid of the target socket.  Must be called with rcu_read_lock.
 */
u32 ovs_vport_find_upcall_portid(const struct vport *vport, struct sk_buff *skb)
{
	struct vport_portids *ids;
	u32 ids_index;
	u32 hash;

	ids = rcu_dereference(vport->upcall_portids);

	if (ids->n_ids == 1 && ids->ids[0] == 0)
		return 0;

	hash = skb_get_hash(skb);
	ids_index = hash - ids->n_ids * reciprocal_divide(hash, ids->rn_ids);
	return ids->ids[ids_index];
}

/**
 *	ovs_vport_receive - pass up received packet to the datapath for processing
 *
 * @vport: vport that received the packet
 * @skb: skb that was received
 * @tun_key: tunnel (if any) that carried packet
 *
 * Must be called with rcu_read_lock.  The packet cannot be shared and
 * skb->data should point to the Ethernet header.
 */
int ovs_vport_receive(struct vport *vport, struct sk_buff *skb,
		      const struct ip_tunnel_info *tun_info)
{
	struct sw_flow_key key;
	int error;

	OVS_CB(skb)->input_vport = vport;
	OVS_CB(skb)->mru = 0;
	if (unlikely(dev_net(skb->dev) != ovs_dp_get_net(vport->dp))) {
		u32 mark;

		mark = skb->mark;
		skb_scrub_packet(skb, true);
		skb->mark = mark;
		tun_info = NULL;
	}

	ovs_skb_init_inner_protocol(skb);
	skb_clear_ovs_gso_cb(skb);
	/* Extract flow from 'skb' into 'key'. */
	error = ovs_flow_key_extract(tun_info, skb, &key);
	if (unlikely(error)) {
		kfree_skb(skb);
		return error;
	}
	ovs_dp_process_packet(skb, &key);
	return 0;
}
EXPORT_SYMBOL_GPL(ovs_vport_receive);

static void free_vport_rcu(struct rcu_head *rcu)
{
	struct vport *vport = container_of(rcu, struct vport, rcu);

	ovs_vport_free(vport);
}

void ovs_vport_deferred_free(struct vport *vport)
{
	if (!vport)
		return;

	call_rcu(&vport->rcu, free_vport_rcu);
}
EXPORT_SYMBOL_GPL(ovs_vport_deferred_free);

int ovs_tunnel_get_egress_info(struct dp_upcall_info *upcall,
			       struct net *net,
			       struct sk_buff *skb,
			       u8 ipproto,
			       __be16 tp_src,
			       __be16 tp_dst)
{
	struct ip_tunnel_info *egress_tun_info = upcall->egress_tun_info;
	struct ip_tunnel_info *tun_info = skb_tunnel_info(skb);
	const struct ip_tunnel_key *tun_key;
	u32 skb_mark = skb->mark;
	struct rtable *rt;
	struct flowi4 fl;

	if (unlikely(!tun_info))
		return -EINVAL;
	if (ip_tunnel_info_af(tun_info) != AF_INET)
		return -EINVAL;

	tun_key = &tun_info->key;

	/* Route lookup to get srouce IP address.
	 * The process may need to be changed if the corresponding process
	 * in vports ops changed.
	 */
	rt = ovs_tunnel_route_lookup(net, tun_key, skb_mark, &fl, ipproto);
	if (IS_ERR(rt))
		return PTR_ERR(rt);

	ip_rt_put(rt);

	/* Generate egress_tun_info based on tun_info,
	 * saddr, tp_src and tp_dst
	 */
	ip_tunnel_key_init(&egress_tun_info->key,
			   fl.saddr, tun_key->u.ipv4.dst,
			   tun_key->tos,
			   tun_key->ttl,
			   tp_src, tp_dst,
			   tun_key->tun_id,
			   tun_key->tun_flags);
	egress_tun_info->options_len = tun_info->options_len;
	egress_tun_info->mode = tun_info->mode;
	upcall->egress_tun_opts = ip_tunnel_info_opts(tun_info);
	return 0;
}
EXPORT_SYMBOL_GPL(ovs_tunnel_get_egress_info);

int ovs_vport_get_egress_tun_info(struct vport *vport, struct sk_buff *skb,
				  struct dp_upcall_info *upcall)
{
	/* get_egress_tun_info() is only implemented on tunnel ports. */
	if (unlikely(!vport->ops->get_egress_tun_info))
		return -EINVAL;

	return vport->ops->get_egress_tun_info(vport, skb, upcall);
}

static unsigned int packet_length(const struct sk_buff *skb)
{
	unsigned int length = skb->len - ETH_HLEN;

	if (skb->protocol == htons(ETH_P_8021Q))
		length -= VLAN_HLEN;

	return length;
}

void ovs_vport_send(struct vport *vport, struct sk_buff *skb)
{
	int mtu = vport->dev->mtu;

	if (unlikely(packet_length(skb) > mtu && !skb_is_gso(skb))) {
		net_warn_ratelimited("%s: dropped over-mtu packet: %d > %d\n",
				     vport->dev->name,
				     packet_length(skb), mtu);
		vport->dev->stats.tx_errors++;
		goto drop;
	}

	skb->dev = vport->dev;
	vport->ops->send(skb);
	return;

drop:
	kfree_skb(skb);
}

int ovs_vport_modify_arrive_tt_item(struct vport* vport, struct tt_table_item *tt_item)
{
	int error;
	int flag = 0;
	struct tt_schedule_info *schedule_info;
	struct tt_table *cur_tt_table;
	struct tt_table *tmp_tt_table;
	
	if (unlikely(!tt_item))
		return -EINVAL;

	if (!(vport->tt_schedule_info)) {
		error = ovs_vport_tt_schedule_info_alloc(vport);
		flag = 1;
		if (error)
			return error;
	}

	schedule_info = vport->tt_schedule_info;
	cur_tt_table = rcu_dereference(schedule_info->arrive_tt_table);
	tmp_tt_table = tt_table_insert_item(cur_tt_table, tt_item);
	if (tmp_tt_table) {
		rcu_assign_pointer(schedule_info->arrive_tt_table, tmp_tt_table);
	}
	else {
		 pr_info("ERROR: insert into arrive tt table faild!\n");
		 if (flag)
			 ovs_vport_finish_tt_schedule(vport);
		 return -ENOMEM; 
	}
	return 0;
}

int ovs_vport_modify_send_tt_item(struct vport* vport, struct tt_table_item *tt_item)
{
	int error;
	int flag;
	struct tt_schedule_info *schedule_info;
	struct tt_table *cur_tt_table;
	struct tt_table *tmp_tt_table;
	
	if (unlikely(!tt_item))
		return -EINVAL;

	if (!(vport->tt_schedule_info)) {
		error = ovs_vport_tt_schedule_info_alloc(vport);
		flag = 1;
		if (error)
			return error;
	}

	schedule_info = vport->tt_schedule_info;
	cur_tt_table = rcu_dereference(schedule_info->send_tt_table);
	tmp_tt_table = tt_table_insert_item(cur_tt_table, tt_item);
	if (tmp_tt_table) {
		rcu_assign_pointer(schedule_info->send_tt_table, tmp_tt_table);
	}
	else {
		 pr_info("ERROR: insert into send tt table faild!\n");
		 if (flag)
			 ovs_vport_finish_tt_schedule(vport);
		 return -ENOMEM; 
	}
	return 0;
}

int ovs_vport_del_arrive_tt_item(struct vport* vport, u32 flow_id)
{
	struct tt_schedule_info *schedule_info;
	struct tt_table *cur_tt_table;
	struct tt_table *tmp_tt_table;
	
	if (!(vport->tt_schedule_info)) 
		return 0;

	schedule_info = vport->tt_schedule_info;
	cur_tt_table = rcu_dereference(schedule_info->arrive_tt_table);
	tmp_tt_table = tt_table_delete_item(cur_tt_table, flow_id);
	if (tmp_tt_table) {
		rcu_assign_pointer(schedule_info->arrive_tt_table, tmp_tt_table);
	}
	else {
		 pr_info("ERROR: delete from arrive tt table faild!\n");
		 return -ENOMEM; 
	}
	return 0;
}

int ovs_vport_del_send_tt_item(struct vport* vport, u32 flow_id)
{
	struct tt_schedule_info *schedule_info;
	struct tt_table *cur_tt_table;
	struct tt_table *tmp_tt_table;
	
	if (!(vport->tt_schedule_info)) 
		return 0;

	schedule_info = vport->tt_schedule_info;
	cur_tt_table = rcu_dereference(schedule_info->send_tt_table);
	tmp_tt_table = tt_table_delete_item(cur_tt_table, flow_id);
	if (tmp_tt_table) {
		rcu_assign_pointer(schedule_info->send_tt_table, tmp_tt_table);
	}
	else {
		 pr_info("ERROR: delete from arrive tt table faild!\n");
		 return -ENOMEM; 
	}
	return 0;
}

struct tt_table_item* ovs_vport_lookup_arrive_tt_table(struct vport* vport, u32 flow_id)
{
	struct tt_schedule_info *schedule_info;
	struct tt_table *cur_tt_table;
	
	if (!(vport->tt_schedule_info)) 
		return NULL;

	schedule_info = vport->tt_schedule_info;
	cur_tt_table = rcu_dereference(schedule_info->arrive_tt_table);
	if (!cur_tt_table) {
		return NULL;
	}

	return tt_table_lookup(cur_tt_table, flow_id);
}

struct tt_table_item* ovs_vport_lookup_send_tt_table(struct vport* vport, u32 flow_id)
{
	struct tt_schedule_info *schedule_info;
	struct tt_table *cur_tt_table;
	
	if (!(vport->tt_schedule_info)) 
		return NULL;

	schedule_info = vport->tt_schedule_info;
	cur_tt_table = rcu_dereference(schedule_info->send_tt_table);
	if (!cur_tt_table) {
		return NULL;
	}

	return tt_table_lookup(cur_tt_table, flow_id);
}

void ovs_vport_del_arrive_tt_table(struct vport* vport)
{
	struct tt_schedule_info *schedule_info = vport->tt_schedule_info;
	struct tt_table *cur_tt_table;
	if (schedule_info) {
		cur_tt_table = rcu_dereference(schedule_info->arrive_tt_table);
		if (cur_tt_table) {
			call_rcu(&cur_tt_table->rcu, rcu_free_tt_table);
			rcu_assign_pointer(schedule_info->arrive_tt_table, NULL);
		}
    }
}

static void ovs_vport_tt_send_info_reset(struct vport *vport)
{
	struct tt_schedule_info *schedule_info = vport->tt_schedule_info;
	if (schedule_info) {
		if (schedule_info->send_info) {
			tt_send_info_free(schedule_info->send_info);
			schedule_info->send_info = NULL;
		}
	}
}

void ovs_vport_del_send_tt_table(struct vport* vport)
{
	struct tt_schedule_info *schedule_info = vport->tt_schedule_info;
	struct tt_table *cur_tt_table;
	if (schedule_info) {
		cur_tt_table = rcu_dereference(schedule_info->send_tt_table);
		if (cur_tt_table) {
			call_rcu(&cur_tt_table->rcu, rcu_free_tt_table);
			rcu_assign_pointer(schedule_info->send_tt_table, NULL);
		}
        ovs_vport_tt_send_info_reset(vport);
    }
}

int ovs_vport_start_tt_schedule(struct vport* vport)
{
	ovs_vport_hrtimer_cancel(vport);
	if (unlikely(dispatch(vport))) {
		pr_info("ERROR: dispatch send info fail!");
		return -EINVAL;
	}
	vport->tt_schedule_info->send_info->advance_time = SEND_ADVANCE_TIME; //===>just for test
	ovs_vport_hrtimer_start(vport);
	return 0;
}

bool ovs_vport_tt_schedule_isrunning(struct vport *vport)
{
	return NULL != vport->tt_schedule_info && 1 == vport->tt_schedule_info->hrtimer_flag;
}
