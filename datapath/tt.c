/*
  * Copyright (c) 2018-2019 Tsinghua University, Inc.
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

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/acpi_pmtmr.h>
#include "datapath.h"
#include "tt.h"
#include "vport.h"

u32 max_u32(u32 a, u32 b)
{
	if (a < b) return b;
	return a;
}

bool udp_port_is_tt(__be16 port) 
{
	return port == htons(TT_PORT);
}

/* if the ether type is TT_ETH_ETYPE, it is tt packet*/
bool eth_p_tt(__be16 eth_type) 
{
	return eth_type == htons(ETH_P_TT);
}

unsigned char *skb_tt_header(struct sk_buff *skb) 
{
	return skb_mac_header(skb) + skb->mac_len;
}

/**
* is_trdp_packet -- whether it is a TRDP packet
* @skb: skb that was received
* In the skb struct，skb->h、skb->nh and skb->mac should be pointed to the correct place.
* Must be called after extrace_key function.
*/
bool is_trdp_packet(struct sk_buff *skb) 
{
	struct ethhdr *eth;
	struct iphdr *nh;
	struct udphdr *udp;

	/* check if the packet is TRDP packet
	   features: transport layer is UDP, network layer is ipv4, 
	   UDP destination port is TT_PORT */
	eth = eth_hdr(skb);
	if (eth->h_proto != htons(ETH_P_IP))
		return 0;

	nh = ip_hdr(skb);
	if (nh->protocol != IPPROTO_UDP)
		return 0;

	udp = udp_hdr(skb);
	if (!udp_port_is_tt(udp->dest))
		return 0;

	return 1;
}

/**
* is_tt_packet -- whether it is a TT packet
* @skb: skb that was received
* In the skb struct，skb->h、skb->nh and skb->mac should be pointed to the correct place.
* Must be called after extrace_key function.
*/
bool is_tt_packet(struct sk_buff *skb) 
{
	struct ethhdr *eth;
	eth = eth_hdr(skb);

	return eth_p_tt(eth->h_proto);
}

/* push TT header */
static int push_tt(struct sk_buff *skb, const __be16* flow_id) 
{
	struct tt_header *tt_hdr;
	struct ethhdr *eth;

	/*use skb_cow_head fuction to check whether has enough space 
	  to add tt header in skb, if not, realloc the skb. */
	if (skb_cow_head(skb, TT_HLEN) < 0) {
		return -ENOMEM;
	}

	/* add tt header space and move the 
	   linker layer header forward TT_HLEN bytes. */
	skb_push(skb, TT_HLEN);
	memmove(skb_mac_header(skb) - TT_HLEN, skb_mac_header(skb), skb->mac_len);
	skb_reset_mac_header(skb);

	eth = eth_hdr(skb);
	eth->h_proto = htons(ETH_P_TT);

	/* push tt message header */
	tt_hdr = (struct tt_header*)skb_tt_header(skb);
	tt_hdr->flow_id = ntohs(*flow_id);
	tt_hdr->len = skb->len - 4; //===>>> uncertain??
	return 0;
}

/* pop TT header */
static int pop_tt(struct sk_buff *skb) 
{
	struct ethhdr *hdr;
	int err;

	err = skb_ensure_writable(skb, skb->mac_len + TT_HLEN);
	if (unlikely(err))
		return err;

	memmove(skb_mac_header(skb) + TT_HLEN, skb_mac_header(skb), skb->mac_len);

	__skb_pull(skb, TT_HLEN);
	skb_reset_mac_header(skb);

	hdr = (struct ethhdr *)(skb_tt_header(skb) - ETH_HLEN);
	hdr->h_proto = htons(ETH_P_IP);

	return 0;
}

/**
* trdp_to_tt -- convert a TRDP packet to TT packet
* @skb: skb that was received
* Must be called after is_trdp_packet and make sure is_trdp_packet return ture.
*/
int trdp_to_tt(struct sk_buff *skb) 
{
	/* in trdp packet, the first two bytes of the udp data field are flow_id
	 * 16 is the length of pktgen header */
	void* udp_data = skb_transport_header(skb) + sizeof(struct udphdr) + 16;
	__be16* flow_id = (__be16*)udp_data;

	return push_tt(skb, flow_id);
}

/**
* tt_to_trdp -- convert a TT packet to TRDP packet
* @skb: skb that was received
* Must be called after is_tt_packet and make sure is_tt_packet return ture.
*/
int tt_to_trdp(struct sk_buff *skb) 
{
	return pop_tt(skb);
}

struct tt_table_item *tt_table_item_alloc(void) 
{
	struct tt_table_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		return NULL;
	}
	return item;
}

void rcu_free_tt_table_item(struct rcu_head *rcu) 
{
	struct tt_table_item *item = container_of(rcu, struct tt_table_item, rcu);

	if (!item)
		return;

	kfree(item);
}

void rcu_free_tt_table(struct rcu_head *rcu) 
{
	struct tt_table *tt = container_of(rcu, struct tt_table, rcu);

	if (!tt)
		return;
	
	kfree(tt);
}

struct tt_table *tt_table_alloc(u32 size) 
{
	struct tt_table *new;
	u32 i;

	size = max_u32(TT_TABLE_SIZE_MIN, size);
	new = kzalloc(sizeof(struct tt_table) +
		sizeof(struct tt_table_item *) * size, GFP_KERNEL);
	if (!new) {
		return NULL;
	}

	new->count = 0;
	new->max = size;
	for (i = 0; i < new->max; i++)
		rcu_assign_pointer(new->tt_items[i], NULL);

	return new;
}

static struct tt_table *tt_table_realloc(struct tt_table *old, u32 size) 
{
	struct tt_table *new;

	new = tt_table_alloc(size);
	if (!new) {
		return NULL;
	}

	if (old) {
		u32 i;

		for (i = 0; i < old->max; i++) {
			if (ovsl_dereference(old->tt_items[i]))
				new->tt_items[i] = old->tt_items[i];
		}

		new->count = old->count;
	}

	if (old)
		call_rcu(&old->rcu, rcu_free_tt_table);

	return new;
}

struct tt_table_item *tt_table_lookup(const struct tt_table* cur_tt_table, const u32 flow_id) 
{
	struct tt_table_item* tt_item;
	if (!cur_tt_table || flow_id >= cur_tt_table->max) 
		return NULL;

	tt_item = ovsl_dereference(cur_tt_table->tt_items[flow_id]);
	return tt_item;
}

u32 tt_table_num_items(const struct tt_table* cur_tt_table) 
{
	return cur_tt_table->count;
}

struct tt_table *tt_table_delete_item(struct tt_table* cur_tt_table, u32 flow_id) 
{
	struct tt_table_item* tt_item;
	if (!cur_tt_table || flow_id >= cur_tt_table->max) {
		return NULL;
	}

	tt_item = ovsl_dereference(cur_tt_table->tt_items[flow_id]);
	if (tt_item) {
		RCU_INIT_POINTER(cur_tt_table->tt_items[flow_id], NULL);
		cur_tt_table->count--;
		call_rcu(&tt_item->rcu, rcu_free_tt_table_item);
	}

	if (cur_tt_table->max >= (TT_TABLE_SIZE_MIN * 2) &&
		cur_tt_table->count <= (cur_tt_table->max / 3)) {
		struct tt_table* res_tt_table;
		res_tt_table = tt_table_realloc(cur_tt_table, cur_tt_table->max / 2);
		if (!res_tt_table) {
			return cur_tt_table;
		}
		
		return res_tt_table;
	}
	return cur_tt_table;
}

struct tt_table *tt_table_insert_item(struct tt_table *cur_tt_table, const struct tt_table_item *new) 
{
	u32 flow_id = new->flow_id;
	struct tt_table_item *item;

	item = tt_table_item_alloc();
	if (!item) {
		return NULL;
	}

	item->flow_id = new->flow_id;
	item->buffer_id = new->buffer_id;
	item->period = new->period;
	item->packet_size = new->packet_size;
	item->base_offset = new->base_offset;
	
	if (!cur_tt_table || flow_id >= cur_tt_table->max) {
		struct tt_table* res_tt_table;
		res_tt_table = tt_table_realloc(cur_tt_table, flow_id + TT_TABLE_SIZE_MIN);
		if (!res_tt_table) {
			call_rcu(&item->rcu, rcu_free_tt_table_item);
			return NULL;
		}
		rcu_assign_pointer(cur_tt_table, res_tt_table);
	}
	
	
	/* if the item is NULL, then count ++*/
	if (!ovsl_dereference(cur_tt_table->tt_items[flow_id]))
		cur_tt_table->count++;
	
	rcu_assign_pointer(cur_tt_table->tt_items[flow_id], item);
	return cur_tt_table;
}

struct tmp_tt_table_item *tmp_tt_table_item_alloc(void)
{
	struct tmp_tt_table_item *item;

	item = kmalloc(sizeof(*item), GFP_KERNEL);
	if (!item) {
		return NULL;
	}
	return item;
}

void tmp_tt_table_free(struct tmp_tt_table *tmp_tt) 
{
	if (!tmp_tt)
		return;
	
	kfree(tmp_tt);
}

struct tmp_tt_table* tmp_tt_table_alloc(u32 size)
{
	struct tmp_tt_table *new;
	u32 i;

	size = max_u32(TT_TABLE_SIZE_MIN, size);
	new = kzalloc(sizeof(struct tmp_tt_table) +
		sizeof(struct tmp_tt_table_item *) * size, GFP_KERNEL);
	if (!new) {
		return NULL;
	}

	new->count = 0;
	new->max = size;

	for (i=0; i<new->max; i++)
		new->tmp_tt_items[i] = NULL;

	return new;
}

u32 tmp_tt_table_num_items(const struct tmp_tt_table* cur_tmp_tt_table)
{
	return cur_tmp_tt_table->count;
}

static struct tmp_tt_table *tmp_tt_table_realloc(struct tmp_tt_table *old, u32 size) 
{
	struct tmp_tt_table *new;

	new = tmp_tt_table_alloc(size);
	if (!new) {
		return NULL;
	}

	if (old) {
		u32 i;
		for (i = 0; i < old->max; i++) {
			if (old->tmp_tt_items[i]) {
				new->tmp_tt_items[i] = old->tmp_tt_items[i];
			}
		}

		new->count = old->count;
	}

	if (old) 
		tmp_tt_table_free(old);
	return new;
}

struct tmp_tt_table *tmp_tt_table_insert_item(struct tmp_tt_table *cur_tmp_tt_table,
		const struct tmp_tt_table_item *new) 
{
	struct tmp_tt_table_item *item;
	u32 count = 0;

	item = tmp_tt_table_item_alloc();
	if (!item) {
		return NULL;
	}

	item->tt_info.flow_id = new->tt_info.flow_id;
	item->tt_info.buffer_id = new->tt_info.buffer_id;
	item->tt_info.period = new->tt_info.period;
	item->tt_info.packet_size = new->tt_info.packet_size;
	item->tt_info.base_offset = new->tt_info.base_offset;
	item->etype = new->etype;
	item->port_id = new->port_id;

	if (!cur_tmp_tt_table || cur_tmp_tt_table->count == cur_tmp_tt_table->max) {
		struct tmp_tt_table* res_tmp_tt_table;
		if (cur_tmp_tt_table)
			count = cur_tmp_tt_table->count;

		res_tmp_tt_table = tmp_tt_table_realloc(cur_tmp_tt_table, count + TT_TABLE_SIZE_MIN);
		if (!res_tmp_tt_table) {
			kfree(item);
			return NULL;
		}
		cur_tmp_tt_table = res_tmp_tt_table;
	}

	cur_tmp_tt_table->tmp_tt_items[cur_tmp_tt_table->count] = item;
	cur_tmp_tt_table->count++;
	return cur_tmp_tt_table;
}

u64 global_time_read(void) 
{
	struct timespec current_time;
	getnstimeofday(&current_time);
	return TIMESPEC_TO_NSEC(current_time);
}

static u64 gcd(u64 a, u64 b) 
{
	u64 mod;
	if(b == 0)
		return a;
	mod = a % b;
	return gcd(b, mod);
}

static u64 lcm(u64 a, u64 b) 
{
	u64 g = gcd(a, b);
	a = div64_u64(a, g);
	return a * b;
}

static void swap_u32(u32 *x, u32 *y) 
{
	u32 t = *x;
	*x = *y;
	*y = t;
}

static void swap_u64(u64 *x, u64 *y)
{
	u64 t = *x;
	*x = *y;
	*y = t;
}

static void sort(u64* send_times, u32* flow_ids, u32 left, u32 right) 
{
	u32 r;
	u32 l;
	u32 mid;
	u64 pivot_send_time;
	u32 pivot_flow_id;

	if (left >= right) 
		return;
		
	mid = left + (right - left)/2;
	l = left;
	r = right;
	if (send_times[r] < send_times[l]) {
		r = left;
		l = right;
	}
	
	if (send_times[mid] < send_times[l]) {
		swap_u64(&send_times[l], &send_times[right]);
		swap_u32(&flow_ids[l], &flow_ids[right]);
	}
	else if (send_times[mid] > send_times[r]) {
		swap_u64(&send_times[r], &send_times[right]);
		swap_u32(&flow_ids[r], &flow_ids[right]);
	}
	else {
		swap_u64(&send_times[mid], &send_times[right]);
		swap_u32(&flow_ids[mid], &flow_ids[right]);
	}
	
	l = left;
	r = right;
	pivot_send_time = send_times[r];
	pivot_flow_id = flow_ids[r];
	while (l < r) {
		while (l < r && send_times[l] < pivot_send_time) {
			l++; 
		}
		send_times[r] = send_times[l];
		flow_ids[r] = flow_ids[l];
		while (l < r && send_times[r] >= pivot_send_time) {
			r--;
		}
		send_times[l] = send_times[r];
		flow_ids[l] = flow_ids[r];
	}

	send_times[r] = pivot_send_time;
	flow_ids[r] = pivot_flow_id;
	
	if (r > 0)
		sort(send_times, flow_ids, left, r-1);
	sort(send_times, flow_ids, r+1, right);
}

/**
* dispatch - initialize the information sent by tt schedule: 
*   including calculating the macro period, sorting the tt flow 
*   according to the time of transmission. 
* @vport: vport that should send tt flow
*/
int dispatch(struct vport* vport) 
{
	struct tt_send_info *send_info;
	struct tt_send_cache *send_cache;
	struct tt_table *send_table;
	struct tt_table_item *tt_item;
	struct tt_schedule_info *schedule_info;
	u64 *send_times = NULL;
	u32 *flow_ids = NULL;
	u64 macro_period;
	u64 size;
	u32 i;
	u32 k;
	u64 temp_period;
	u64 offset;

	schedule_info = vport->tt_schedule_info;
	if (unlikely(!schedule_info)) {
		goto error_einval;
	}

	send_info = schedule_info->send_info;
	send_table = rcu_dereference(schedule_info->send_tt_table);
	
	if (unlikely(!send_table)) {
		goto error_einval;
	}
	
	if (!send_info) {
		send_info = tt_send_info_alloc();
		if (!send_info) {
			goto error_enomen;
		}
	}

	macro_period = 1;
	for (i = 0; i < send_table->max; i++) {
		tt_item = rcu_dereference(send_table->tt_items[i]);
		if (!tt_item)
			continue;

		macro_period = lcm(macro_period, tt_item->period);
	}
	
	size = 0;
	for (i = 0; i < send_table->max; i++) {
		tt_item = rcu_dereference(send_table->tt_items[i]);
		if (!tt_item)
			continue;

		temp_period = macro_period;
		temp_period = div64_u64(temp_period, tt_item->period);
		size += temp_period;
	}

	send_times = kmalloc(size * sizeof(u64), GFP_KERNEL);
	if (!send_times) {
		goto error_enomen;
	}

	flow_ids = kmalloc(size * sizeof(u32), GFP_KERNEL);
	if (!send_info) {
		goto error_enomen;
	}
	
	k = 0;
	for (i = 0; i < send_table->max; i++) {
		tt_item = rcu_dereference(send_table->tt_items[i]);
		if (!tt_item)
			continue;
		
		offset = tt_item->base_offset;
		while(offset < macro_period){
			send_times[k] = offset; 
			flow_ids[k] = tt_item->flow_id;
			offset += tt_item->period;
			k++;
		}
	}

	/* sort tt flow */
	sort(send_times, flow_ids, 0, size - 1);
	
	/* print info */
	/* pr_info("DISPATCH: macro_period: %llu, size: %llu\n", macro_period, size);
	for (i = 0; i < size; i++){
		pr_info("DISPATCH: index %d, flow_id: %d, send_time: %llu", i, flow_ids[i], send_times[i]);
	}*/

	send_cache = &send_info->send_cache;
	if (send_cache->send_times)
		kfree(send_cache->send_times);
	if (send_cache->flow_ids)
		kfree(send_cache->flow_ids);

	send_cache->send_times = send_times;
	send_cache->flow_ids = flow_ids;
	send_cache->size = size;

	send_info->macro_period = macro_period;
	schedule_info->send_info = send_info;	
	
	return 0;

error_einval:
	return -EINVAL;
error_enomen:
	if (send_times)
		kfree(send_times);
	if (flow_ids)
		kfree(flow_ids);
	if (send_info)
		kfree(send_info);
	return -ENOMEM;
}

static u32 binarySearch(struct tt_schedule_info *schedule_info, u64 mod_time)
{
	u64 *send_times;
	u32 *flow_ids;
	u32 left;
	u32 right;
	u32 mid;
	u32 size;

	send_times = schedule_info->send_info->send_cache.send_times;
	flow_ids = schedule_info->send_info->send_cache.flow_ids;
	size = schedule_info->send_info->send_cache.size;
	left = 0;
	right = size;

	while (left < right) {
		mid = (right - left) / 2 + left;
		if (send_times[mid] <= mod_time){
			left = mid + 1;
		}else{
			right = mid;
		}
	}
	
	return left % size;
}

void get_next_time(struct tt_schedule_info *schedule_info, u64 cur_time, u64 *wait_time, u32 *flow_id, u64 *send_time) 
{
	u64 mod_time;
	u32 idx;
	u32 next_idx;
	struct tt_send_info *send_info;
	struct tt_send_cache *send_cache;

	send_info = schedule_info->send_info;
	send_cache = &send_info->send_cache;
	mod_time = cur_time % send_info->macro_period;
	
	idx = binarySearch(schedule_info, mod_time);
	next_idx = idx + 1;
	next_idx = next_idx % send_cache->size;

	*flow_id = send_cache->flow_ids[idx];
	if (next_idx == 0) {
		*wait_time = send_cache->send_times[next_idx] + send_info->macro_period - send_cache->send_times[idx];
	}
	else {
		*wait_time = send_cache->send_times[next_idx] - send_cache->send_times[idx];
	}

	if (mod_time > send_cache->send_times[idx]) {
		*send_time = send_info->macro_period - mod_time + send_cache->send_times[idx];
	}
	else {
		*send_time = send_cache->send_times[idx] - mod_time;
	}

	//*send_time = cur_time + *send_time;
	/* pr_info("SEND_INFO: mod_time %llu, cur_idx %d, current flow id %d, current send time %llu", \
	mod_time, idx, send_cache->flow_ids[idx], send_cache->send_times[idx]);*/
}

void tt_send_info_free(struct tt_send_info *send_info)
{
	if (send_info) {
		if (send_info->send_cache.send_times) {
			kfree(send_info->send_cache.send_times);
			send_info->send_cache.send_times = NULL;
		}
		if (send_info->send_cache.flow_ids) {
			kfree(send_info->send_cache.flow_ids);
			send_info->send_cache.flow_ids = NULL;
		}
		kfree(send_info);
	}
}

struct tt_send_info *tt_send_info_alloc(void)
{
	struct tt_send_info *send_info;
	send_info = kmalloc(sizeof(struct tt_send_info), GFP_KERNEL);
	if (send_info) {
		send_info->macro_period = 0;
		send_info->advance_time = 0;
		send_info->send_cache.send_times = NULL;
		send_info->send_cache.flow_ids = NULL;
		send_info->send_cache.size = 0;
	}
	return send_info;
}

struct tt_schedule_info *tt_schedule_info_alloc(struct vport* vport)
{
	struct tt_schedule_info *schedule_info;
	schedule_info = kmalloc(sizeof(*schedule_info), GFP_KERNEL);
	if (!schedule_info)
		return NULL;

	schedule_info->hrtimer_flag = 0;
	schedule_info->is_edge_vport = 0;
	schedule_info->vport = vport;
	rcu_assign_pointer(schedule_info->arrive_tt_table, NULL);
	rcu_assign_pointer(schedule_info->send_tt_table, NULL);
	schedule_info->send_info = NULL;

	return schedule_info;
}

void tt_schedule_info_free(struct tt_schedule_info *schedule_info)
{
	if (schedule_info) {
		struct tt_table *cur_tt_table;
		if (schedule_info->send_info) {
			tt_send_info_free(schedule_info->send_info);
			schedule_info->send_info = NULL;
		}	
		cur_tt_table = ovsl_dereference(schedule_info->arrive_tt_table);
		if (cur_tt_table) {
			call_rcu(&cur_tt_table->rcu, rcu_free_tt_table);
			rcu_assign_pointer(schedule_info->arrive_tt_table, NULL);
		}
		
		cur_tt_table = ovsl_dereference(schedule_info->send_tt_table);
		if (cur_tt_table) {
            call_rcu(&cur_tt_table->rcu, rcu_free_tt_table);
			rcu_assign_pointer(schedule_info->send_tt_table, NULL);
		}
		
		kfree(schedule_info);
	}
}
