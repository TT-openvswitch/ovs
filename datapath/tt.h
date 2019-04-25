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


#ifndef TT_H
#define TT_H 1

#include <linux/types.h>
#include <linux/skbuff.h>

#define TT_FLOW_ID_MAX  1024	/* max flow id */
#define TT_PORT 63000   /* tt flow dest port */
#define ETH_P_TT 0x88D7 /* tt flow ethernet type */

#define TT_HLEN 4   /* tt header length */
#define TT_TABLE_SIZE_MIN 16	/* minimum size of tt_table */
#define TT_BUFFER_SIZE 4096 /* one flow one buffer */
#define MAX_JITTER 10000000
#define SEND_ADVANCE_TIME 2000000
#define NSEC_PER_SECOND 1000000000
#define NSEC_PER_MSECOND 1000000
#define NSEC_PER_USECOND 1000

#define TIMESPEC_TO_NSEC(time_spec) \
	(time_spec.tv_sec * (u64)NSEC_PER_SECOND + time_spec.tv_nsec)

struct tt_header {
	u16 flow_id; /* tt flow_id */
	u16 len; /* tt packet's length */
};

/**
  struct tt_table_item - tt schedule table item, 
						 must be protected by rcu.
  @flow_id: tt flow identifier.
  @buffer_id: buffer to which this tt flow should be store.
  @period: the period of tt flow (ns).
  @base_offset: send time or receive time in current period (ns).
  @rcu: Rcu callback head of deferred destruction.
  @packet_size: tt packet's length
 */
struct tt_table_item {
	u32 flow_id;
	u32 buffer_id;
	u64 period;
	u64 base_offset;
	struct rcu_head rcu;
	u32 packet_size;
};

struct tmp_tt_table_item {
	struct tt_table_item tt_info;
	u32 etype; /* send or receive tt table item*/
	u32 port_id; /* port id*/
};

/**
  struct tt_table - tt schedule table, 
					must be protected by rcu.
  @rcu: Rcu callback head of deferred destruction.
  @count: total number of tt flow in this tt_table.
  @max: max tt_table size.
  @tt_items: tt flow items.
 */
struct tt_table {
	struct rcu_head rcu;
	u32 count, max;
	struct tt_table_item __rcu *tt_items[];
};

struct tmp_tt_table {
	u32 count;
	u32 max;
	struct tmp_tt_table_item *tmp_tt_items[];
};

struct tt_send_cache {
	u64 *send_times;
	u32 *flow_ids;
	u32 size;
};

struct tt_send_info {
	u64 macro_period;
	u64 advance_time;
	struct tt_send_cache send_cache;
};

/**
  * struct tt_schedule_info - tt schedule information in a vport
  * @arrive_tt_table: tt arrive table
  * @send_tt_table: tt send table
  * @send_info: tt send info
  * @timer: hrtimer for tt schedule
  * @vport: pointer to a struct vport that has the tt schedule message
  * @hrtimer_flag: hrtimer should or shouldn't restart, 1 for restart, 0 for not restart
  * @is_edge_vport: whether the vport is a edge vport, 1 for yes, 0 for no
  */
struct tt_schedule_info {
	struct tt_table __rcu *arrive_tt_table;
	struct tt_table __rcu *send_tt_table;
	struct tt_send_info *send_info;
	struct hrtimer timer;
	struct vport *vport;
	u8 hrtimer_flag;
	u8 is_edge_vport;
};

/* tt operation */
bool udp_port_is_tt(__be16 port);
bool eth_p_tt(__be16 eth_type);
unsigned char *skb_tt_header(struct sk_buff *skb);
bool is_trdp_packet(struct sk_buff *skb);
bool is_tt_packet(struct sk_buff *skb);
int trdp_to_tt(struct sk_buff *skb);
int tt_to_trdp(struct sk_buff *skb);

/* tt_table operation */
struct tt_table_item *tt_table_item_alloc(void);
void rcu_free_tt_table(struct rcu_head *rcu);
struct tt_table *tt_table_alloc(u32 size);
struct tt_table_item *tt_table_lookup(const struct tt_table* cur_tt_table, const u32 flow_id);
u32 tt_table_num_items(const struct tt_table* cur_tt_table);
struct tt_table *tt_table_delete_item(struct tt_table* cur_tt_table, u32 flow_id);
struct tt_table *tt_table_insert_item(struct tt_table *cur_tt_table, const struct tt_table_item *new);

struct tmp_tt_table_item *tmp_tt_table_item_alloc(void);
struct tmp_tt_table *tmp_tt_table_alloc(u32 size);
u32 tmp_tt_table_num_items(const struct tmp_tt_table* cur_tmp_tt_table);
struct tmp_tt_table *tmp_tt_table_insert_item(struct tmp_tt_table *cur_tmp_tt_table, const struct tmp_tt_table_item *new);
void tmp_tt_table_free(struct tmp_tt_table *cur_tmp_tt_table);

/* tt send info */
u64 global_time_read(void);
int dispatch(struct vport* vport);
void get_next_time(struct tt_schedule_info *schedule_info, u64 cur_time, u64 *wait_time, u32 *flow_id, u64 *send_time);
void tt_send_info_free(struct tt_send_info *send_info);
struct tt_send_info *tt_send_info_alloc(void);
struct tt_schedule_info *tt_schedule_info_alloc(struct vport *vport);
void tt_schedule_info_free(struct tt_schedule_info *schedule_info);
#endif
