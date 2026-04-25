/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Yandex LLC
 * Copyright (c) 2025 Andrey V. Elsukov <ae@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
/*
 * Example of compatibility layer for ipfw's rule management routines.
 */

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_ipfw.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/rmlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>
#include <sys/fnv_hash.h>
#include <net/if.h>
#include <net/pfil.h>
#include <net/route.h>
#include <net/vnet.h>
#include <vm/vm.h>
#include <vm/vm_extern.h>

#include <netinet/in.h>
#include <netinet/ip_var.h> /* hooks */
#include <netinet/ip_fw.h>

#include <netpfil/ipfw/ip_fw_private.h>
#include <netpfil/ipfw/ip_fw_table.h>

#ifdef MAC
#include <security/mac/mac_framework.h>
#endif

/*
 * These structures were used by IP_FW3 socket option with version 0.
 */
typedef struct _ipfw_dyn_rule_v0 {
	ipfw_dyn_rule	*next;		/* linked list of rules.	*/
	struct ip_fw *rule;		/* pointer to rule		*/
	/* 'rule' is used to pass up the rule number (from the parent)	*/

	ipfw_dyn_rule *parent;		/* pointer to parent rule	*/
	u_int64_t	pcnt;		/* packet match counter		*/
	u_int64_t	bcnt;		/* byte match counter		*/
	struct ipfw_flow_id id;		/* (masked) flow id		*/
	u_int32_t	expire;		/* expire time			*/
	u_int32_t	bucket;		/* which bucket in hash table	*/
	u_int32_t	state;		/* state of this rule (typically a
					 * combination of TCP flags)
					 */
	u_int32_t	ack_fwd;	/* most recent ACKs in forward	*/
	u_int32_t	ack_rev;	/* and reverse directions (used	*/
					/* to generate keepalives)	*/
	u_int16_t	dyn_type;	/* rule type			*/
	u_int16_t	count;		/* refcount			*/
	u_int16_t	kidx;		/* index of named object */
} __packed __aligned(8) ipfw_dyn_rule_v0;

typedef struct _ipfw_obj_dyntlv_v0 {
	ipfw_obj_tlv	head;
	ipfw_dyn_rule_v0 state;
} ipfw_obj_dyntlv_v0;

typedef struct _ipfw_obj_ntlv_v0 {
	ipfw_obj_tlv	head;		/* TLV header			*/
	uint16_t	idx;		/* Name index			*/
	uint8_t		set;		/* set, if applicable		*/
	uint8_t		type;		/* object type, if applicable	*/
	uint32_t	spare;		/* unused			*/
	char		name[64];	/* Null-terminated name		*/
} ipfw_obj_ntlv_v0;

typedef struct _ipfw_range_tlv_v0 {
	ipfw_obj_tlv	head;		/* TLV header			*/
	uint32_t	flags;		/* Range flags			*/
	uint16_t	start_rule;	/* Range start			*/
	uint16_t	end_rule;	/* Range end			*/
	uint32_t	set;		/* Range set to match		 */
	uint32_t	new_set;	/* New set to move/swap to	*/
} ipfw_range_tlv_v0;

typedef struct _ipfw_range_header_v0 {
	ip_fw3_opheader	opheader;	/* IP_FW3 opcode		*/
	ipfw_range_tlv_v0 range;
} ipfw_range_header_v0;

typedef struct	_ipfw_insn_limit_v0 {
	ipfw_insn o;
	uint8_t _pad;
	uint8_t limit_mask;
	uint16_t conn_limit;
} ipfw_insn_limit_v0;

typedef struct	_ipfw_obj_tentry_v0 {
	ipfw_obj_tlv	head;		/* TLV header			*/
	uint8_t		subtype;	/* subtype (IPv4,IPv6)		*/
	uint8_t		masklen;	/* mask length			*/
	uint8_t		result;		/* request result		*/
	uint8_t		spare0;
	uint16_t	idx;		/* Table name index		*/
	uint16_t	spare1;
	union {
		/* Longest field needs to be aligned by 8-byte boundary	*/
		struct in_addr		addr;	/* IPv4 address	*/
		uint32_t		key;	/* uid/gid/port	*/
		struct in6_addr		addr6;	/* IPv6 address	*/
		char	iface[IF_NAMESIZE];	/* interface name */
		struct tflow_entry	flow;
	} k;
	union {
		ipfw_table_value	value;	/* value data */
		uint32_t		kidx;	/* value kernel index */
	} v;
} ipfw_obj_tentry_v0;

static sopt_handler_f dump_config_v0, add_rules_v0, del_rules_v0,
    clear_rules_v0, move_rules_v0, manage_sets_v0, dump_soptcodes_v0,
    dump_srvobjects_v0;

static sopt_handler_f manage_table_ent_v1_compat, find_table_entry_compat,
    dump_table_v1_compat;

static struct ipfw_sopt_handler scodes[] = {
    { IP_FW_XGET,		IP_FW3_OPVER_0, HDIR_GET, dump_config_v0 },
    { IP_FW_XADD,		IP_FW3_OPVER_0, HDIR_BOTH, add_rules_v0 },
    { IP_FW_XDEL,		IP_FW3_OPVER_0, HDIR_BOTH, del_rules_v0 },
    { IP_FW_XZERO,		IP_FW3_OPVER_0, HDIR_SET, clear_rules_v0 },
    { IP_FW_XRESETLOG,		IP_FW3_OPVER_0, HDIR_SET, clear_rules_v0 },
    { IP_FW_XMOVE,		IP_FW3_OPVER_0, HDIR_SET, move_rules_v0 },
    { IP_FW_SET_SWAP,		IP_FW3_OPVER_0, HDIR_SET, manage_sets_v0 },
    { IP_FW_SET_MOVE,		IP_FW3_OPVER_0, HDIR_SET, manage_sets_v0 },
    { IP_FW_SET_ENABLE,		IP_FW3_OPVER_0, HDIR_SET, manage_sets_v0 },
    { IP_FW_DUMP_SOPTCODES,	IP_FW3_OPVER_0, HDIR_GET, dump_soptcodes_v0 },
    { IP_FW_DUMP_SRVOBJECTS,	IP_FW3_OPVER_0, HDIR_GET, dump_srvobjects_v0 },
    /*
     * IP_FW_TABLE_* sockopts.
     *
     * The on-wire structures used by these handlers (ipfw_obj_header,
     * ipfw_obj_ntlv, ipfw_obj_tentry, ipfw_xtable_info) preserved their
     * total size in the v0 -> v1 transition; only the layout of a small
     * idx/spare pair changed inside ipfw_obj_header and ipfw_obj_ntlv,
     * and the analogous idx/spare1 pair in ipfw_obj_tentry.
     *
     * Most table operations (XCREATE, XINFO, XDESTROY, XFLUSH, XMODIFY,
     * XSWAP, XLIST tables) only care about ntlv.name, which is at the
     * same offset in both layouts, so the v1 handlers can be reused
     * verbatim. Operations that look the table up via tent->idx or that
     * cross-reference oh->ntlv.idx with tent->idx (XADD, XDEL, XFIND,
     * XLIST entries) need an explicit conversion wrapper - see the
     * v1_overrides[] array below.
     */
    { IP_FW_TABLE_XCREATE,	IP_FW3_OPVER_0, HDIR_SET,  create_table },
    { IP_FW_TABLE_XDESTROY,	IP_FW3_OPVER_0, HDIR_SET,  flush_table_v0 },
    { IP_FW_TABLE_XFLUSH,	IP_FW3_OPVER_0, HDIR_SET,  flush_table_v0 },
    { IP_FW_TABLE_XMODIFY,	IP_FW3_OPVER_0, HDIR_BOTH, modify_table },
    { IP_FW_TABLE_XINFO,	IP_FW3_OPVER_0, HDIR_GET,  describe_table },
    { IP_FW_TABLES_XLIST,	IP_FW3_OPVER_0, HDIR_GET,  list_tables },
    { IP_FW_TABLE_XSWAP,	IP_FW3_OPVER_0, HDIR_SET,  swap_table },
    /*
     * The 14.x ipfw(8) sends version=0 only for XFIND; XADD/XDEL/XLIST
     * are sent with version=1 (the original wire version of those
     * handlers) and therefore reach the kernel through v1_overrides[]
     * below. We still register the wrapper under version=0 here so that
     * builds of 14.x ipfw(8) which omit the version=1 override land in
     * the same conversion path.
     */
    { IP_FW_TABLE_XADD,		IP_FW3_OPVER_0, HDIR_BOTH,
	manage_table_ent_v1_compat },
    { IP_FW_TABLE_XDEL,		IP_FW3_OPVER_0, HDIR_BOTH,
	manage_table_ent_v1_compat },
    { IP_FW_TABLE_XFIND,	IP_FW3_OPVER_0, HDIR_GET,
	find_table_entry_compat },
    { IP_FW_TABLE_XLIST,	IP_FW3_OPVER_0, HDIR_GET,
	dump_table_v1_compat },
};

/*
 * Originals taken over from ip_fw_table.c at module load. We DELete the
 * original (opcode, version=1, original-handler) registration and ADD our
 * compat wrapper in its place; on unload we reverse the operation.
 */
static struct ipfw_sopt_handler v1_originals[] = {
    { IP_FW_TABLE_XADD,		IP_FW3_OPVER, HDIR_BOTH, manage_table_ent_v1 },
    { IP_FW_TABLE_XDEL,		IP_FW3_OPVER, HDIR_BOTH, manage_table_ent_v1 },
    { IP_FW_TABLE_XLIST,	IP_FW3_OPVER, HDIR_GET,  dump_table_v1 },
    { IP_FW_TABLE_XFIND,	IP_FW3_OPVER, HDIR_GET,  find_table_entry },
};

static struct ipfw_sopt_handler v1_overrides[] = {
    { IP_FW_TABLE_XADD,		IP_FW3_OPVER, HDIR_BOTH,
	manage_table_ent_v1_compat },
    { IP_FW_TABLE_XDEL,		IP_FW3_OPVER, HDIR_BOTH,
	manage_table_ent_v1_compat },
    { IP_FW_TABLE_XLIST,	IP_FW3_OPVER, HDIR_GET,
	dump_table_v1_compat },
    { IP_FW_TABLE_XFIND,	IP_FW3_OPVER, HDIR_GET,
	find_table_entry_compat },
};

/*
 * Calculate v0 cmd length for a v1 opcode (inverse of adjust_size_v0()).
 * Returns v0 length in u32 words for @cmd encoded in v1.
 */
static int
v0_cmdlen_for_v1(ipfw_insn *cmd)
{
	int cmdlen;

	cmdlen = F_LEN(cmd);
	switch (cmd->opcode) {
	case O_CHECK_STATE:
	case O_KEEP_STATE:
	case O_PROBE_STATE:
	case O_EXTERNAL_ACTION:
	case O_EXTERNAL_INSTANCE:
		return (F_INSN_SIZE(ipfw_insn));
	case O_LIMIT:
		return (F_INSN_SIZE(ipfw_insn_limit_v0));
	case O_IP_SRC_LOOKUP:
	case O_IP_DST_LOOKUP:
	case O_IP_FLOW_LOOKUP:
	case O_MAC_SRC_LOOKUP:
	case O_MAC_DST_LOOKUP:
		if (cmdlen == F_INSN_SIZE(ipfw_insn_kidx))
			return (F_INSN_SIZE(ipfw_insn));
		if (cmdlen == F_INSN_SIZE(ipfw_insn_table))
			return (F_INSN_SIZE(ipfw_insn_u32));
		return (cmdlen);
	case O_SKIPTO:
	case O_CALLRETURN:
		return (F_INSN_SIZE(ipfw_insn));
	default:
		return (cmdlen);
	}
}

/*
 * Inverse of convert_v0_to_v1(): copy @src v1 opcode stream into @dst v0.
 * Returns number of u32 words written to @dst.
 */
static void
convert_v1_to_v0(ipfw_insn *src, ipfw_insn *dst, int cmd_len_v1,
    uint16_t *act_ofs_v0, uint16_t act_ofs_v1)
{
	ipfw_insn *start = dst;
	int l, cmdlen, newlen;

	*act_ofs_v0 = 0;
	for (l = cmd_len_v1; l > 0;
	    l -= cmdlen, src += cmdlen, dst += newlen) {
		cmdlen = F_LEN(src);
		if (cmd_len_v1 - l == act_ofs_v1)
			*act_ofs_v0 = dst - start;
		switch (src->opcode) {
		case O_CHECK_STATE:
		case O_KEEP_STATE:
		case O_PROBE_STATE:
		case O_EXTERNAL_ACTION:
		case O_EXTERNAL_INSTANCE:
			newlen = F_INSN_SIZE(ipfw_insn);
			dst->opcode = src->opcode;
			dst->len = (src->len & (F_NOT | F_OR)) | newlen;
			dst->arg1 = (uint16_t)insntoc(src, kidx)->kidx;
			break;
		case O_LIMIT: {
			ipfw_insn_limit_v0 *d0;
			const ipfw_insn_limit *s1;

			newlen = F_INSN_SIZE(ipfw_insn_limit_v0);
			s1 = insntoc(src, limit);
			d0 = (ipfw_insn_limit_v0 *)dst;
			d0->o.opcode = src->opcode;
			d0->o.len = (src->len & (F_NOT | F_OR)) | newlen;
			d0->o.arg1 = (uint16_t)s1->kidx;
			d0->_pad = 0;
			d0->limit_mask = s1->limit_mask;
			d0->conn_limit = s1->conn_limit;
			break;
		}
		case O_IP_SRC_LOOKUP:
		case O_IP_DST_LOOKUP:
		case O_IP_FLOW_LOOKUP:
		case O_MAC_SRC_LOOKUP:
		case O_MAC_DST_LOOKUP:
			if (cmdlen == F_INSN_SIZE(ipfw_insn_kidx)) {
				newlen = F_INSN_SIZE(ipfw_insn);
				dst->opcode = src->opcode;
				dst->len = (src->len & (F_NOT | F_OR)) | newlen;
				dst->arg1 =
				    (uint16_t)insntoc(src, kidx)->kidx;
			} else if (cmdlen == F_INSN_SIZE(ipfw_insn_table)) {
				const ipfw_insn_table *st;
				ipfw_insn_u32 *d32;

				newlen = F_INSN_SIZE(ipfw_insn_u32);
				st = insntoc(src, table);
				d32 = (ipfw_insn_u32 *)dst;
				d32->o.opcode = src->opcode;
				d32->o.len =
				    (src->len & (F_NOT | F_OR)) | newlen;
				d32->o.arg1 = (uint16_t)st->kidx;
				d32->d[0] = st->value;
			} else {
				newlen = cmdlen;
				memcpy(dst, src, sizeof(uint32_t) * newlen);
			}
			break;
		case O_SKIPTO:
		case O_CALLRETURN:
			newlen = F_INSN_SIZE(ipfw_insn);
			dst->opcode = src->opcode;
			dst->len = (src->len & (F_NOT | F_OR)) | newlen;
			dst->arg1 =
			    (uint16_t)insntoc(src, u32)->d[0];
			break;
		default:
			newlen = cmdlen;
			memcpy(dst, src, sizeof(uint32_t) * newlen);
			break;
		}
	}
	if (cmd_len_v1 == act_ofs_v1)
		*act_ofs_v0 = dst - start;
}

/*
 * Compute v0 cmd_len (in u32 words) for @krule's cmd stream.
 */
static uint16_t
v0_cmd_len(struct ip_fw *krule)
{
	ipfw_insn *cmd;
	int l, cmdlen;
	uint16_t total;

	total = 0;
	cmd = krule->cmd;
	for (l = krule->cmd_len; l > 0; l -= cmdlen, cmd += cmdlen) {
		cmdlen = F_LEN(cmd);
		total += v0_cmdlen_for_v1(cmd);
	}
	return (total);
}

/*
 * Total size (in bytes) of a single exported v0 rule, including TLV header.
 * Mirrors RULEUSIZE1() but for the (possibly shorter) v0 encoding.
 */
static size_t
ruleusize1_v0(struct ip_fw *krule)
{
	uint16_t cmd_len;

	cmd_len = v0_cmd_len(krule);
	return (roundup2(sizeof(struct ip_fw_rule) + cmd_len * 4 - 4, 8));
}

/*
 * Export @krule into v0 userland buffer @data.
 * Layout:
 * [ ipfw_obj_tlv(IPFW_TLV_RULE_ENT) [ ip_fw_bcounter (optional) ip_fw_rule ] ]
 * Assumes @data is zeroed.
 */
static void
export_rule_v0(struct ip_fw *krule, caddr_t data, int len, int rcntrs)
{
	struct ip_fw_bcounter *cntr;
	struct ip_fw_rule *urule;
	ipfw_obj_tlv *tlv;
	uint16_t act_ofs;

	tlv = (ipfw_obj_tlv *)data;
	tlv->type = IPFW_TLV_RULE_ENT;
	tlv->length = len;

	if (rcntrs != 0) {
		cntr = (struct ip_fw_bcounter *)(tlv + 1);
		urule = (struct ip_fw_rule *)(cntr + 1);
		export_cntr1_base(krule, cntr);
	} else
		urule = (struct ip_fw_rule *)(tlv + 1);

	convert_v1_to_v0(krule->cmd, urule->cmd, krule->cmd_len, &act_ofs,
	    krule->act_ofs);

	urule->act_ofs = act_ofs;
	urule->cmd_len = v0_cmd_len(krule);
	urule->rulenum = krule->rulenum;
	urule->set = krule->set;
	urule->flags = krule->flags;
	urule->id = krule->id;
}

/*
 * Dump static rules (with v0 cmd stream) in @sd. Mirrors dump_static_rules()
 * but writes v0-encoded rules.
 */
static int
dump_static_rules_v0(struct ip_fw_chain *chain, struct rule_dump_args *da,
    struct sockopt_data *sd)
{
	ipfw_obj_ctlv *ctlv;
	struct ip_fw *krule;
	caddr_t dst;
	uint32_t i;
	int l;

	ctlv = (ipfw_obj_ctlv *)ipfw_get_sopt_space(sd, sizeof(*ctlv));
	if (ctlv == NULL)
		return (ENOMEM);
	ctlv->head.type = IPFW_TLV_RULE_LIST;
	ctlv->head.length = da->rsize + sizeof(*ctlv);
	ctlv->count = da->rcount;

	for (i = da->b; i < da->e; i++) {
		krule = chain->map[i];

		/* Skip rules with rulenum that doesn't fit v0 userland */
		if (krule->rulenum > IPFW_DEFAULT_RULE)
			continue;

		l = ruleusize1_v0(krule) + sizeof(ipfw_obj_tlv);
		if (da->rcounters != 0)
			l += sizeof(struct ip_fw_bcounter);
		dst = (caddr_t)ipfw_get_sopt_space(sd, l);
		if (dst == NULL)
			return (ENOMEM);

		export_rule_v0(krule, dst, l, da->rcounters);
	}

	return (0);
}

/*
 * Export one named object as ipfw_obj_ntlv_v0 (16-bit idx).
 * Returns 0 on success or ENOMEM.
 */
static int
export_objhash_ntlv_v0(struct namedobj_instance *ni, uint32_t kidx,
    struct sockopt_data *sd)
{
	struct named_object *no;
	ipfw_obj_ntlv_v0 *ntlv;

	no = ipfw_objhash_lookup_kidx(ni, kidx);
	KASSERT(no != NULL, ("invalid object kernel index passed"));

	ntlv = (ipfw_obj_ntlv_v0 *)ipfw_get_sopt_space(sd, sizeof(*ntlv));
	if (ntlv == NULL)
		return (ENOMEM);

	ntlv->head.type = no->etlv;
	ntlv->head.length = sizeof(*ntlv);
	/* v0 idx is 16-bit; drop high bits if present. */
	ntlv->idx = (uint16_t)no->kidx;
	strlcpy(ntlv->name, no->name, sizeof(ntlv->name));
	return (0);
}

static int
export_named_objects_v0(struct namedobj_instance *ni,
    struct rule_dump_args *da, struct sockopt_data *sd)
{
	uint32_t i;
	int error;

	for (i = 0; i < IPFW_TABLES_MAX && da->tcount > 0; i++) {
		if ((da->bmask[i / 32] & (1 << (i % 32))) == 0)
			continue;
		if ((error = export_objhash_ntlv_v0(ni, i, sd)) != 0)
			return (error);
		da->tcount--;
	}
	return (0);
}

static int
dump_named_objects_v0(struct ip_fw_chain *ch, struct rule_dump_args *da,
    struct sockopt_data *sd)
{
	ipfw_obj_ctlv *ctlv;
	int error;

	MPASS(da->tcount > 0);
	ctlv = (ipfw_obj_ctlv *)ipfw_get_sopt_space(sd, sizeof(*ctlv));
	if (ctlv == NULL)
		return (ENOMEM);
	ctlv->head.type = IPFW_TLV_TBLNAME_LIST;
	ctlv->head.length = da->tcount * sizeof(ipfw_obj_ntlv_v0) +
	    sizeof(*ctlv);
	ctlv->count = da->tcount;
	ctlv->objsize = sizeof(ipfw_obj_ntlv_v0);

	error = export_named_objects_v0(ipfw_get_table_objhash(ch), da, sd);
	if (error != 0)
		return (error);
	da->bmask += IPFW_TABLES_MAX / 32;
	return (export_named_objects_v0(CHAIN_TO_SRV(ch), da, sd));
}

/*
 * Dumps requested objects data (v0 layout). Mirrors dump_config() in
 * ip_fw_sockopt.c but emits v0-sized ipfw_obj_ntlv and converts the per-rule
 * cmd stream back to v0 encoding. Dynamic states are not exported in v0 yet.
 *
 * Data layout (v0):
 * Request: [ ipfw_cfg_lheader ] + IPFW_CFG_GET_* flags
 * Reply: [ ipfw_cfg_lheader
 *   [ ipfw_obj_ctlv(IPFW_TLV_TBL_LIST) ipfw_obj_ntlv_v0 x N ] (optional)
 *   [ ipfw_obj_ctlv(IPFW_TLV_RULE_LIST)
 *     ipfw_obj_tlv(IPFW_TLV_RULE_ENT) [ ip_fw_bcounter? ip_fw_rule ]
 *   ] (optional)
 * ]
 */
static int
dump_config_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	struct rule_dump_args da;
	ipfw_cfg_lheader *hdr;
	struct ip_fw *rule;
	size_t sz, rnum;
	uint32_t hdr_flags, *bmask;
	int error, i;

	hdr = (ipfw_cfg_lheader *)ipfw_get_sopt_header(sd, sizeof(*hdr));
	if (hdr == NULL)
		return (EINVAL);

	error = 0;
	bmask = NULL;
	memset(&da, 0, sizeof(da));
	if (hdr->flags & (IPFW_CFG_GET_STATIC | IPFW_CFG_GET_STATES))
		da.bmask = bmask = malloc(
		    sizeof(uint32_t) * IPFW_TABLES_MAX * 2 / 32, M_TEMP,
		    M_WAITOK | M_ZERO);
	IPFW_UH_RLOCK(chain);

	/*
	 * STAGE 1: Determine size/count for objects in range.
	 */
	sz = sizeof(ipfw_cfg_lheader);
	da.e = chain->n_rules;

	if (hdr->end_rule != 0) {
		if ((rnum = hdr->start_rule) > IPFW_DEFAULT_RULE)
			rnum = IPFW_DEFAULT_RULE;
		da.b = ipfw_find_rule(chain, rnum, 0);
		rnum = (hdr->end_rule < IPFW_DEFAULT_RULE) ?
		    hdr->end_rule + 1: IPFW_DEFAULT_RULE;
		da.e = ipfw_find_rule(chain, rnum, UINT32_MAX) + 1;
	}

	if (hdr->flags & IPFW_CFG_GET_STATIC) {
		for (i = da.b; i < da.e; i++) {
			rule = chain->map[i];
			/* Hide rules with rulenum > 16-bit from v0. */
			if (rule->rulenum > IPFW_DEFAULT_RULE)
				continue;
			da.rsize += ruleusize1_v0(rule) + sizeof(ipfw_obj_tlv);
			da.rcount++;
			mark_rule_objects(chain, rule, &da);
		}
		if (hdr->flags & IPFW_CFG_GET_COUNTERS) {
			da.rsize += sizeof(struct ip_fw_bcounter) * da.rcount;
			da.rcounters = 1;
		}
		sz += da.rsize + sizeof(ipfw_obj_ctlv);
	}

	if (da.tcount > 0)
		sz += da.tcount * sizeof(ipfw_obj_ntlv_v0) +
		    sizeof(ipfw_obj_ctlv);

	hdr->size = sz;
	hdr->set_mask = ~V_set_disable;
	hdr_flags = hdr->flags;
	hdr = NULL;

	if (sd->valsize < sz) {
		error = ENOMEM;
		goto cleanup;
	}

	/* STAGE 2: Store actual data */
	if (da.tcount > 0) {
		error = dump_named_objects_v0(chain, &da, sd);
		if (error != 0)
			goto cleanup;
	}

	if (hdr_flags & IPFW_CFG_GET_STATIC) {
		error = dump_static_rules_v0(chain, &da, sd);
		if (error != 0)
			goto cleanup;
	}

	/*
	 * Dynamic states export in v0 layout is not implemented;
	 * userland will just see an empty state list.
	 */

cleanup:
	IPFW_UH_RUNLOCK(chain);

	if (bmask != NULL)
		free(bmask, M_TEMP);

	return (error);
}

/*
 * Calculate the size adjust needed to store opcodes converted from v0
 * to v1.
 */
static int
adjust_size_v0(ipfw_insn *cmd)
{
	int cmdlen, adjust;

	cmdlen = F_LEN(cmd);
	switch (cmd->opcode) {
	case O_CHECK_STATE:
	case O_KEEP_STATE:
	case O_PROBE_STATE:
	case O_EXTERNAL_ACTION:
	case O_EXTERNAL_INSTANCE:
		adjust = F_INSN_SIZE(ipfw_insn_kidx) - cmdlen;
		break;
	case O_LIMIT:
		adjust = F_INSN_SIZE(ipfw_insn_limit) - cmdlen;
		break;
	case O_IP_SRC_LOOKUP:
	case O_IP_DST_LOOKUP:
	case O_IP_FLOW_LOOKUP:
	case O_MAC_SRC_LOOKUP:
	case O_MAC_DST_LOOKUP:
		if (cmdlen == F_INSN_SIZE(ipfw_insn))
			adjust = F_INSN_SIZE(ipfw_insn_kidx) - cmdlen;
		else
			adjust = F_INSN_SIZE(ipfw_insn_table) - cmdlen;
		break;
	case O_SKIPTO:
	case O_CALLRETURN:
		adjust = F_INSN_SIZE(ipfw_insn_u32) - cmdlen;
		break;
	default:
		adjust = 0;
	}
	return (adjust);
}

static int
parse_rules_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd, ipfw_obj_ctlv **prtlv,
    struct rule_check_info **pci)
{
	ipfw_obj_ctlv *ctlv, *rtlv, *tstate;
	ipfw_obj_ntlv_v0 *ntlv;
	struct rule_check_info *ci, *cbuf;
	struct ip_fw_rule *r;
	size_t count, clen, read, rsize;
	uint32_t rulenum;
	int idx, error;

	op3 = (ip_fw3_opheader *)ipfw_get_sopt_space(sd, sd->valsize);
	ctlv = (ipfw_obj_ctlv *)(op3 + 1);
	read = sizeof(ip_fw3_opheader);
	if (read + sizeof(*ctlv) > sd->valsize)
		return (EINVAL);

	rtlv = NULL;
	tstate = NULL;
	cbuf = NULL;
	/* Table names or other named objects. */
	if (ctlv->head.type == IPFW_TLV_TBLNAME_LIST) {
		/* Check size and alignment. */
		clen = ctlv->head.length;
		if (read + clen > sd->valsize || clen < sizeof(*ctlv) ||
		    (clen % sizeof(uint64_t)) != 0)
			return (EINVAL);
		/* Check for validness. */
		count = (ctlv->head.length - sizeof(*ctlv)) / sizeof(*ntlv);
		if (ctlv->count != count || ctlv->objsize != sizeof(*ntlv))
			return (EINVAL);
		/*
		 * Check each TLV.
		 * Ensure TLVs are sorted ascending and
		 * there are no duplicates.
		 */
		idx = -1;
		ntlv = (ipfw_obj_ntlv_v0 *)(ctlv + 1);
		while (count > 0) {
			if (ntlv->head.length != sizeof(ipfw_obj_ntlv_v0))
				return (EINVAL);

			error = ipfw_check_object_name_generic(ntlv->name);
			if (error != 0)
				return (error);

			if (ntlv->idx <= idx)
				return (EINVAL);

			idx = ntlv->idx;
			count--;
			ntlv++;
		}

		tstate = ctlv;
		read += ctlv->head.length;
		ctlv = (ipfw_obj_ctlv *)((caddr_t)ctlv + ctlv->head.length);

		if (read + sizeof(*ctlv) > sd->valsize)
			return (EINVAL);
	}

	/* List of rules. */
	if (ctlv->head.type == IPFW_TLV_RULE_LIST) {
		clen = ctlv->head.length;
		if (read + clen > sd->valsize || clen < sizeof(*ctlv) ||
		    (clen % sizeof(uint64_t)) != 0)
			return (EINVAL);

		clen -= sizeof(*ctlv);
		if (ctlv->count == 0 ||
		    ctlv->count > clen / sizeof(struct ip_fw_rule))
			return (EINVAL);

		/* Allocate state for each rule */
		cbuf = malloc(ctlv->count * sizeof(struct rule_check_info),
		    M_TEMP, M_WAITOK | M_ZERO);

		/*
		 * Check each rule for validness.
		 * Ensure numbered rules are sorted ascending
		 * and properly aligned
		 */
		rulenum = 0;
		count = 0;
		error = 0;
		ci = cbuf;
		r = (struct ip_fw_rule *)(ctlv + 1);
		while (clen > 0) {
			rsize = RULEUSIZE1(r);
			if (rsize > clen || count > ctlv->count) {
				error = EINVAL;
				break;
			}
			ci->ctlv = tstate;
			ci->version = IP_FW3_OPVER_0;
			error = ipfw_check_rule(r, rsize, ci);
			if (error != 0)
				break;

			/* Check sorting */
			if (r->rulenum != 0 && r->rulenum < rulenum) {
				printf("ipfw: wrong order: rulenum %u"
				    " vs %u\n", r->rulenum, rulenum);
				error = EINVAL;
				break;
			}
			rulenum = r->rulenum;
			ci->urule = (caddr_t)r;
			clen -= rsize;
			r = (struct ip_fw_rule *)((caddr_t)r + rsize);
			count++;
			ci++;
		}

		if (ctlv->count != count || error != 0) {
			free(cbuf, M_TEMP);
			return (EINVAL);
		}

		rtlv = ctlv;
		read += ctlv->head.length;
		ctlv = (ipfw_obj_ctlv *)((caddr_t)ctlv + ctlv->head.length);
	}

	if (read != sd->valsize || rtlv == NULL) {
		free(cbuf, M_TEMP);
		return (EINVAL);
	}

	*prtlv = rtlv;
	*pci = cbuf;
	return (0);
}

static void
convert_v0_to_v1(struct rule_check_info *ci, int rule_len)
{
	struct ip_fw_rule *urule;
	struct ip_fw *krule;
	ipfw_insn *src, *dst;
	int l, cmdlen, newlen;

	urule = (struct ip_fw_rule *)ci->urule;
	krule = ci->krule;
	for (l = urule->cmd_len, src = urule->cmd, dst = krule->cmd;
	    l > 0 && rule_len > 0;
	    l -= cmdlen, src += cmdlen,
	    rule_len -= newlen, dst += newlen) {
		cmdlen = F_LEN(src);
		switch (src->opcode) {
		case O_CHECK_STATE:
		case O_KEEP_STATE:
		case O_PROBE_STATE:
		case O_EXTERNAL_ACTION:
		case O_EXTERNAL_INSTANCE:
			newlen = F_INSN_SIZE(ipfw_insn_kidx);
			insntod(dst, kidx)->kidx = src->arg1;
			break;
		case O_LIMIT:
			newlen = F_INSN_SIZE(ipfw_insn_limit);
			insntod(dst, limit)->kidx = src->arg1;
			insntod(dst, limit)->limit_mask =
			    insntoc(src, limit)->limit_mask;
			insntod(dst, limit)->conn_limit =
			    insntoc(src, limit)->conn_limit;
			break;
		case O_IP_DST_LOOKUP:
			if (cmdlen == F_INSN_SIZE(ipfw_insn) + 2) {
				/* lookup type stored in d[1] */
				dst->arg1 = insntoc(src, table)->value;
			}
		case O_IP_SRC_LOOKUP:
		case O_IP_FLOW_LOOKUP:
		case O_MAC_SRC_LOOKUP:
		case O_MAC_DST_LOOKUP:
			if (cmdlen == F_INSN_SIZE(ipfw_insn)) {
				newlen = F_INSN_SIZE(ipfw_insn_kidx);
				insntod(dst, kidx)->kidx = src->arg1;
			} else {
				newlen = F_INSN_SIZE(ipfw_insn_table);
				insntod(dst, table)->kidx = src->arg1;
				insntod(dst, table)->value =
				    insntoc(src, u32)->d[0];
			}
			break;
		case O_CALLRETURN:
		case O_SKIPTO:
			newlen = F_INSN_SIZE(ipfw_insn_u32);
			insntod(dst, u32)->d[0] = src->arg1;
			break;
		default:
			newlen = cmdlen;
			memcpy(dst, src, sizeof(uint32_t) * newlen);
			continue;
		}
		dst->opcode = src->opcode;
		dst->len = (src->len & (F_NOT | F_OR)) | newlen;
	}
}

/*
 * Copy rule @urule from v0 userland format to kernel @krule.
 */
static void
import_rule_v0(struct ip_fw_chain *chain, struct rule_check_info *ci)
{
	struct ip_fw_rule *urule;
	struct ip_fw *krule;
	ipfw_insn *cmd;
	int l, cmdlen, adjust, aadjust;

	urule = (struct ip_fw_rule *)ci->urule;
	l = urule->cmd_len;
	cmd = urule->cmd;
	adjust = aadjust = 0;

	/* Scan all opcodes and determine the needed size */
	while (l > 0) {
		adjust += adjust_size_v0(cmd);
		if (ACTION_PTR(urule) < cmd)
			aadjust = adjust;
		cmdlen = F_LEN(cmd);
		l -= cmdlen;
		cmd += cmdlen;
	}

	cmdlen = urule->cmd_len + adjust;
	krule = ci->krule = ipfw_alloc_rule(chain, /* RULEKSIZE1(cmdlen) */
	    roundup2(sizeof(struct ip_fw) + cmdlen * 4 - 4, 8));

	krule->act_ofs = urule->act_ofs + aadjust;
	krule->cmd_len = urule->cmd_len + adjust;

	if (adjust != 0)
		printf("%s: converted rule %u: cmd_len %u -> %u, "
		    "act_ofs %u -> %u\n", __func__, urule->rulenum,
		    urule->cmd_len, krule->cmd_len, urule->act_ofs,
		    krule->act_ofs);

	krule->rulenum = urule->rulenum;
	krule->set = urule->set;
	krule->flags = urule->flags;

	/* Save rulenum offset */
	ci->urule_numoff = offsetof(struct ip_fw_rule, rulenum);
	convert_v0_to_v1(ci, cmdlen);
}

static int
add_rules_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_obj_ctlv *rtlv;
	struct rule_check_info *ci, *nci;
	int i, ret;

	/*
	 * Check rules buffer for validness.
	 */
	ret = parse_rules_v0(chain, op3, sd, &rtlv, &nci);
	if (ret != 0)
		return (ret);
	/*
	 * Allocate storage for the kernel representation of rules.
	 */
	for (i = 0, ci = nci; i < rtlv->count; i++, ci++)
		import_rule_v0(chain, ci);
	/*
	 * Try to add new rules to the chain.
	 */
	if ((ret = ipfw_commit_rules(chain, nci, rtlv->count)) != 0) {
		for (i = 0, ci = nci; i < rtlv->count; i++, ci++)
			ipfw_free_rule(ci->krule);
	}
	/* Cleanup after ipfw_parse_rules() */
	free(nci, M_TEMP);
	return (ret);
}

static int
check_range_tlv_v0(const ipfw_range_tlv_v0 *rt, ipfw_range_tlv *crt)
{
	if (rt->head.length != sizeof(*rt))
		return (1);
	if (rt->start_rule > rt->end_rule)
		return (1);
	if (rt->set >= IPFW_MAX_SETS || rt->new_set >= IPFW_MAX_SETS)
		return (1);
	if ((rt->flags & IPFW_RCFLAG_USER) != rt->flags)
		return (1);

	crt->head = rt->head;
	crt->head.length = sizeof(*crt);
	crt->flags = rt->flags;
	crt->start_rule = rt->start_rule;
	crt->end_rule = rt->end_rule;
	crt->set = rt->set;
	crt->new_set = rt->new_set;
	return (0);
}

static int
del_rules_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_range_tlv rv;
	ipfw_range_header_v0 *rh;
	int error, ndel;

	if (sd->valsize != sizeof(*rh))
		return (EINVAL);

	rh = (ipfw_range_header_v0 *)ipfw_get_sopt_space(sd, sd->valsize);
	if (check_range_tlv_v0(&rh->range, &rv) != 0)
		return (EINVAL);

	ndel = 0;
	if ((error = delete_range(chain, &rv, &ndel)) != 0)
		return (error);

	/* Save number of rules deleted */
	rh->range.new_set = ndel;
	return (0);
}

/*
 * Clear rule accounting data matching specified parameters.
 * Data layout (v0):
 * Request:  [ ip_fw3_opheader ipfw_range_tlv_v0 ]
 * Reply:    [ ip_fw3_opheader ipfw_range_tlv_v0 ] (new_set = num cleared)
 */
static int
clear_rules_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_range_tlv rv;
	ipfw_range_header_v0 *rh;
	int log_only, num;
	char *msg;

	if (sd->valsize != sizeof(*rh))
		return (EINVAL);

	rh = (ipfw_range_header_v0 *)ipfw_get_sopt_space(sd, sd->valsize);
	if (check_range_tlv_v0(&rh->range, &rv) != 0)
		return (EINVAL);

	log_only = (op3->opcode == IP_FW_XRESETLOG);
	num = clear_range(chain, &rv, log_only);

	if (rv.flags & IPFW_RCFLAG_ALL)
		msg = log_only ? "All logging counts reset" :
		    "Accounting cleared";
	else
		msg = log_only ? "logging count reset" : "cleared";

	if (V_fw_verbose) {
		int lev = LOG_SECURITY | LOG_NOTICE;
		log(lev, "ipfw: %s.\n", msg);
	}

	/* Save number of rules cleared */
	rh->range.new_set = num;
	return (0);
}

/*
 * Move rules matching specified parameters to a new set.
 * Data layout (v0):
 * Request: [ ip_fw3_opheader ipfw_range_tlv_v0 ]
 */
static int
move_rules_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_range_tlv rv;
	ipfw_range_header_v0 *rh;

	if (sd->valsize != sizeof(*rh))
		return (EINVAL);

	rh = (ipfw_range_header_v0 *)ipfw_get_sopt_space(sd, sd->valsize);
	if (check_range_tlv_v0(&rh->range, &rv) != 0)
		return (EINVAL);

	return (move_range(chain, &rv));
}

/*
 * Swap/move/enable sets.
 * Data layout (v0):
 * Request: [ ip_fw3_opheader ipfw_range_tlv_v0 ]
 *
 * Note: for IP_FW_SET_ENABLE the .set / .new_set fields are bitmasks of sets
 * rather than set indices, so the IPFW_MAX_SETS check in check_range_tlv_v0()
 * is not applicable.
 */
static int
manage_sets_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_range_tlv rv;
	ipfw_range_header_v0 *rh;
	int ret;

	if (sd->valsize != sizeof(*rh))
		return (EINVAL);

	rh = (ipfw_range_header_v0 *)ipfw_get_sopt_space(sd, sd->valsize);

	if (rh->range.head.length != sizeof(rh->range))
		return (EINVAL);
	if (op3->opcode != IP_FW_SET_ENABLE &&
	    (rh->range.set >= IPFW_MAX_SETS ||
	    rh->range.new_set >= IPFW_MAX_SETS))
		return (EINVAL);

	memset(&rv, 0, sizeof(rv));
	rv.head = rh->range.head;
	rv.head.length = sizeof(rv);
	rv.flags = rh->range.flags;
	rv.start_rule = rh->range.start_rule;
	rv.end_rule = rh->range.end_rule;
	rv.set = rh->range.set;
	rv.new_set = rh->range.new_set;

	ret = 0;
	IPFW_UH_WLOCK(chain);
	switch (op3->opcode) {
	case IP_FW_SET_SWAP:
	case IP_FW_SET_MOVE:
		ret = ipfw_swap_sets(chain, &rv,
		    op3->opcode == IP_FW_SET_MOVE);
		break;
	case IP_FW_SET_ENABLE:
		ipfw_enable_sets(chain, &rv);
		break;
	}
	IPFW_UH_WUNLOCK(chain);

	return (ret);
}

static int
dump_soptcodes_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	return (EOPNOTSUPP);
}

static int
dump_srvobjects_v0(struct ip_fw_chain *chain, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	return (EOPNOTSUPP);
}

static enum ipfw_opcheck_result
check_opcode_compat(ipfw_insn **pcmd, int *plen, struct rule_check_info *ci)
{
	ipfw_insn *cmd;
	size_t cmdlen;

	if (ci->version != IP_FW3_OPVER_0)
		return (FAILED);

	cmd = *pcmd;
	cmdlen = F_LEN(cmd);
	switch (cmd->opcode) {
	case O_PROBE_STATE:
	case O_KEEP_STATE:
		if (cmdlen != F_INSN_SIZE(ipfw_insn))
			return (BAD_SIZE);
		ci->object_opcodes++;
		break;
	case O_LIMIT:
		if (cmdlen != F_INSN_SIZE(ipfw_insn_limit_v0))
			return (BAD_SIZE);
		ci->object_opcodes++;
		break;
	case O_IP_SRC_LOOKUP:
		if (cmdlen > F_INSN_SIZE(ipfw_insn_u32))
			return (BAD_SIZE);
		/* FALLTHROUGH */
	case O_IP_DST_LOOKUP:
		if (cmdlen != F_INSN_SIZE(ipfw_insn) &&
		    cmdlen != F_INSN_SIZE(ipfw_insn_u32) + 1 &&
		    cmdlen != F_INSN_SIZE(ipfw_insn_u32))
			return (BAD_SIZE);
		if (cmd->arg1 >= V_fw_tables_max) {
			printf("ipfw: invalid table number %u\n",
			    cmd->arg1);
			return (FAILED);
		}
		ci->object_opcodes++;
		break;
	case O_IP_FLOW_LOOKUP:
		if (cmdlen != F_INSN_SIZE(ipfw_insn) &&
		    cmdlen != F_INSN_SIZE(ipfw_insn_u32))
			return (BAD_SIZE);
		if (cmd->arg1 >= V_fw_tables_max) {
			printf("ipfw: invalid table number %u\n",
			    cmd->arg1);
			return (FAILED);
		}
		ci->object_opcodes++;
		break;
	case O_CHECK_STATE:
		ci->object_opcodes++;
		/* FALLTHROUGH */
	case O_SKIPTO:
	case O_CALLRETURN:
		if (cmdlen != F_INSN_SIZE(ipfw_insn))
			return (BAD_SIZE);
		return (CHECK_ACTION);

	case O_EXTERNAL_ACTION:
		if (cmd->arg1 == 0 ||
		    cmdlen != F_INSN_SIZE(ipfw_insn)) {
			printf("ipfw: invalid external "
			    "action opcode\n");
			return (FAILED);
		}
		ci->object_opcodes++;
		/*
		 * Do we have O_EXTERNAL_INSTANCE or O_EXTERNAL_DATA
		 * opcode?
		 */
		if (*plen != cmdlen) {
			*plen -= cmdlen;
			*pcmd = cmd += cmdlen;
			cmdlen = F_LEN(cmd);
			if (cmd->opcode == O_EXTERNAL_DATA)
				return (CHECK_ACTION);
			if (cmd->opcode != O_EXTERNAL_INSTANCE) {
				printf("ipfw: invalid opcode "
				    "next to external action %u\n",
				    cmd->opcode);
				return (FAILED);
			}
			if (cmd->arg1 == 0 ||
			    cmdlen != F_INSN_SIZE(ipfw_insn)) {
				printf("ipfw: invalid external "
				    "action instance opcode\n");
				return (FAILED);
			}
			ci->object_opcodes++;
		}
		return (CHECK_ACTION);

	default:
		return (ipfw_check_opcode(pcmd, plen, ci));
	}
	return (SUCCESS);
}

/*
 * 14.x -> 15.x compatibility for IP_FW_TABLE_X{ADD,DEL,LIST,FIND}
 * =================================================================
 *
 * Commit 4a77657cbc01 widened a number of `idx` fields from 16 to 32 bits
 * and rearranged the surrounding spare bytes in the on-wire structures
 * used by IP_FW3 socket options:
 *
 *	ipfw_obj_header	(16-byte tail after the ip_fw3_opheader):
 *		v0: spare(u32) idx(u16)  objtype(u8) objsubtype(u8)
 *		v1: idx(u32)   spare(u16) objtype(u8) objsubtype(u8)
 *
 *	ipfw_obj_ntlv	(16-byte tail after ipfw_obj_tlv head):
 *		v0: idx(u16) set(u8) type(u8) spare(u32) name[64]
 *		v1: idx(u32) set(u8) type(u8) spare(u16) name[64]
 *
 *	ipfw_obj_tentry (the idx slot at offset 12):
 *		v0: idx(u16) spare1(u16)
 *		v1: idx(u32)
 *
 * The total wire size of every structure is preserved, and the table
 * name (the only field most XINFO/XCREATE/XLIST handlers consult) lives
 * at the same offset in both layouts. That is why the table operations
 * registered under IP_FW3_OPVER_0 above keep working with the unmodified
 * v1 handlers.
 *
 * However, XADD, XDEL, XFIND and XLIST(entries) reach into the idx/set
 * fields. They locate the table by `tent->idx` (used as ti.uidx) and
 * then look the corresponding ntlv up by that uidx. With a 14.x client
 * the v1 reinterpretation produces e.g. ntlv.idx = 0x04000001 (table
 * type byte spilling into the high bits of idx) and tent.idx = 1, so
 * the search never matches and add_table_entry() returns ESRCH ("table
 * not found").
 *
 * The 14.x ipfw(8) always sets oh->idx = 1 (a legacy index marker), so
 * after v1 reinterpret the high half of that area - which v1 calls
 * `oh->spare` - becomes 1. 15.x clients leave both fields zero. We use
 * that as the heuristic to decide whether to rewrite the request to v1
 * layout in place before invoking the underlying v1 handler.
 */
static bool
ipfw_compat_obj_header_is_v0(const ipfw_obj_header *oh)
{

	return (oh->spare != 0);
}

static void
ipfw_compat_obj_ntlv_v0_to_v1(ipfw_obj_ntlv *ntlv)
{
	uint8_t *raw = (uint8_t *)ntlv;
	uint8_t set, type;

	/* Pull set/type from their v0 byte offsets before overwriting. */
	set = raw[10];	/* v0 ntlv.set */
	type = raw[11];	/* v0 ntlv.type */

	ntlv->idx = 0;
	ntlv->set = set;
	ntlv->type = type;
	ntlv->spare = 0;
}

static void
ipfw_compat_obj_header_v0_to_v1(ipfw_obj_header *oh)
{
	/*
	 * The objtype/objsubtype bytes already line up between v0 and v1
	 * (both are the trailing two bytes of the 8-byte tail after the
	 * opheader). All we have to fix is the idx/spare pair.
	 */
	oh->idx = 0;
	oh->spare = 0;
	ipfw_compat_obj_ntlv_v0_to_v1(&oh->ntlv);
}

static void
ipfw_compat_obj_tentry_v0_to_v1(ipfw_obj_tentry *tent)
{
	/*
	 * In v0 the slot at offset 12 was idx(u16) + spare1(u16); 14.x
	 * always writes idx == oh->idx == 1 (the legacy marker) and
	 * leaves spare1 == 0. Replace the resulting v1 idx (== 1) with
	 * 0 so the v1 handler falls back to looking the table up by
	 * name via oh->ntlv (which we have already rewritten).
	 *
	 * The ipfw_table_value union that follows differs in field
	 * layout between v0 and v1 but its wire size is unchanged. We
	 * deliberately do not translate value contents here: that only
	 * matters for callers that pass non-zero values (e.g.
	 * `ipfw table N add KEY VALUE`), which 14.x ipfw(8) was already
	 * unable to express portably.
	 */
	tent->idx = 0;
}

static int
manage_table_ent_v1_compat(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_obj_header *oh;
	ipfw_obj_ctlv *ctlv;
	ipfw_obj_tentry *tent;
	uint32_t i;

	if (sd->valsize >= sizeof(*oh) + sizeof(*ctlv)) {
		oh = (ipfw_obj_header *)sd->kbuf;
		if (ipfw_compat_obj_header_is_v0(oh)) {
			uint32_t cnt, max_cnt;

			ipfw_compat_obj_header_v0_to_v1(oh);
			ctlv = (ipfw_obj_ctlv *)(oh + 1);
			tent = (ipfw_obj_tentry *)(ctlv + 1);
			/*
			 * Defensively cap the count by the available buffer
			 * before the underlying v1 handler has had a chance
			 * to validate it.
			 */
			max_cnt = (sd->valsize - sizeof(*oh) -
			    sizeof(*ctlv)) / sizeof(*tent);
			cnt = ctlv->count;
			if (cnt > max_cnt)
				cnt = max_cnt;
			for (i = 0; i < cnt; i++)
				ipfw_compat_obj_tentry_v0_to_v1(&tent[i]);
		}
	}
	return (manage_table_ent_v1(ch, op3, sd));
}

static int
find_table_entry_compat(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_obj_header *oh;
	ipfw_obj_tentry *tent;

	if (sd->valsize >= sizeof(*oh) + sizeof(*tent)) {
		oh = (ipfw_obj_header *)sd->kbuf;
		if (ipfw_compat_obj_header_is_v0(oh)) {
			ipfw_compat_obj_header_v0_to_v1(oh);
			tent = (ipfw_obj_tentry *)(oh + 1);
			ipfw_compat_obj_tentry_v0_to_v1(tent);
		}
	}
	return (find_table_entry(ch, op3, sd));
}

static int
dump_table_v1_compat(struct ip_fw_chain *ch, ip_fw3_opheader *op3,
    struct sockopt_data *sd)
{
	ipfw_obj_header *oh;

	if (sd->valsize >= sizeof(*oh)) {
		oh = (ipfw_obj_header *)sd->kbuf;
		if (ipfw_compat_obj_header_is_v0(oh))
			ipfw_compat_obj_header_v0_to_v1(oh);
	}
	return (dump_table_v1(ch, op3, sd));
}

static int
ipfw_compat_modevent(module_t mod, int type, void *unused)
{
	switch (type) {
	case MOD_LOAD:
		IPFW_ADD_SOPT_HANDLER(1, scodes);
		/*
		 * Replace the v1 table sockopt handlers with our wrappers
		 * so that 14.x clients (which set opheader.version = 1 for
		 * XADD/XDEL/XLIST entries and rely on legacy v0 layout for
		 * the body) get the request rewritten to v1 layout before
		 * the underlying handler runs.
		 */
		IPFW_DEL_SOPT_HANDLER(1, v1_originals);
		IPFW_ADD_SOPT_HANDLER(1, v1_overrides);
		ipfw_register_compat(check_opcode_compat);
		break;
	case MOD_UNLOAD:
		ipfw_unregister_compat();
		IPFW_DEL_SOPT_HANDLER(1, v1_overrides);
		IPFW_ADD_SOPT_HANDLER(1, v1_originals);
		IPFW_DEL_SOPT_HANDLER(1, scodes);
		break;
	default:
		return (EOPNOTSUPP);
	}
	return (0);
}

static moduledata_t ipfw_compat_mod = {
	"ipfw_compat",
	ipfw_compat_modevent,
	0
};

/* Define startup order. */
#define	IPFW_COMPAT_SI_SUB_FIREWALL	SI_SUB_PROTO_FIREWALL
#define	IPFW_COMPAT_MODEVENT_ORDER	(SI_ORDER_ANY - 128) /* after ipfw */
#define	IPFW_COMPAT_MODULE_ORDER	(IPFW_COMPAT_MODEVENT_ORDER + 1)

DECLARE_MODULE(ipfw_compat, ipfw_compat_mod, IPFW_COMPAT_SI_SUB_FIREWALL,
    IPFW_COMPAT_MODULE_ORDER);
MODULE_DEPEND(ipfw_compat, ipfw, 3, 3, 3);
MODULE_VERSION(ipfw_compat, 1);
