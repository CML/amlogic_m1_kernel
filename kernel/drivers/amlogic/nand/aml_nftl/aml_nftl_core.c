
/*
 * Aml nftl core
 *
 * (C) 2010 10
 */

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/blktrans.h>
#include <linux/mutex.h>

#include "aml_nftl.h"

static void aml_nftl_update_sectmap(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t phy_blk_addr, addr_page_t logic_page_addr, addr_page_t phy_page_addr)
{
	struct phyblk_node_t *phy_blk_node;
	phy_blk_node = &aml_nftl_info->phypmt[phy_blk_addr];

	phy_blk_node->valid_sects++;
	phy_blk_node->phy_page_map[logic_page_addr] = phy_page_addr;
	phy_blk_node->last_write = phy_page_addr;
}

static int aml_nftl_write_pages(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr, addr_page_t page_addr,
								unsigned page_nums, unsigned char *data_buf, unsigned char *nftl_oob_buf)
{
	int i, status, test_page;
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;
	struct nftl_oobinfo_t *nftl_oob_info = (struct nftl_oobinfo_t *)nftl_oob_buf;	

	status = aml_nftl_ops->write_pages(aml_nftl_info, blk_addr, page_addr, page_nums, data_buf, nftl_oob_buf);
	if (status)
		return status;

	test_page = nftl_oob_info->sect;
	for (i=0; i<page_nums; i++) {
		nftl_oob_info = (struct nftl_oobinfo_t *)(nftl_oob_buf + i*sizeof(struct nftl_oobinfo_t));
		aml_nftl_update_sectmap(aml_nftl_info, blk_addr, nftl_oob_info->sect, page_addr + i);
		if (nftl_oob_info->sect != (test_page + i))
			aml_nftl_dbg("nftl write pages logic sect error %d %d\n", blk_addr, page_addr);
	}
	return 0;
}

static int aml_nftl_read_page(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr, addr_page_t page_addr,
								unsigned char *data_buf, unsigned char *nftl_oob_buf)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;

	return aml_nftl_ops->read_page(aml_nftl_info, blk_addr, page_addr, data_buf, nftl_oob_buf);
}

static int aml_nftl_copy_page(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t dest_blk_addr, addr_page_t dest_page, 
				addr_blk_t src_blk_addr, addr_page_t src_page)
{
	int status = 0;
	unsigned char *nftl_data_buf;
	unsigned char nftl_oob_buf[sizeof(struct nftl_oobinfo_t)];
	struct nftl_oobinfo_t *nftl_oob_info = (struct nftl_oobinfo_t *)nftl_oob_buf;
	struct phyblk_node_t *phy_blk_node = &aml_nftl_info->phypmt[dest_blk_addr];

	nftl_data_buf = aml_nftl_info->copy_page_buf;
	status = aml_nftl_info->read_page(aml_nftl_info, src_blk_addr, src_page, nftl_data_buf, nftl_oob_buf);
	if (status) {
		aml_nftl_dbg("copy page read failed: %d status: %d\n", src_blk_addr, status);
		goto exit;
	}

	nftl_oob_info->ec = phy_blk_node->ec;
	nftl_oob_info->timestamp = phy_blk_node->timestamp;
	nftl_oob_info->status_page = 1;
	status = aml_nftl_info->write_pages(aml_nftl_info, dest_blk_addr, dest_page, 1, nftl_data_buf, nftl_oob_buf);
	if (status) {
		aml_nftl_dbg("copy page write failed: %d status: %d\n", dest_blk_addr, status);
		goto exit;
	}

exit:
	return status;
}

static int aml_nftl_get_page_status(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t blk_addr, addr_page_t page_addr, unsigned char * nftl_oob_buf)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;

	return aml_nftl_ops->get_page_status(aml_nftl_info, blk_addr, page_addr, nftl_oob_buf);	
}

static int aml_nftl_blk_isbad(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t blk_addr)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;

	return aml_nftl_ops->blk_isbad(aml_nftl_info, blk_addr);
}

static int aml_nftl_blk_mark_bad(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t blk_addr)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;
	struct phyblk_node_t *phy_blk_node = &aml_nftl_info->phypmt[blk_addr];
	struct vtblk_node_t  *vt_blk_node;
	int i, j;

	if (phy_blk_node->vtblk >= 0) {
		vt_blk_node = &aml_nftl_info->vtpmt[phy_blk_node->vtblk];
		for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
			if (vt_blk_node->phy_blk_addr[i] == blk_addr) {
				vt_blk_node->phy_blk_addr[i] = BLOCK_INIT_VALUE;
				break;
			}
		}
		for (j=i; j<(MAX_BLK_NUM_PER_NODE-1); j++)
			vt_blk_node->phy_blk_addr[j] = vt_blk_node->phy_blk_addr[j+1];
	}
	memset((unsigned char *)phy_blk_node, 0xff, sizeof(struct phyblk_node_t));
	phy_blk_node->status_page = STATUS_BAD_BLOCK;

	return aml_nftl_ops->blk_mark_bad(aml_nftl_info, blk_addr);	
}

static int aml_nftl_get_block_status(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr, unsigned char * nftl_oob_buf)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;

	return aml_nftl_ops->get_page_status(aml_nftl_info, blk_addr, 0, nftl_oob_buf);
}

static int aml_nftl_creat_sectmap(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t phy_blk_addr)
{
	int i, status;
	uint32_t page_per_blk;
	int16_t valid_sects = 0;
	struct phyblk_node_t *phy_blk_node;
	unsigned char nftl_oob_buf[sizeof(struct nftl_oobinfo_t)];
	struct nftl_oobinfo_t *nftl_oob_info;
	phy_blk_node = &aml_nftl_info->phypmt[phy_blk_addr];
	nftl_oob_info = (struct nftl_oobinfo_t *)nftl_oob_buf;

	page_per_blk = aml_nftl_info->pages_per_blk;
	for (i=0; i<page_per_blk; i++) {
		status = aml_nftl_info->get_page_status(aml_nftl_info, phy_blk_addr, i, nftl_oob_buf);
		if (status) {
			aml_nftl_dbg("nftl creat sect map faile at: %d\n", phy_blk_addr);
			return AML_NFTL_FAILURE;
		}

		if (i == 0) {
			phy_blk_node->ec = nftl_oob_info->ec;
			phy_blk_node->vtblk = nftl_oob_info->vtblk;
			phy_blk_node->timestamp = nftl_oob_info->timestamp;
		}
		if (nftl_oob_info->sect >= 0) {
			phy_blk_node->phy_page_map[nftl_oob_info->sect] = i;
			phy_blk_node->last_write = i;
			valid_sects++;
		}
	}
	phy_blk_node->valid_sects = valid_sects;

	return 0;
}

static int aml_nftl_get_phy_sect_map(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr)
{
	int status;
	struct phyblk_node_t *phy_blk_node;
	phy_blk_node = &aml_nftl_info->phypmt[blk_addr];

	if (phy_blk_node->valid_sects < 0) {
		status = aml_nftl_creat_sectmap(aml_nftl_info, blk_addr);
		if (status)
			return AML_NFTL_FAILURE;
	}

	return 0;	
}

static void aml_nftl_erase_sect_map(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr)
{
	int i;
	struct phyblk_node_t *phy_blk_node;
	struct vtblk_node_t  *vt_blk_node;
	phy_blk_node = &aml_nftl_info->phypmt[blk_addr];

	if (phy_blk_node->vtblk >= 0) {
		vt_blk_node = &aml_nftl_info->vtpmt[phy_blk_node->vtblk];
		for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
			if (vt_blk_node->phy_blk_addr[i] == blk_addr)
				aml_nftl_dbg("%d %d %d %d %d\n", vt_blk_node->phy_blk_addr[0], vt_blk_node->phy_blk_addr[1], vt_blk_node->phy_blk_addr[2], vt_blk_node->phy_blk_addr[3], blk_addr);
			//BUG_ON(vt_blk_node->phy_blk_addr[i] == blk_addr);
			//vt_blk_node->phy_blk_addr[i] = 0xffff;
		}
	}

	phy_blk_node->ec++;
	phy_blk_node->valid_sects = 0;
	phy_blk_node->vtblk = BLOCK_INIT_VALUE;
	phy_blk_node->last_write = BLOCK_INIT_VALUE;
	phy_blk_node->timestamp = MAX_TIMESTAMP_NUM;
	memset(phy_blk_node->phy_page_map, 0xff, (sizeof(addr_sect_t)*MAX_PAGES_IN_BLOCK));

	return;
}

static int aml_nftl_erase_block(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_info->aml_nftl_ops;
	int status;

	status = aml_nftl_ops->erase_block(aml_nftl_info, blk_addr);
	if (status)
		return AML_NFTL_FAILURE;

	aml_nftl_erase_sect_map(aml_nftl_info, blk_addr);
	return 0;
}

static int aml_nftl_add_node(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t logic_blk_addr, addr_blk_t phy_blk_addr)
{
	struct phyblk_node_t *phy_blk_node, *phy_blk_tmp_node;
	struct vtblk_node_t  *vt_blk_node;
	struct aml_nftl_wl_t *aml_nftl_wl;
	uint32_t phy_blk_tmp;
	int i, j, k;

	aml_nftl_wl = aml_nftl_info->aml_nftl_wl;
	vt_blk_node = &aml_nftl_info->vtpmt[logic_blk_addr];
	phy_blk_node = &aml_nftl_info->phypmt[phy_blk_addr];
	for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
		if (vt_blk_node->phy_blk_addr[i] < 0) {
			goto add_node;
		}
	}

	for (k=0; k<aml_nftl_info->pages_per_blk; k++) {
		for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=0; j--) {
			phy_blk_tmp = vt_blk_node->phy_blk_addr[j];
			if (aml_nftl_info->get_phy_sect_map(aml_nftl_info, phy_blk_tmp))
				continue;
			phy_blk_tmp_node = &aml_nftl_info->phypmt[phy_blk_tmp];
			if (phy_blk_tmp_node->phy_page_map[k] >= 0)
				break;
		}
		if ((j == 0) && (phy_blk_tmp_node->phy_page_map[k] >= 0)) {
			if (aml_nftl_info->vtpmt_special->vtblk_node == NULL) {

				aml_nftl_info->vtpmt_special->vtblk_node = vt_blk_node;
				aml_nftl_info->vtpmt_special->ext_phy_blk_addr = phy_blk_addr;

				phy_blk_tmp = vt_blk_node->phy_blk_addr[(MAX_BLK_NUM_PER_NODE - 1)];
				phy_blk_tmp_node = &aml_nftl_info->phypmt[phy_blk_tmp];
				if ((phy_blk_tmp_node->timestamp >= MAX_TIMESTAMP_NUM) || (phy_blk_tmp_node->timestamp < 0))
					aml_nftl_creat_sectmap(aml_nftl_info, phy_blk_tmp);

				if (phy_blk_tmp_node->timestamp >= MAX_TIMESTAMP_NUM)
					phy_blk_node->timestamp = 0;
				else
					phy_blk_node->timestamp = (phy_blk_tmp_node->timestamp + 1);
				phy_blk_node->vtblk = logic_blk_addr;

				return AML_NFTL_STRUCTURE_FULL;
			}
			else
				return AML_NFTL_FAILURE;
		}
	}

	aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[0]);
	for (i=0; i<(MAX_BLK_NUM_PER_NODE - 1); i++) {

		vt_blk_node->phy_blk_addr[i] = vt_blk_node->phy_blk_addr[i+1];
	}

add_node:
	if (i == 0) {
		phy_blk_node->timestamp = i;
	}
	else {
		phy_blk_tmp = vt_blk_node->phy_blk_addr[i-1];
		phy_blk_tmp_node = &aml_nftl_info->phypmt[phy_blk_tmp];
		if ((phy_blk_tmp_node->timestamp >= MAX_TIMESTAMP_NUM) || (phy_blk_tmp_node->timestamp < 0))
			aml_nftl_creat_sectmap(aml_nftl_info, phy_blk_tmp);

		if (phy_blk_tmp_node->timestamp >= MAX_TIMESTAMP_NUM)
			phy_blk_node->timestamp = 0;
		else
			phy_blk_node->timestamp = (phy_blk_tmp_node->timestamp + 1);
	}
	phy_blk_node->vtblk = logic_blk_addr;
	//aml_nftl_dbg("nftl add node vt blk: %d phy blk: %d prev stamp: %d stamp: %d i: %d root phy blk: %d\n", logic_blk_addr, phy_blk_addr, tmp_stamp, phy_blk_node->timestamp, i, vt_blk_node->phy_blk_addr[i]);
	vt_blk_node->phy_blk_addr[i] = phy_blk_addr;

	return 0;	
}

static int aml_nftl_calculate_last_write(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t phy_blk_addr)
{
	int status;
	struct phyblk_node_t *phy_blk_node;
	phy_blk_node = &aml_nftl_info->phypmt[phy_blk_addr];

	if (phy_blk_node->valid_sects < 0) {
		status = aml_nftl_creat_sectmap(aml_nftl_info, phy_blk_addr);
		if (status)
			return AML_NFTL_FAILURE;
	}

	return 0;
}

static int aml_nftl_get_valid_pos(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t logic_blk_addr, addr_blk_t *phy_blk_addr,
									 addr_page_t logic_page_addr, addr_page_t *phy_page_addr, uint8_t flag )
{
	struct phyblk_node_t *phy_blk_node;
	struct vtblk_node_t  *vt_blk_node;
	int status;
	int i;
	uint32_t page_per_blk;

	page_per_blk = aml_nftl_info->pages_per_blk;
	*phy_blk_addr = BLOCK_INIT_VALUE;
	vt_blk_node = &aml_nftl_info->vtpmt[logic_blk_addr];
	for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
		if (i == (MAX_BLK_NUM_PER_NODE - 1)) {
			*phy_blk_addr = vt_blk_node->phy_blk_addr[i];
			break;
		}
		else {

			if ((vt_blk_node->phy_blk_addr[i] >= 0) && (vt_blk_node->phy_blk_addr[i + 1] < 0)) {
				*phy_blk_addr = vt_blk_node->phy_blk_addr[i];
				break;
			}
		}
	}
	if (*phy_blk_addr < 0) {
		//if (flag == WRITE_OPERATION)
			//aml_nftl_dbg("NFTL couldn`t find valid node for logic blk: %d root blk: %d\n", logic_blk_addr, vt_blk_node->phy_blk_addr[0]);
		return AML_NFTL_BLKNOTFOUND;
	}

	phy_blk_node = &aml_nftl_info->phypmt[*phy_blk_addr];
	status = aml_nftl_get_phy_sect_map(aml_nftl_info, *phy_blk_addr);
	if (status)
		return AML_NFTL_FAILURE;

	if (flag == WRITE_OPERATION) {
		if (phy_blk_node->last_write < 0)
			aml_nftl_calculate_last_write(aml_nftl_info, *phy_blk_addr);

		*phy_page_addr = phy_blk_node->last_write + 1;
		if (*phy_page_addr >= page_per_blk)
			return AML_NFTL_PAGENOTFOUND;

		return 0;
	}
	else if (flag == READ_OPERATION) {
		do {

			*phy_blk_addr = vt_blk_node->phy_blk_addr[i];
			phy_blk_node = &aml_nftl_info->phypmt[*phy_blk_addr];

			status = aml_nftl_get_phy_sect_map(aml_nftl_info, *phy_blk_addr);
			if (status)
				return AML_NFTL_FAILURE;

			if (phy_blk_node->phy_page_map[logic_page_addr] >= 0) {
				*phy_page_addr = phy_blk_node->phy_page_map[logic_page_addr];
				return 0;
			}

			i--;
		}while ((vt_blk_node->phy_blk_addr[i] >= 0) && (i >= 0));

		return AML_NFTL_PAGENOTFOUND;
	}
	return 0;
}

static int aml_nftl_read_sect(struct aml_nftl_info_t *aml_nftl_info, addr_page_t sect_addr, unsigned char *buf)
{
	uint32_t page_per_blk;
	addr_page_t logic_page_addr, phy_page_addr;
	addr_blk_t logic_blk_addr, phy_blk_addr;
	int status = 0;

	page_per_blk = aml_nftl_info->pages_per_blk;
	logic_page_addr = sect_addr % page_per_blk;
	logic_blk_addr = sect_addr / page_per_blk;

	status = aml_nftl_get_valid_pos(aml_nftl_info, logic_blk_addr, &phy_blk_addr, logic_page_addr, &phy_page_addr, READ_OPERATION);
	if ((status == AML_NFTL_PAGENOTFOUND) || (status == AML_NFTL_BLKNOTFOUND)) {
		memset(buf, 0xff, aml_nftl_info->writesize);
		return 0;
	}

	if (status == AML_NFTL_FAILURE)
        return AML_NFTL_FAILURE;

	status = aml_nftl_info->read_page(aml_nftl_info, phy_blk_addr, phy_page_addr, buf, NULL);
	if (status)
		return status;

	return 0;
}

static int aml_nftl_write_sects(struct aml_nftl_info_t *aml_nftl_info, addr_page_t sect_addr, unsigned sect_nums, unsigned char *buf)
{
	int status = 0, special_gc = 0, i;
	struct aml_nftl_wl_t *aml_nftl_wl = aml_nftl_info->aml_nftl_wl;
	struct phyblk_node_t *phy_blk_node;
	uint32_t page_per_blk, write_page_nums, buf_offset, total_write_nums = 0;
	addr_page_t logic_page_addr, phy_page_addr;
	addr_blk_t logic_blk_addr, phy_blk_addr;
	unsigned char nftl_oob_buf[sizeof(struct nftl_oobinfo_t)*sect_nums];
	struct nftl_oobinfo_t *nftl_oob_info = (struct nftl_oobinfo_t *)nftl_oob_buf;

	page_per_blk = aml_nftl_info->pages_per_blk;
	write_page_nums = 0;
	buf_offset = 0;

	do {

		logic_page_addr = sect_addr % page_per_blk;
		logic_blk_addr = sect_addr / page_per_blk;

		status = aml_nftl_get_valid_pos(aml_nftl_info, logic_blk_addr, &phy_blk_addr, logic_page_addr, &phy_page_addr, WRITE_OPERATION);
		if (status == AML_NFTL_FAILURE)
        	return AML_NFTL_FAILURE;

		if ((status == AML_NFTL_PAGENOTFOUND) || (status == AML_NFTL_BLKNOTFOUND)) {

			if ((aml_nftl_wl->free_root.count <= aml_nftl_info->fillfactor) && (!aml_nftl_wl->erased_root.count))
				aml_nftl_wl->garbage_collect(aml_nftl_wl, 0);

			status = aml_nftl_wl->get_best_free(aml_nftl_wl, &phy_blk_addr);
			if (status) {
				status = aml_nftl_wl->garbage_collect(aml_nftl_wl, DO_COPY_PAGE);
				if (status == 0) {
					aml_nftl_dbg("nftl couldn`t found free block: %d\n", aml_nftl_wl->free_root.count);
					return -ENOENT;
				}
				status = aml_nftl_wl->get_best_free(aml_nftl_wl, &phy_blk_addr);
				if (status)
					return status;
			}

			aml_nftl_wl->add_used(aml_nftl_wl, phy_blk_addr);
			status = aml_nftl_add_node(aml_nftl_info, logic_blk_addr, phy_blk_addr);
			if (status == AML_NFTL_STRUCTURE_FULL) {
				//aml_nftl_dbg("aml nftl structure full at logic : %d phy blk: %d\n", logic_blk_addr, phy_blk_addr);
				special_gc = 1;
			}
			phy_page_addr = 0;
		}

		phy_blk_node = &aml_nftl_info->phypmt[phy_blk_addr];
		if (sect_nums <= (page_per_blk - phy_page_addr))
			write_page_nums = sect_nums;
		else
			write_page_nums = (page_per_blk - phy_page_addr);
		for (i=0; i<write_page_nums; i++) {
			nftl_oob_info = (struct nftl_oobinfo_t *)(nftl_oob_buf + i*sizeof(struct nftl_oobinfo_t));
			nftl_oob_info->ec = phy_blk_node->ec;
			nftl_oob_info->vtblk = logic_blk_addr;
			nftl_oob_info->timestamp = phy_blk_node->timestamp;
			nftl_oob_info->status_page = 1;
			nftl_oob_info->sect = logic_page_addr + i;
		}

		status = aml_nftl_info->write_pages(aml_nftl_info, phy_blk_addr, phy_page_addr, write_page_nums, buf+buf_offset, nftl_oob_buf);
		if (status) {
			aml_nftl_info->blk_mark_bad(aml_nftl_info, phy_blk_addr);
			aml_nftl_dbg("nftl write page faile blk: %d page: %d status: %d\n", phy_blk_addr, phy_page_addr, status);
			return status;
		}

		if (special_gc) {
			status = aml_nftl_wl->gc_special(aml_nftl_wl);
			if (status)
				return status;
		}
		buf_offset += write_page_nums * aml_nftl_info->writesize;
		total_write_nums += write_page_nums;
		sect_addr += write_page_nums;
	}while (total_write_nums < sect_nums);

	return 0;
}

static void aml_nftl_add_block(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t phy_blk, struct nftl_oobinfo_t *nftl_oob_info, void **timestamp_conflict_node)
{
	struct phyblk_node_t *phy_blk_node, *phy_blk_node_curt;
	struct vtblk_node_t  *vt_blk_node;
	struct aml_nftl_wl_t *aml_nftl_wl;
	addr_blk_t phy_blk_save[MAX_BLK_NUM_PER_NODE+1], phy_blk_conflict[MAX_BLK_NUM_PER_NODE+1], phy_blk_add;
	int i = 0, j, k, m, conflict = 0;

	aml_nftl_wl = aml_nftl_info->aml_nftl_wl;
	phy_blk_add = phy_blk;
	phy_blk_node = &aml_nftl_info->phypmt[phy_blk];
	phy_blk_node->ec = nftl_oob_info->ec;
	phy_blk_node->vtblk = nftl_oob_info->vtblk;
	phy_blk_node->timestamp = nftl_oob_info->timestamp;
	vt_blk_node = &aml_nftl_info->vtpmt[nftl_oob_info->vtblk];

add_block:
	memset((unsigned char *)phy_blk_save, 0xff, sizeof(addr_blk_t)*(MAX_BLK_NUM_PER_NODE+1));
	memcpy((unsigned char *)phy_blk_save, (unsigned char *)vt_blk_node, sizeof(struct vtblk_node_t));

	do {

		if ((phy_blk_save[i] < 0) || (i >= MAX_BLK_NUM_PER_NODE))
			break;

		phy_blk_node_curt = &aml_nftl_info->phypmt[phy_blk_save[i]];
		//aml_nftl_dbg("block timestamp prev: %d next: %d phy blk: %d cur stamp: %d add stamp: %d vt blk: %d\n",
				 //phy_blk_save[i], phy_blk_save[i+1], phy_blk, phy_blk_node_curt->timestamp, phy_blk_node->timestamp, phy_blk_node->vtblk);
		if (phy_blk_node->timestamp == phy_blk_node_curt->timestamp) {
			aml_nftl_dbg("nftl found timestamp bug node vt blk: %d phy blk: %d \n", nftl_oob_info->vtblk, phy_blk);
			if (timestamp_conflict_node[nftl_oob_info->vtblk] == NULL) {
				timestamp_conflict_node[nftl_oob_info->vtblk] = aml_nftl_malloc(sizeof(struct vtblk_node_t));
				if (timestamp_conflict_node[nftl_oob_info->vtblk] == NULL)
					return;
				memset((unsigned char *)timestamp_conflict_node[nftl_oob_info->vtblk], 0xff, sizeof(struct vtblk_node_t));
			}
			if (phy_blk_node->ec < phy_blk_node_curt->ec) {
				phy_blk_add = vt_blk_node->phy_blk_addr[i];
				vt_blk_node->phy_blk_addr[i] = phy_blk;
				phy_blk_node = &aml_nftl_info->phypmt[phy_blk_add];
			}
			vt_blk_node = (struct vtblk_node_t *)timestamp_conflict_node[nftl_oob_info->vtblk];
			if (conflict == 1) {
				aml_nftl_wl->add_free(aml_nftl_wl, phy_blk_add);
				return;
			}

			conflict = 1;
			goto add_block;
		}
		else if (phy_blk_node->timestamp < phy_blk_node_curt->timestamp)
			break;

	}while((i++) < MAX_BLK_NUM_PER_NODE);

	for (j=MAX_BLK_NUM_PER_NODE; j>i; j--)
		phy_blk_save[j] = phy_blk_save[j-1];
	phy_blk_save[i] = phy_blk_add;

	conflict = 0;
	for (k=0; k<MAX_BLK_NUM_PER_NODE; k++) {
		if ((phy_blk_save[k] < 0) || (phy_blk_save[k+1] < 0))
			break;

		phy_blk_node_curt = &aml_nftl_info->phypmt[phy_blk_save[k]];
		phy_blk_node = &aml_nftl_info->phypmt[phy_blk_save[k+1]];
		if ((phy_blk_node->timestamp - phy_blk_node_curt->timestamp) >= (MAX_TIMESTAMP_NUM - aml_nftl_info->accessibleblocks)) {
			conflict = 1;
			aml_nftl_dbg("nftl found timestamp full node vt blk: %d phy blk: %d \n", nftl_oob_info->vtblk, phy_blk);
			break;
		}
	}
	if (conflict == 1) {
		memcpy((unsigned char *)phy_blk_conflict, (unsigned char *)phy_blk_save, sizeof(addr_blk_t)*(MAX_BLK_NUM_PER_NODE+1));
		memset((unsigned char *)phy_blk_save, 0xff, sizeof(addr_blk_t)*(MAX_BLK_NUM_PER_NODE+1));
		for (j=0; j<(MAX_BLK_NUM_PER_NODE-k); j++)
			phy_blk_save[j] = phy_blk_conflict[k+1+j];

		for (j=0; j<=k; j++) {
			phy_blk_node = &aml_nftl_info->phypmt[phy_blk_conflict[j]];
			for (i=0; i<=MAX_BLK_NUM_PER_NODE; i++) {
				if (phy_blk_save[i] < 0) {
					phy_blk_save[i] = phy_blk_conflict[j];
					break;
				}
				phy_blk_node_curt = &aml_nftl_info->phypmt[phy_blk_save[i]];

				if ((phy_blk_node_curt->timestamp - phy_blk_node->timestamp) >= (MAX_TIMESTAMP_NUM - aml_nftl_info->accessibleblocks))
					continue;
				else {
					if ((phy_blk_node_curt->timestamp - phy_blk_node->timestamp) >= 1) {
						for (m=MAX_BLK_NUM_PER_NODE; m>i; m--)
							phy_blk_save[m] = phy_blk_save[m-1];
						phy_blk_save[m] = phy_blk_conflict[j];
					}
				}
			}
		}
	}

	if (phy_blk_save[MAX_BLK_NUM_PER_NODE] >= 0) {
		aml_nftl_wl->add_free(aml_nftl_wl, phy_blk_save[0]);
		aml_nftl_wl->add_full(aml_nftl_wl, nftl_oob_info->vtblk, phy_blk_save[0]);
		memcpy((unsigned char *)vt_blk_node, (unsigned char *)(&phy_blk_save[1]), sizeof(addr_blk_t)*MAX_BLK_NUM_PER_NODE);
	}
	else {
		memcpy((unsigned char *)vt_blk_node, (unsigned char *)(&phy_blk_save[0]), sizeof(addr_blk_t)*MAX_BLK_NUM_PER_NODE);
	}

	//aml_nftl_dbg("NFTL add logic block to node for logic blk: %d root blk: %d ec: %d\n", nftl_oob_info->vtblk, phy_blk_save[i], phy_blk_node->ec);
	return;
}

static void aml_nftl_check_full_node(struct aml_nftl_info_t *aml_nftl_info, void **timestamp_conflict_node)
{
	struct phyblk_node_t *phy_blk_node, *phy_blk_node_conflict;
	struct vtblk_node_t  *vt_blk_node, *vt_blk_node_conflict;
	struct aml_nftl_wl_t *aml_nftl_wl;
	int error = 0, i = 0, j, k, m, free_num, total_valid = 0, conflict = 0, tmp_timestamp;
	addr_blk_t phy_blk_num, vt_blk_num, ext_phy_blk, phy_blk_full;
	addr_blk_t dest_blk, src_blk;
	addr_page_t dest_page, src_page;
	int16_t valid_page[MAX_BLK_NUM_PER_NODE];

	aml_nftl_wl = aml_nftl_info->aml_nftl_wl;
	for (vt_blk_num=0; vt_blk_num<aml_nftl_info->accessibleblocks; vt_blk_num++) {

		if (timestamp_conflict_node[vt_blk_num] != NULL) {
			vt_blk_node = &aml_nftl_info->vtpmt[vt_blk_num];
			vt_blk_node_conflict = (struct vtblk_node_t *)timestamp_conflict_node[vt_blk_num];
			for (i=(MAX_BLK_NUM_PER_NODE-1); i>=0; i--) {
				if (vt_blk_node->phy_blk_addr[i] >= 0) {
					phy_blk_node = &aml_nftl_info->phypmt[vt_blk_node->phy_blk_addr[i]];
					tmp_timestamp = (phy_blk_node->timestamp + 1);
					break;
				}
			}
			phy_blk_node = &aml_nftl_info->phypmt[vt_blk_node->phy_blk_addr[0]];
			phy_blk_node_conflict = &aml_nftl_info->phypmt[vt_blk_node_conflict->phy_blk_addr[0]];
			if (phy_blk_node->timestamp != phy_blk_node_conflict->timestamp)
				continue;

			for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
				ext_phy_blk = vt_blk_node_conflict->phy_blk_addr[i];
				if (ext_phy_blk >= 0) {
					phy_blk_node_conflict = &aml_nftl_info->phypmt[ext_phy_blk];
					aml_nftl_info->get_phy_sect_map(aml_nftl_info, ext_phy_blk);

					phy_blk_num = vt_blk_node->phy_blk_addr[i];
					if (phy_blk_num >= 0) {
						phy_blk_node = &aml_nftl_info->phypmt[phy_blk_num];
						if (phy_blk_node->timestamp == phy_blk_node_conflict->timestamp) {
							vt_blk_node->phy_blk_addr[i] = BLOCK_INIT_VALUE;
							error = aml_nftl_info->erase_block(aml_nftl_info, phy_blk_num);
							if (error)
								aml_nftl_info->blk_mark_bad(aml_nftl_info, phy_blk_num);
							else
								aml_nftl_wl->add_erased(aml_nftl_wl, phy_blk_num);
						}
						else
							aml_nftl_info->get_phy_sect_map(aml_nftl_info, phy_blk_num);
					}
				}
				else {
					phy_blk_num = vt_blk_node->phy_blk_addr[i];
					if (phy_blk_num >= 0) 
						aml_nftl_info->get_phy_sect_map(aml_nftl_info, phy_blk_num);
				}				
			}

			error = aml_nftl_wl->get_best_free(aml_nftl_wl, &dest_blk);
			if (error)
				continue;
			aml_nftl_wl->add_used(aml_nftl_wl, dest_blk);

			phy_blk_node = &aml_nftl_info->phypmt[dest_blk];
			phy_blk_node->vtblk = vt_blk_num;
			if (tmp_timestamp >= MAX_TIMESTAMP_NUM)
				phy_blk_node->timestamp = 0;
			else
				phy_blk_node->timestamp = (tmp_timestamp + 1);

			for(k=0; k<aml_nftl_wl->pages_per_blk; k++) {

				src_blk = -1;
				for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=0; j--) {
					phy_blk_num = vt_blk_node_conflict->phy_blk_addr[j];
					if (phy_blk_num < 0)
						continue;
					phy_blk_node_conflict = &aml_nftl_info->phypmt[phy_blk_num];
					if (phy_blk_node_conflict->phy_page_map[k] >= 0) {
						src_blk = phy_blk_num;
						src_page = phy_blk_node_conflict->phy_page_map[k];
						break;
					}
				}
				if (src_blk < 0) {
					for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=0; j--) {
						phy_blk_num = vt_blk_node->phy_blk_addr[j];
						if (phy_blk_num < 0)
							continue;
						phy_blk_node_conflict = &aml_nftl_info->phypmt[phy_blk_num];
						if (phy_blk_node_conflict->phy_page_map[k] >= 0) {
							src_blk = phy_blk_num;
							src_page = phy_blk_node_conflict->phy_page_map[k];
							break;
						}
					}
				}
				if (src_blk < 0) 
					continue;

				dest_page = phy_blk_node->last_write + 1;
				aml_nftl_info->copy_page(aml_nftl_info, dest_blk, dest_page, src_blk, src_page);
			}

			for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
				if (vt_blk_node->phy_blk_addr[i] >= 0) {
					aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[i]);
					vt_blk_node->phy_blk_addr[i] = BLOCK_INIT_VALUE;
				}
				if (vt_blk_node_conflict->phy_blk_addr[i] >= 0) {
					aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node_conflict->phy_blk_addr[i]);
					vt_blk_node_conflict->phy_blk_addr[i] = BLOCK_INIT_VALUE;
				}
			}
			vt_blk_node->phy_blk_addr[0] = dest_blk;
			aml_nftl_free(timestamp_conflict_node[vt_blk_num]);
			timestamp_conflict_node[vt_blk_num] = NULL;
			continue;
		}

		if (conflict == 1)
			continue;
		error = aml_nftl_wl->get_full(aml_nftl_wl, vt_blk_num, &phy_blk_full);
		if (error)
			continue;

		vt_blk_node = &aml_nftl_info->vtpmt[vt_blk_num];
		for (i=0; i<MAX_BLK_NUM_PER_NODE; i++) {
			if (vt_blk_node->phy_blk_addr[i] < 0)
				continue;

			phy_blk_num = vt_blk_node->phy_blk_addr[i];
			error = aml_nftl_info->get_phy_sect_map(aml_nftl_info, phy_blk_num);
			if (error)
				continue;
		}

		memset((unsigned char *)valid_page, 0x0, sizeof(int16_t)*MAX_BLK_NUM_PER_NODE);
		for (k=0; k<aml_nftl_info->pages_per_blk; k++) {

			for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=0; j--) {

				if (vt_blk_node->phy_blk_addr[j] < 0)
					continue;

				phy_blk_num = vt_blk_node->phy_blk_addr[j];
				phy_blk_node = &aml_nftl_info->phypmt[phy_blk_num];
				if (phy_blk_node->phy_page_map[k] >= 0) {
					valid_page[j]++;
					break;
				}
			}
		}

		for (j=0; j<MAX_BLK_NUM_PER_NODE; j++) {
			if (valid_page[j] == 0) {
				aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[j]);
				vt_blk_node->phy_blk_addr[j] = BLOCK_INIT_VALUE;
			}
			else 
				break;
		}
		if (j == 0) {

			for (m=0; m<MAX_BLK_NUM_PER_NODE; m++)
				total_valid += valid_page[m];

			ext_phy_blk = vt_blk_node->phy_blk_addr[(MAX_BLK_NUM_PER_NODE - 1)];
			phy_blk_node = &aml_nftl_info->phypmt[ext_phy_blk];
			if ((aml_nftl_info->vtpmt_special->vtblk_node == NULL)
				 	&& (total_valid < aml_nftl_info->pages_per_blk)
					&& (valid_page[MAX_BLK_NUM_PER_NODE-1] >= (phy_blk_node->last_write + 1))) {

				aml_nftl_dbg("found conflict node vt blk: %d phy blk: %d\n", vt_blk_num, phy_blk_full);
				aml_nftl_info->vtpmt_special->vtblk_node = vt_blk_node;
				aml_nftl_info->vtpmt_special->ext_phy_blk_addr = ext_phy_blk;
				for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=1; j--) {
					vt_blk_node->phy_blk_addr[j] = vt_blk_node->phy_blk_addr[j-1];
				}
				vt_blk_node->phy_blk_addr[0] = phy_blk_full;
				aml_nftl_wl->gc_special(aml_nftl_wl);
				conflict = 1;

				continue;
			}
		}
		else {

			free_num = j;
			for (k=0; k<(MAX_BLK_NUM_PER_NODE-free_num); k++) {
				vt_blk_node->phy_blk_addr[k] = vt_blk_node->phy_blk_addr[j];
				j++;
			}
			for (k=(MAX_BLK_NUM_PER_NODE-free_num); k<MAX_BLK_NUM_PER_NODE; k++)
				vt_blk_node->phy_blk_addr[k] = BLOCK_INIT_VALUE;
		}
	}

	return;
}

static void aml_nftl_creat_structure(struct aml_nftl_info_t *aml_nftl_info)
{
	struct phyblk_node_t *phy_blk_node;
	struct vtblk_node_t  *vt_blk_node;
	struct aml_nftl_wl_t *aml_nftl_wl;
	int error = 0, i = 0, j, k, m, free_num, total_valid = 0;
	addr_blk_t phy_blk_num, vt_blk_num, ext_phy_blk;
	int16_t valid_page[MAX_BLK_NUM_PER_NODE];

	aml_nftl_wl = aml_nftl_info->aml_nftl_wl;
	for (vt_blk_num=aml_nftl_info->cur_split_blk; vt_blk_num<aml_nftl_info->accessibleblocks; vt_blk_num++) {

		if ((vt_blk_num - aml_nftl_info->cur_split_blk) >= DEFAULT_SPLIT_UNIT)
			break;

		vt_blk_node = &aml_nftl_info->vtpmt[vt_blk_num];
		if (vt_blk_node->phy_blk_addr[0] < 0)
			continue;

		i = 0;
		do {

			phy_blk_num = vt_blk_node->phy_blk_addr[i];
			if ((phy_blk_num < 0) || (i >= MAX_BLK_NUM_PER_NODE))
				break;

			phy_blk_node = &aml_nftl_info->phypmt[phy_blk_num];
			if (phy_blk_node->status_page == STATUS_BAD_BLOCK) {
				i++;
				aml_nftl_dbg("creat phy sect map found bad block: %d vt blk : %d\n", phy_blk_num, vt_blk_num);
				continue;
			}

			error = aml_nftl_info->get_phy_sect_map(aml_nftl_info, phy_blk_num);
			if (error) {
				aml_nftl_dbg("creat phy sect map failed: %d\n", phy_blk_num);
				//aml_nftl_info->accessibleblocks--;
				i++;
				continue;
			}

		}while ((i++) < MAX_BLK_NUM_PER_NODE);

		if (vt_blk_node->phy_blk_addr[1] < 0)
			continue;

		memset((unsigned char *)valid_page, 0x0, sizeof(int16_t)*MAX_BLK_NUM_PER_NODE);
		for (k=0; k<aml_nftl_info->pages_per_blk; k++) {

			for (j=(i - 1); j>=0; j--) {

				if (vt_blk_node->phy_blk_addr[j] < 0)
					continue;

				phy_blk_num = vt_blk_node->phy_blk_addr[j];
				phy_blk_node = &aml_nftl_info->phypmt[phy_blk_num];
				if (phy_blk_node->phy_page_map[k] >= 0) {
					valid_page[j]++;
					break;
				}
			}
		}

		for (j=0; j<i; j++) {
			if (valid_page[j] == 0) {
				//aml_nftl_dbg("nftl add free used block : %d i: %d vt blk: %d\n", vt_blk_node->phy_blk_addr[j], i, vt_blk_num);
				aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[j]);
				vt_blk_node->phy_blk_addr[j] = BLOCK_INIT_VALUE;
			}
			else 
				break;
		}
		if ((i >= MAX_BLK_NUM_PER_NODE) && (valid_page[0] > 0)) {

			for (m=0; m<i; m++)
				total_valid += valid_page[m];

			ext_phy_blk = vt_blk_node->phy_blk_addr[(MAX_BLK_NUM_PER_NODE - 1)];
			phy_blk_node = &aml_nftl_info->phypmt[ext_phy_blk];
			if ((aml_nftl_info->vtpmt_special->vtblk_node == NULL)
				 	&& (total_valid < aml_nftl_info->pages_per_blk)
					&& (valid_page[MAX_BLK_NUM_PER_NODE-1] >= (phy_blk_node->last_write + 1))) {

				error = aml_nftl_wl->get_full(aml_nftl_wl, vt_blk_num, &phy_blk_num);
				if (error)
					continue;

				aml_nftl_dbg("found conflict node vt blk: %d phy blk: %d\n", vt_blk_num, phy_blk_num);
				error = aml_nftl_info->get_phy_sect_map(aml_nftl_info, phy_blk_num);
				if (error)
					continue;

				aml_nftl_info->vtpmt_special->vtblk_node = vt_blk_node;
				aml_nftl_info->vtpmt_special->ext_phy_blk_addr = ext_phy_blk;
				for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=1; j--) {
					vt_blk_node->phy_blk_addr[j] = vt_blk_node->phy_blk_addr[j-1];
				}
				vt_blk_node->phy_blk_addr[0] = phy_blk_num;
				error = aml_nftl_wl->gc_special(aml_nftl_wl);
				if (error)
					continue;

				continue;
			}
		}

		free_num = j;
		for (k=0; k<(MAX_BLK_NUM_PER_NODE-free_num); k++) 
			vt_blk_node->phy_blk_addr[k] = vt_blk_node->phy_blk_addr[j++];

		for (k=(MAX_BLK_NUM_PER_NODE-free_num); k<MAX_BLK_NUM_PER_NODE; k++) 
			vt_blk_node->phy_blk_addr[k] = BLOCK_INIT_VALUE;
	}

	aml_nftl_info->cur_split_blk = vt_blk_num;
	if (aml_nftl_info->cur_split_blk >= aml_nftl_info->accessibleblocks) {
		if ((aml_nftl_wl->free_root.count <= DEFAULT_IDLE_FREE_BLK) && (!aml_nftl_wl->erased_root.count))
			aml_nftl_wl->gc_need_flag = 1;

		aml_nftl_info->isinitialised = 1;
		aml_nftl_wl->gc_start_block = aml_nftl_info->accessibleblocks - 1;
		aml_nftl_dbg("nftl creat stucture completely free blk: %d erased blk: %d\n", aml_nftl_wl->free_root.count, aml_nftl_wl->erased_root.count);
	}

	return;
}

int aml_nftl_initialize(struct aml_nftl_blk_t *aml_nftl_blk)
{
	struct mtd_info *mtd = aml_nftl_blk->mbd.mtd;
	struct nftl_oobinfo_t *nftl_oob_info;
	struct aml_nftl_wl_t *aml_nftl_wl;
	struct phyblk_node_t *phy_blk_node;
	int error = 0, phy_blk_num;
	uint32_t phy_page_addr, size_in_blk;
	uint32_t phys_erase_shift;
	void **timestamp_conflict_node;
	unsigned char nftl_oob_buf[sizeof(struct nftl_oobinfo_t)];

	struct aml_nftl_info_t *aml_nftl_info = aml_nftl_malloc(sizeof(struct aml_nftl_info_t));
	if (!aml_nftl_info)
		return -ENOMEM;

	aml_nftl_blk->aml_nftl_info = aml_nftl_info;
	aml_nftl_info->mtd = mtd;
	aml_nftl_info->writesize = mtd->writesize;
	aml_nftl_info->oobsize = mtd->oobsize;
	phys_erase_shift = ffs(mtd->erasesize) - 1;
	size_in_blk =  (mtd->size >> phys_erase_shift);
	if (size_in_blk <= AML_LIMIT_FACTOR)
		return -EPERM;

	aml_nftl_info->pages_per_blk = mtd->erasesize / mtd->writesize;
	aml_nftl_info->fillfactor = (size_in_blk / 32);
	if (aml_nftl_info->fillfactor < AML_LIMIT_FACTOR)
		aml_nftl_info->fillfactor = AML_LIMIT_FACTOR;
	aml_nftl_info->accessibleblocks = size_in_blk - aml_nftl_info->fillfactor;

	aml_nftl_info->copy_page_buf = aml_nftl_malloc(aml_nftl_info->writesize);
	if (!aml_nftl_info->copy_page_buf)
		return -ENOMEM;
	aml_nftl_info->phypmt = aml_nftl_malloc((sizeof(struct phyblk_node_t) * size_in_blk));
	if (!aml_nftl_info->phypmt)
		return -ENOMEM;
	aml_nftl_info->vtpmt = aml_nftl_malloc((sizeof(struct vtblk_node_t) * aml_nftl_info->accessibleblocks));
	if (!aml_nftl_info->vtpmt)
		return -ENOMEM;
	aml_nftl_info->vtpmt_special = aml_nftl_malloc(sizeof(struct vtblk_special_node_t));
	if (!aml_nftl_info->vtpmt_special)
		return -ENOMEM;
	aml_nftl_info->vtpmt_special = aml_nftl_malloc(sizeof(struct vtblk_special_node_t));
	if (!aml_nftl_info->vtpmt_special)
		return -ENOMEM;
	timestamp_conflict_node = (void **)aml_nftl_malloc(sizeof(void *) * aml_nftl_info->accessibleblocks);
	if (!timestamp_conflict_node)
		return -ENOMEM;

	aml_nftl_info->vtpmt_special->vtblk_node = NULL;
	aml_nftl_info->vtpmt_special->ext_phy_blk_addr = BLOCK_INIT_VALUE;
	memset((unsigned char *)aml_nftl_info->phypmt, 0xff, sizeof(struct phyblk_node_t)*size_in_blk);
	memset((unsigned char *)aml_nftl_info->vtpmt, 0xff, sizeof(struct vtblk_node_t)*aml_nftl_info->accessibleblocks);

	aml_nftl_ops_init(aml_nftl_info);

	aml_nftl_info->read_page = aml_nftl_read_page;
	aml_nftl_info->write_pages = aml_nftl_write_pages;
	aml_nftl_info->copy_page = aml_nftl_copy_page;
	aml_nftl_info->get_page_status = aml_nftl_get_page_status;
	aml_nftl_info->blk_mark_bad = aml_nftl_blk_mark_bad;
	aml_nftl_info->blk_isbad = aml_nftl_blk_isbad;
	aml_nftl_info->get_block_status = aml_nftl_get_block_status;
	aml_nftl_info->get_phy_sect_map = aml_nftl_get_phy_sect_map;
	aml_nftl_info->erase_block = aml_nftl_erase_block;

	aml_nftl_info->read_sect = aml_nftl_read_sect;
	aml_nftl_info->write_sects = aml_nftl_write_sects;
	aml_nftl_info->creat_structure = aml_nftl_creat_structure;

	error = aml_nftl_wl_init(aml_nftl_info);
	if (error)
		return error;

	aml_nftl_wl = aml_nftl_info->aml_nftl_wl;
	nftl_oob_info = (struct nftl_oobinfo_t *)nftl_oob_buf;
	for (phy_blk_num=0; phy_blk_num<size_in_blk; phy_blk_num++) {

		phy_page_addr = 0;
		phy_blk_node = &aml_nftl_info->phypmt[phy_blk_num];

		error = aml_nftl_info->blk_isbad(aml_nftl_info, phy_blk_num);
		if (error) {
			aml_nftl_info->accessibleblocks--;
			aml_nftl_dbg("nftl detect bad blk at : %d \n", phy_blk_num);
			continue;
		}

		error = aml_nftl_info->get_page_status(aml_nftl_info, phy_blk_num, phy_page_addr, nftl_oob_buf);
		if (error) {
			aml_nftl_info->accessibleblocks--;
			phy_blk_node->status_page = STATUS_BAD_BLOCK;
			aml_nftl_dbg("get status error at blk: %d \n", phy_blk_num);
			continue;
		}

		if (nftl_oob_info->status_page == 0) {
			aml_nftl_info->accessibleblocks--;
			aml_nftl_dbg("get status faile at blk: %d \n", phy_blk_num);
			aml_nftl_info->blk_mark_bad(aml_nftl_info, phy_blk_num);
			continue;
		}

		if (nftl_oob_info->vtblk == -1) {
			phy_blk_node->valid_sects = 0;
			phy_blk_node->ec = 0;
			aml_nftl_wl->add_erased(aml_nftl_wl, phy_blk_num);	
		}
		else if ((nftl_oob_info->vtblk < 0) || (nftl_oob_info->vtblk >= (size_in_blk - aml_nftl_info->fillfactor))) {
			aml_nftl_dbg("nftl invalid vtblk: %d \n", nftl_oob_info->vtblk);
			error = aml_nftl_info->erase_block(aml_nftl_info, phy_blk_num);
			if (error) {
				aml_nftl_info->accessibleblocks--;
				phy_blk_node->status_page = STATUS_BAD_BLOCK;
				aml_nftl_info->blk_mark_bad(aml_nftl_info, phy_blk_num);
			}
			else {
				phy_blk_node->valid_sects = 0;
				phy_blk_node->ec = 0;
				aml_nftl_wl->add_erased(aml_nftl_wl, phy_blk_num);
			}
		}
		else {
			aml_nftl_add_block(aml_nftl_info, phy_blk_num, nftl_oob_info, timestamp_conflict_node);
			aml_nftl_wl->add_used(aml_nftl_wl, phy_blk_num);
		}
	}

	aml_nftl_check_full_node(aml_nftl_info, timestamp_conflict_node);

	aml_nftl_free(timestamp_conflict_node);
	aml_nftl_info->isinitialised = 0;
	aml_nftl_info->cur_split_blk = 0;
	aml_nftl_wl->gc_start_block = aml_nftl_info->accessibleblocks - 1;
	aml_nftl_blk->mbd.size = (aml_nftl_info->accessibleblocks * (mtd->erasesize  >> 9));
	aml_nftl_dbg("nftl initilize completely dev size: 0x%lx \n", aml_nftl_blk->mbd.size * 512);

	return 0;
}

void aml_nftl_info_release(struct aml_nftl_info_t *aml_nftl_info)
{
	if (aml_nftl_info->vtpmt)
		aml_nftl_free(aml_nftl_info->vtpmt);
	if (aml_nftl_info->phypmt)
		aml_nftl_free(aml_nftl_info->phypmt);
	if (aml_nftl_info->aml_nftl_wl)
		aml_nftl_free(aml_nftl_info->aml_nftl_wl);
}

