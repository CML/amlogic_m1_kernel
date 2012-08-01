
/*
 * Aml nftl ops
 *
 * (C) 2010 10
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/nand.h>
#include <linux/mtd/nand_ecc.h>
#include <linux/mtd/compatmac.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
#include <linux/leds.h>

#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/vmalloc.h>

#include <linux/mtd/blktrans.h>
#include <linux/mutex.h>

#include "aml_nftl.h"

static int aml_ops_read_page(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr, addr_page_t page_addr, 
								unsigned char *data_buf, unsigned char *nftl_oob_buf)
{
	struct mtd_info *mtd = aml_nftl_info->mtd;
	struct mtd_oob_ops aml_oob_ops;
	loff_t from;
	size_t len, retlen;
	int ret;

	from = mtd->erasesize;
	from *= blk_addr;
	from += page_addr * mtd->writesize;

	len = mtd->writesize;
	aml_oob_ops.mode = MTD_OOB_AUTO;
	aml_oob_ops.len = mtd->writesize;
	aml_oob_ops.ooblen = sizeof(struct nftl_oobinfo_t);
	aml_oob_ops.ooboffs = mtd->ecclayout->oobfree[0].offset;
	aml_oob_ops.datbuf = data_buf;
	aml_oob_ops.oobbuf = nftl_oob_buf;

	if (nftl_oob_buf)
		ret = mtd->read_oob(mtd, from, &aml_oob_ops);
	else
		ret = mtd->read(mtd, from, len, &retlen, data_buf);

	if (ret == -EUCLEAN) {
		//if (mtd->ecc_stats.corrected >= 10)
			//do read err 
		ret = 0;
	}

	return ret;
}

static int aml_ops_write_pages(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr, addr_page_t page_addr, 
								unsigned page_nums, unsigned char *data_buf, unsigned char *nftl_oob_buf)
{
	struct mtd_info *mtd = aml_nftl_info->mtd;
	struct mtd_oob_ops aml_oob_ops;
	loff_t from;
	size_t len, retlen;
	int ret;

	from = mtd->erasesize;
	from *= blk_addr;
	from += page_addr * mtd->writesize;

	len = mtd->writesize * page_nums;
	aml_oob_ops.mode = MTD_OOB_AUTO;
	aml_oob_ops.len = mtd->writesize * page_nums;
	aml_oob_ops.ooblen = sizeof(struct nftl_oobinfo_t) * page_nums;
	aml_oob_ops.ooboffs = mtd->ecclayout->oobfree[0].offset;
	aml_oob_ops.datbuf = data_buf;
	aml_oob_ops.oobbuf = nftl_oob_buf;

	if (nftl_oob_buf)
		ret = mtd->write_oob(mtd, from, &aml_oob_ops);
	else
		ret = mtd->write(mtd, from, len, &retlen, data_buf);

	return ret;
}

static int aml_ops_get_page_status(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t blk_addr, 
										addr_page_t page_addr, unsigned char * nftl_oob_buf)
{
	struct mtd_info *mtd = aml_nftl_info->mtd;
	struct mtd_oob_ops aml_oob_ops;
	struct mtd_ecc_stats stats;
	loff_t from;
	int ret;

	stats = mtd->ecc_stats;
	from = mtd->erasesize;
	from *= blk_addr;
	from += page_addr * mtd->writesize;

	aml_oob_ops.mode = MTD_OOB_AUTO;
	aml_oob_ops.len = 0;
	aml_oob_ops.ooblen = sizeof(struct nftl_oobinfo_t);
	aml_oob_ops.ooboffs = mtd->ecclayout->oobfree[0].offset;
	aml_oob_ops.datbuf = NULL;
	aml_oob_ops.oobbuf = nftl_oob_buf;

	ret = mtd->read_oob(mtd, from, &aml_oob_ops);

	if (ret == -EUCLEAN) {
		//if (mtd->ecc_stats.corrected >= 10)
			//do read err 
		ret = 0;
	}

	return ret;
}

static int aml_ops_blk_isbad(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t blk_addr)
{
	struct mtd_info *mtd = aml_nftl_info->mtd;
	loff_t from;

	from = mtd->erasesize;
	from *= blk_addr;

	return mtd->block_isbad(mtd, from);
}

static int aml_ops_blk_mark_bad(struct aml_nftl_info_t *aml_nftl_info, addr_blk_t blk_addr)
{
	struct mtd_info *mtd = aml_nftl_info->mtd;
	loff_t from;

	from = mtd->erasesize;
	from *= blk_addr;

	return mtd->block_markbad(mtd, from);
}

static int aml_ops_erase_block(struct aml_nftl_info_t * aml_nftl_info, addr_blk_t blk_addr)
{
	struct mtd_info *mtd = aml_nftl_info->mtd;
	struct erase_info aml_nftl_erase_info;

	memset(&aml_nftl_erase_info, 0, sizeof(struct erase_info));
	aml_nftl_erase_info.mtd = mtd;
	aml_nftl_erase_info.addr = mtd->erasesize;
	aml_nftl_erase_info.addr *= blk_addr;
	aml_nftl_erase_info.len = mtd->erasesize;

	return mtd->erase(mtd, &aml_nftl_erase_info);
}

void aml_nftl_ops_init(struct aml_nftl_info_t *aml_nftl_info)
{
	struct aml_nftl_ops_t *aml_nftl_ops = aml_nftl_malloc(sizeof(struct aml_nftl_ops_t));
	if (!aml_nftl_ops)
		return;

	aml_nftl_info->aml_nftl_ops = aml_nftl_ops;
	aml_nftl_ops->read_page = aml_ops_read_page;
	aml_nftl_ops->write_pages = aml_ops_write_pages;
	aml_nftl_ops->get_page_status = aml_ops_get_page_status;
	aml_nftl_ops->blk_isbad = aml_ops_blk_isbad;
	aml_nftl_ops->blk_mark_bad = aml_ops_blk_mark_bad;
	aml_nftl_ops->erase_block = aml_ops_erase_block;

	return;
}

