/**
 *wl.c - jnftl wear leveling & garbage collection
 */
 
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/kthread.h>
#include <linux/freezer.h>

#include "aml_nftl.h"

#define list_to_node(l)	container_of(l, struct wl_list_t, list)
/**
 * construct_lnode - construct list node
 * @ vblk : logical block addr
 *
 *     1. check valid block addr
 *     2. malloc node
 *     3. evaluate logical block
 *
 * If the logical block is not a valid value, NULL will be returned, 
 * else return list node
 */
static inline struct wl_list_t *construct_lnode(struct aml_nftl_wl_t* wl, addr_blk_t vt_blk, addr_blk_t phy_blk)
{
	struct wl_list_t *lnode;

	if(vt_blk == BLOCK_INIT_VALUE)
		return NULL;

	lnode = aml_nftl_malloc(sizeof(struct wl_list_t));
	if(lnode) {
		lnode->vt_blk = vt_blk;
		lnode->phy_blk = phy_blk;
		
	}
	return lnode;
}

/**
 * construct_tnode - construct tree node
 * @ blk : linear block addr
 *
 *     1. check valid block addr
 *     2. malloc node
 *     3. evaluate linear block & ec
 *
 * If the linear block is not a valid value, NULL will be returned, 
 * else return tree node
 */
static inline struct wl_rb_t* construct_tnode(struct aml_nftl_wl_t* wl, addr_blk_t blk)
{
	struct aml_nftl_info_t *aml_nftl_info = wl->aml_nftl_info;
	struct wl_rb_t* tnode;
	struct phyblk_node_t *phy_blk_node;

	if(blk == BLOCK_INIT_VALUE)
		return NULL;

	phy_blk_node = &aml_nftl_info->phypmt[blk];
	tnode = aml_nftl_malloc(sizeof(struct wl_rb_t));
	if(tnode){
		tnode->blk = blk;
		tnode->ec = phy_blk_node->ec;
	}
	return tnode;
}

/**
 * del_from_tree - delete tree node from redblack tree
 * @ tree : free / erased / used tree
 * @ tnode : tree node
 *
 * Erase tree node & tree count-- & free
 */
static void del_from_tree(struct aml_nftl_wl_t* wl, struct wl_tree_t* tree, struct wl_rb_t* tnode)
{
	rb_erase(&tnode->rb_node, &tree->root);
	tree->count--;
	aml_nftl_free(tnode);
	return;
}

/**
 * _del_free - delete tree node from free tree
 */
static inline void _del_free(struct aml_nftl_wl_t* wl, struct wl_rb_t* tnode)
{
	del_from_tree(wl, &wl->free_root, tnode);
	return;
}

/**
 * _del_free - delete tree node from used tree
 */
static inline void _del_used(struct aml_nftl_wl_t* wl, struct wl_rb_t* tnode)
{
	del_from_tree(wl, &wl->used_root, tnode);
}

/**
 * _del_free - delete tree node from erased tree
 */
static inline void _del_erased(struct aml_nftl_wl_t* wl, struct wl_rb_t* tnode)
{
	del_from_tree(wl, &wl->erased_root, tnode);
}


/**
 * add_tree - add tree node into redblack tree
 * @ tree : free / erased / used tree
 * @ tnode : tree node
 *
 * To avoid the same ec in the rb tree, as to get confused in rb_left & rb_right,
 * we make a new value: ec<<16+blk to make tree, without modify rb structure
 *     1. make ec blk
 *     2. find a suitable place in tree
 *     3. linke node & insert it at the place we just found
 *     4. add tree node number
 */
static void add_tree(struct aml_nftl_wl_t* wl, struct wl_tree_t* tree, struct wl_rb_t* tnode)
{
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct wl_rb_t *cur;
	uint32_t  node_ec_blk = MAKE_EC_BLK(tnode->ec, tnode->blk);
	uint32_t  cur_ec_blk;

	while (*p) {
		parent = *p;
		cur = rb_entry(parent, struct wl_rb_t, rb_node);
		cur_ec_blk = MAKE_EC_BLK(cur->ec, cur->blk);

		if (node_ec_blk < cur_ec_blk)
			p = &parent->rb_left;
		else
			p = &parent->rb_right;
	}
	rb_link_node(&tnode->rb_node, parent, p);
	rb_insert_color(&tnode->rb_node, &tree->root);
	
	tree->count++;
	return;
}

/**
 * search_tree - search ec_blk from the rb tree, get the tree node
 * @ tree : tree searched in
 * @ blk : linear block addr
 * @ ec : erase count
 *
 * To avoid the same ec in the rb tree, as to get confused in rb_left & rb_right,
 * we make a new value: ec<<16+blk to make tree, without modify rb structure
 *     1. make ec blk
 *     2. search the same ec_blk in the tree
 *     3. return tree node or NULL
 */
static struct wl_rb_t* search_tree(struct aml_nftl_wl_t* wl, struct wl_tree_t* tree, addr_blk_t blk, 
						erase_count_t ec)
{
	struct rb_node **p = &tree->root.rb_node;
	struct rb_node *parent = NULL;
	struct wl_rb_t* cur;
	uint32_t  node_ec_blk = MAKE_EC_BLK(ec, blk);
	uint32_t  cur_ec_blk;

	while(*p){
		parent = *p;
		cur = rb_entry(parent, struct wl_rb_t, rb_node);
		cur_ec_blk = MAKE_EC_BLK(cur->ec, cur->blk);

		if(node_ec_blk < cur_ec_blk)
			p = &parent->rb_left;
		else if(node_ec_blk > cur_ec_blk)
			p = &parent->rb_right;
		else
			return cur;
	}

	return NULL;	
}

static void add_used(struct aml_nftl_wl_t* wl, addr_blk_t blk)
{
	struct wl_rb_t* tnode;

	tnode = construct_tnode(wl, blk);
	if(tnode)
		add_tree(wl, &wl->used_root, tnode);

	return;
}

/**
 * add_erased - add erased free block info erase rb_tree
 * @ blk : linear block addr
 */
static void add_erased(struct aml_nftl_wl_t* wl, addr_blk_t blk)
{
	struct aml_nftl_info_t *aml_nftl_info = wl->aml_nftl_info;
	struct phyblk_node_t *phy_blk_node;
	struct wl_rb_t* tnode;

	phy_blk_node = &aml_nftl_info->phypmt[blk];
	tnode = search_tree(wl, &wl->used_root, blk, phy_blk_node->ec);
	if (tnode)
		_del_used(wl, tnode);

	tnode = construct_tnode(wl, blk);
	if(tnode)
		add_tree(wl, &wl->erased_root, tnode);
}


/**
 * add_free - add free block into free rb tree
 * @ blk : linear block addr
 *
 *     1. construct tree node
 *     2. add node into free rb tree
 *     3. update current delta(current free block ec - coldest used block)
 */
static void add_free(struct aml_nftl_wl_t * wl, addr_blk_t blk)
{
	struct aml_nftl_info_t *aml_nftl_info = wl->aml_nftl_info;
	struct phyblk_node_t *phy_blk_node;
	struct wl_rb_t* tnode_cold;	
	struct wl_rb_t* tnode;

	if (blk < 0)
		return;

	phy_blk_node = &aml_nftl_info->phypmt[blk];
	tnode = search_tree(wl, &wl->used_root, blk, phy_blk_node->ec);
	if (tnode)
		_del_used(wl, tnode);

	tnode = construct_tnode(wl, blk);
	if(tnode) {
		add_tree(wl, &wl->free_root, tnode);

		/*update current delta(current free block, coldest block)*/
		tnode_cold = rb_entry(rb_first(&wl->used_root.root), struct wl_rb_t, rb_node);
		if ((tnode->ec > tnode_cold->ec) && (tnode_cold->ec > 0) && (tnode->ec > 0))
			wl->cur_delta = tnode->ec - tnode_cold->ec;
	}
}

static void add_node_full(struct aml_nftl_wl_t* wl, addr_blk_t vt_blk, addr_blk_t phy_blk)
{
	struct wl_list_t* lnode, *lnode_add;
	struct list_head *l, *n;
	struct phyblk_node_t *phy_blk_node, *phy_blk_tmp_node;
	struct aml_nftl_info_t *aml_nftl_info = wl->aml_nftl_info;

	phy_blk_node = &aml_nftl_info->phypmt[phy_blk];
	if (!list_empty(&wl->node_full_head.list)) {
		list_for_each_safe(l, n, &wl->node_full_head.list) {

			lnode = list_to_node(l);
			if (lnode->vt_blk == vt_blk) {
				phy_blk_tmp_node = &aml_nftl_info->phypmt[lnode->phy_blk];
				if (phy_blk_tmp_node->timestamp < phy_blk_node->timestamp) {
					if ((phy_blk_node->timestamp - phy_blk_tmp_node->timestamp) < (MAX_TIMESTAMP_NUM - aml_nftl_info->accessibleblocks)) {
						list_del(&lnode->list);
						aml_nftl_free(lnode);
					}
					else
						return;
				}
				else {
					if ((phy_blk_tmp_node->timestamp - phy_blk_node->timestamp) >= (MAX_TIMESTAMP_NUM - aml_nftl_info->accessibleblocks)) {
						list_del(&lnode->list);
						aml_nftl_free(lnode);
					}
					else
						return;
				}
			}
		}
	}

	lnode_add = construct_lnode(wl, vt_blk, phy_blk);
	if(lnode_add)
		list_add(&lnode_add->list, &wl->node_full_head.list);

	return;
}

static int32_t get_node_full(struct aml_nftl_wl_t* wl, addr_blk_t vt_blk, addr_blk_t *phy_blk)
{
	struct wl_list_t* lnode;
	struct list_head *l, *n;

	if (list_empty(&wl->node_full_head.list))
		return -ENOENT;

	list_for_each_safe(l, n, &wl->node_full_head.list) {

		lnode = list_to_node(l);
		if (lnode->vt_blk == vt_blk) {
			*phy_blk = lnode->phy_blk;
			list_del(&lnode->list);
			aml_nftl_free(lnode);
			return 0;
		}
	}

	return -ENOENT;
}

/**
 * staticwl_linear_blk - static wear leveling this linear block
 * @ blk : root linear block
 * 
 * Static wl block should be the logical block only with root block
 *
 *     1. get root sector map
 *     2. get best free block
 *     3. calculate src, dest page addr base
 *     4. do copy_page from 0 to block end
 *     5. add this block to free tree
 */
static int32_t staticwl_linear_blk(struct aml_nftl_wl_t* aml_nftl_wl, addr_blk_t blk)
{
	struct aml_nftl_info_t *aml_nftl_info = aml_nftl_wl->aml_nftl_info;
	struct phyblk_node_t *phy_blk_node_src, *phy_blk_node_dest;
	struct vtblk_node_t  *vt_blk_node;
	uint16_t i;
	addr_blk_t dest_blk, src_blk;
	addr_page_t dest_page;
	addr_page_t src_page;

	if(aml_nftl_wl->get_best_free(aml_nftl_wl, &dest_blk))
		return -ENOENT;

	aml_nftl_wl->add_used(aml_nftl_wl, dest_blk);
	vt_blk_node = &aml_nftl_info->vtpmt[blk];
	src_blk = vt_blk_node->phy_blk_addr[0];
	phy_blk_node_src = &aml_nftl_info->phypmt[src_blk];

	phy_blk_node_dest = &aml_nftl_info->phypmt[dest_blk];
	phy_blk_node_dest->vtblk = phy_blk_node_src->vtblk;
	if (phy_blk_node_src->timestamp >= MAX_TIMESTAMP_NUM)
		phy_blk_node_dest->timestamp = 0;
	else
		phy_blk_node_dest->timestamp = (phy_blk_node_src->timestamp + 1);

	dest_page = 0;
	for(i=0; i<aml_nftl_wl->pages_per_blk; i++){

		src_page = phy_blk_node_src->phy_page_map[i];
		if (src_page < 0)
			continue;

		dest_page = phy_blk_node_dest->last_write + 1;
		aml_nftl_info->copy_page(aml_nftl_info, dest_blk, dest_page, src_blk, src_page);
	}

	aml_nftl_wl->add_free(aml_nftl_wl, src_blk);
	vt_blk_node->phy_blk_addr[0] = dest_blk;
	return 0;
}

static int gc_get_dirty_block(struct aml_nftl_wl_t* aml_nftl_wl, uint8_t gc_flag)
{
	struct aml_nftl_info_t *aml_nftl_info = aml_nftl_wl->aml_nftl_info;
	struct phyblk_node_t *phy_blk_node_src, *phy_blk_node_dest;
	struct vtblk_node_t  *vt_blk_node;
	int16_t i, j, k, free_num, free_num2, valid_page[MAX_BLK_NUM_PER_NODE], erase_gc_num = 0, copy_gc_num = 0;
	addr_blk_t dest_blk, src_blk;
	addr_page_t dest_page, src_page;
	unsigned valid_page_save;

	for (i=aml_nftl_wl->gc_start_block; i>=0; i--) {

		vt_blk_node = &aml_nftl_info->vtpmt[i];
		if (vt_blk_node->phy_blk_addr[0] < 0)
			continue;

		if (vt_blk_node->phy_blk_addr[1] < 0) {
			if(aml_nftl_wl->cur_delta >= aml_nftl_wl->wl_delta)
				staticwl_linear_blk(aml_nftl_wl, i);

			continue;
		}

		memset((unsigned char *)valid_page, 0x0, sizeof(int16_t)*MAX_BLK_NUM_PER_NODE);
		for (k=0; k<aml_nftl_wl->pages_per_blk; k++) {

			for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=0; j--) {

				if (vt_blk_node->phy_blk_addr[j] < 0)
					continue;

				phy_blk_node_src = &aml_nftl_info->phypmt[vt_blk_node->phy_blk_addr[j]];
				aml_nftl_info->get_phy_sect_map(aml_nftl_info, vt_blk_node->phy_blk_addr[j]);
				if (phy_blk_node_src->phy_page_map[k] >= 0) {
					valid_page[j]++;
					break;
				}
			}
		}

		for (j=0; j<MAX_BLK_NUM_PER_NODE; j++) {
			if (valid_page[j] == 0) {
				aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[j]);
				vt_blk_node->phy_blk_addr[j] = BLOCK_INIT_VALUE;
				erase_gc_num++;
			}
			else 
				break;
		}
		free_num = j;
		free_num2 = free_num;
		for (k=0; k<(MAX_BLK_NUM_PER_NODE-free_num); k++) {
			vt_blk_node->phy_blk_addr[k] = vt_blk_node->phy_blk_addr[j];
			valid_page[k] = valid_page[j];
			j++;
		}

		for (k=(MAX_BLK_NUM_PER_NODE-free_num); k<MAX_BLK_NUM_PER_NODE; k++) {
			vt_blk_node->phy_blk_addr[k] = BLOCK_INIT_VALUE;
			valid_page[k] = 0;
		}
		if (erase_gc_num >= 4)
			break;

		//if space is small do copy page garbage collect
		if (gc_flag == DO_COPY_PAGE) {

			if ((vt_blk_node->phy_blk_addr[1] < 0) || (vt_blk_node->phy_blk_addr[0] < 0))
				continue;

			for (k=2; k<MAX_BLK_NUM_PER_NODE; k++) {

				if (vt_blk_node->phy_blk_addr[k] < 0)
					break;
				phy_blk_node_dest = &aml_nftl_info->phypmt[vt_blk_node->phy_blk_addr[k]];
				//aml_nftl_dbg("nftl vt node phy blk: %d valid page: %d last write: %d vt blk: %d\n", vt_blk_node->phy_blk_addr[k], valid_page[k], phy_blk_node_dest->last_write, i);
			}

			dest_blk = vt_blk_node->phy_blk_addr[k-1];
			free_num = (k - 2);
			free_num2 = free_num;
			phy_blk_node_dest = &aml_nftl_info->phypmt[dest_blk];

			if (valid_page[k-1] >= (phy_blk_node_dest->last_write + 1)) {
				//needn`t get free block just copy in node

				valid_page_save = valid_page[k-1];

				for(k=0; k<aml_nftl_wl->pages_per_blk; k++) {

					if (phy_blk_node_dest->phy_page_map[k] >= 0)
						continue;

					free_num = free_num2;
					do {
						src_blk = vt_blk_node->phy_blk_addr[free_num];
						phy_blk_node_src = &aml_nftl_info->phypmt[src_blk];
						if (phy_blk_node_src->phy_page_map[k] >= 0) {
							src_page = phy_blk_node_src->phy_page_map[k];
							break;
						}
						free_num--;

					}while (free_num >= 0);
					if (free_num < 0) 
						continue;

					dest_page = phy_blk_node_dest->last_write + 1;
					aml_nftl_info->copy_page(aml_nftl_info, dest_blk, dest_page, src_blk, src_page);
				}

				for (j=0; j<=free_num2; j++) {
					if (vt_blk_node->phy_blk_addr[j] < 0)
						aml_nftl_dbg("nftl garbage copy in node block addr: %d  %d  %d  %d %d\n", vt_blk_node->phy_blk_addr[0], vt_blk_node->phy_blk_addr[1], vt_blk_node->phy_blk_addr[2], vt_blk_node->phy_blk_addr[3], j);
					aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[j]);
					vt_blk_node->phy_blk_addr[j] = BLOCK_INIT_VALUE;
					copy_gc_num++;
				}	
				vt_blk_node->phy_blk_addr[0] = dest_blk;
				vt_blk_node->phy_blk_addr[free_num2+1] = BLOCK_INIT_VALUE;		
			}
			else {
				if(aml_nftl_wl->get_best_free(aml_nftl_wl, &dest_blk))
					continue;

				aml_nftl_wl->add_used(aml_nftl_wl, dest_blk);
				free_num++;
				free_num2 = free_num;
				phy_blk_node_src = &aml_nftl_info->phypmt[vt_blk_node->phy_blk_addr[free_num]];
				phy_blk_node_dest = &aml_nftl_info->phypmt[dest_blk];
				phy_blk_node_dest->vtblk = i;
				if (phy_blk_node_src->timestamp >= MAX_TIMESTAMP_NUM)
					phy_blk_node_dest->timestamp = 0;
				else
					phy_blk_node_dest->timestamp = (phy_blk_node_src->timestamp + 1);

				for(k=0; k<aml_nftl_wl->pages_per_blk; k++) {

					free_num = free_num2;
					do {
						src_blk = vt_blk_node->phy_blk_addr[free_num];
						phy_blk_node_src = &aml_nftl_info->phypmt[src_blk];
						if (phy_blk_node_src->phy_page_map[k] >= 0) {
							src_page = phy_blk_node_src->phy_page_map[k];
							break;
						}
						free_num--;

					}while (free_num >= 0);
					if (free_num < 0)
						continue;

					dest_page = phy_blk_node_dest->last_write + 1;
					aml_nftl_info->copy_page(aml_nftl_info, dest_blk, dest_page, src_blk, src_page);
				}

				for (j=0; j<=free_num2; j++) {
					if (vt_blk_node->phy_blk_addr[j] < 0)
						aml_nftl_dbg("nftl garbage get free copy  block addr: %d  %d  %d  %d %d\n", vt_blk_node->phy_blk_addr[0], vt_blk_node->phy_blk_addr[1], vt_blk_node->phy_blk_addr[2], vt_blk_node->phy_blk_addr[3], j);
					aml_nftl_wl->add_free(aml_nftl_wl, vt_blk_node->phy_blk_addr[j]);
					vt_blk_node->phy_blk_addr[j] = BLOCK_INIT_VALUE;
					copy_gc_num++;
				}	
				vt_blk_node->phy_blk_addr[0] = dest_blk;

			}
			if (copy_gc_num >= 1)
				break;
		}
	}

	//aml_nftl_dbg("nftl garbage block num: %d free num: %d flag: %d\n", (copy_gc_num + erase_gc_num), aml_nftl_wl->free_root.count, gc_flag);
	if (i <= 2)
		aml_nftl_wl->gc_start_block = aml_nftl_info->accessibleblocks - 1;
	else
		aml_nftl_wl->gc_start_block = i;
	aml_nftl_wl->gc_need_flag = 0;
	return (copy_gc_num + erase_gc_num);
}

/**
 * gc_copy_special - copy root, leaf, sroot, sleaf to free block
 * 
 * Copy all block to new free block, regardless valid sectors in each blocks
 *
 *     1. malloc special root, leaf sector map for temp use
 *     2. get best free linear block
 *     3. get root, leaf, sroot, sleaf linear block relative to special node
 *     4. get sector map for root, leaf, sroot, sleaf
 *     5. calculate page addr base
 *     6. copy_page depend on sector map, do not encode/decode ga_pmap
 *     7. add root, leaf, sroot, sleaf linear block into free tree
 *         add_free will not process invalid block(if no sleaf in this vblk)
 *     8. free temp sroot, sleaf sector map
 */
static int32_t gc_copy_special(struct aml_nftl_wl_t* aml_nftl_wl)
{
	int status = 0;
	struct aml_nftl_info_t *aml_nftl_info = aml_nftl_wl->aml_nftl_info;
	struct phyblk_node_t *phy_blk_tmp_node, *phy_blk_node_dest;
	struct vtblk_node_t  *vt_special_node;
	int16_t i, j;
	addr_blk_t dest_blk, src_blk, phy_blk_tmp;
	addr_page_t dest_page, src_page;

	if (aml_nftl_info->vtpmt_special->vtblk_node == NULL)
		return -1;

	vt_special_node = aml_nftl_info->vtpmt_special->vtblk_node;
	dest_blk = aml_nftl_info->vtpmt_special->ext_phy_blk_addr;

	phy_blk_node_dest = &aml_nftl_info->phypmt[dest_blk];

	for (i=0; i<aml_nftl_wl->pages_per_blk; i++) {

		if (phy_blk_node_dest->phy_page_map[i] >= 0)
			continue;

		for (j=(MAX_BLK_NUM_PER_NODE - 1); j>=0; j--) {
			phy_blk_tmp = vt_special_node->phy_blk_addr[j];
			phy_blk_tmp_node = &aml_nftl_info->phypmt[phy_blk_tmp];
			if (phy_blk_tmp_node->phy_page_map[i] >= 0) {
				src_blk = phy_blk_tmp;
				src_page = phy_blk_tmp_node->phy_page_map[i];
				break;
			}
		}
		if ((phy_blk_tmp_node->phy_page_map[i] < 0) || (j > 0))
			continue;

		dest_page = phy_blk_node_dest->last_write + 1;
		aml_nftl_info->copy_page(aml_nftl_info, dest_blk, dest_page, src_blk, src_page);
	}

	aml_nftl_wl->add_free(aml_nftl_wl, vt_special_node->phy_blk_addr[0]);
	for (j=0; j<(MAX_BLK_NUM_PER_NODE - 1); j++) {
		//aml_nftl_wl->add_free(aml_nftl_wl, vt_special_node->phy_blk_addr[j]);
		vt_special_node->phy_blk_addr[j] = vt_special_node->phy_blk_addr[j+1];
	}
	vt_special_node->phy_blk_addr[MAX_BLK_NUM_PER_NODE-1] = dest_blk;
	aml_nftl_info->vtpmt_special->vtblk_node = NULL;
	aml_nftl_info->vtpmt_special->ext_phy_blk_addr = BLOCK_INIT_VALUE;

	return status;
}

static int aml_nftl_garbage_collect(struct aml_nftl_wl_t *aml_nftl_wl, uint8_t gc_flag)
{
	int gc_num = 0, copy_page_bounce_num;
	struct aml_nftl_info_t *aml_nftl_info = aml_nftl_wl->aml_nftl_info;

	if (aml_nftl_info->isinitialised == 0) {
		gc_num = gc_get_dirty_block(aml_nftl_wl, 0);
		if (gc_num >= 4) 
			return gc_num;

		aml_nftl_info->isinitialised = 1;
		aml_nftl_wl->gc_start_block = aml_nftl_info->accessibleblocks - 1;
		aml_nftl_dbg("nftl creat stucture completely in garbage free blk: %d erased blk: %d\n", aml_nftl_wl->free_root.count, aml_nftl_wl->erased_root.count);
	}
	if ((aml_nftl_info->fillfactor/8) >= AML_LIMIT_FACTOR)
		copy_page_bounce_num = aml_nftl_info->fillfactor / 8;
	else
		copy_page_bounce_num = AML_LIMIT_FACTOR;

	if ((aml_nftl_wl->free_root.count <= copy_page_bounce_num) || (gc_flag == DO_COPY_PAGE))
		return gc_get_dirty_block(aml_nftl_wl, DO_COPY_PAGE);
	else
		return gc_get_dirty_block(aml_nftl_wl, 0);
}

/**
 * get_best_free - get best free block
 * @block : linear block
 *
 *     1. get free block from erased free tree & remove node from tree
 *     2. get free block from dirty free tree & remove node from tree
 *     3.      update ec
 *     4.      erase dirty free block
 */
static int32_t get_best_free(struct aml_nftl_wl_t *wl, addr_blk_t* blk)
{
	int error = 0;
	struct rb_node* p;
	struct wl_rb_t* tnode;
	struct aml_nftl_info_t *aml_nftl_info = wl->aml_nftl_info;

get_free:
	if(wl->erased_root.count) {
		p = rb_first(&wl->erased_root.root);
		tnode = rb_entry(p, struct wl_rb_t, rb_node);
		*blk = tnode->blk;
		_del_erased(wl, tnode);
	}
	else if(wl->free_root.count) {
		p = rb_first(&wl->free_root.root);
		tnode = rb_entry(p, struct wl_rb_t, rb_node);
		*blk = tnode->blk;
		_del_free(wl, tnode);

		error = aml_nftl_info->erase_block(aml_nftl_info, *blk);
		if (error) {
			aml_nftl_info->blk_mark_bad(aml_nftl_info, *blk);
			goto get_free;
		}
	}
	else
		return -ENOENT;

	return 0;
}

int aml_nftl_wl_init(struct aml_nftl_info_t *aml_nftl_info)
{
	struct aml_nftl_wl_t *aml_nftl_wl = aml_nftl_malloc(sizeof(struct aml_nftl_wl_t));
	if(!aml_nftl_wl)
		return -1;

	aml_nftl_wl->aml_nftl_info = aml_nftl_info;
	aml_nftl_info->aml_nftl_wl = aml_nftl_wl;
	
	aml_nftl_wl->wl_delta = WL_DELTA;
	aml_nftl_wl->pages_per_blk = aml_nftl_info->pages_per_blk;
	aml_nftl_wl->gc_start_block = aml_nftl_info->accessibleblocks - 1;

	aml_nftl_wl->erased_root.root = RB_ROOT;
	aml_nftl_wl->free_root.root = RB_ROOT;
	aml_nftl_wl->used_root.root = RB_ROOT;

	INIT_LIST_HEAD(&aml_nftl_wl->node_full_head.list);
	aml_nftl_wl->node_full_head.vt_blk = BLOCK_INIT_VALUE;
	INIT_LIST_HEAD(&aml_nftl_wl->readerr_head.list);
	aml_nftl_wl->readerr_head.vt_blk = BLOCK_INIT_VALUE;

	/*init function pointer*/
	aml_nftl_wl->add_free = add_free;
	aml_nftl_wl->add_erased = add_erased;
	aml_nftl_wl->add_used = add_used;
	aml_nftl_wl->add_full = add_node_full;
	aml_nftl_wl->get_best_free = get_best_free;
	aml_nftl_wl->get_full = get_node_full;

	aml_nftl_wl->gc_special = gc_copy_special;
	aml_nftl_wl->garbage_collect = aml_nftl_garbage_collect;

	return 0;
}
