/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011-2012 Spectra Logic Corporation.  All rights reserved.
 */

#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_zfetch.h>
#include <sys/zfs_ioctl.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#include <sys/sa.h>
#ifdef _KERNEL
#include <sys/zfs_znode.h>
#endif

const dmu_object_type_info_t dmu_ot[DMU_OT_NUMTYPES] = {
	{	byteswap_uint8_array,	TRUE,	"unallocated"		},
	{	zap_byteswap,		TRUE,	"object directory"	},
	{	byteswap_uint64_array,	TRUE,	"object array"		},
	{	byteswap_uint8_array,	TRUE,	"packed nvlist"		},
	{	byteswap_uint64_array,	TRUE,	"packed nvlist size"	},
	{	byteswap_uint64_array,	TRUE,	"bpobj"			},
	{	byteswap_uint64_array,	TRUE,	"bpobj header"		},
	{	byteswap_uint64_array,	TRUE,	"SPA space map header"	},
	{	byteswap_uint64_array,	TRUE,	"SPA space map"		},
	{	byteswap_uint64_array,	TRUE,	"ZIL intent log"	},
	{	dnode_buf_byteswap,	TRUE,	"DMU dnode"		},
	{	dmu_objset_byteswap,	TRUE,	"DMU objset"		},
	{	byteswap_uint64_array,	TRUE,	"DSL directory"		},
	{	zap_byteswap,		TRUE,	"DSL directory child map"},
	{	zap_byteswap,		TRUE,	"DSL dataset snap map"	},
	{	zap_byteswap,		TRUE,	"DSL props"		},
	{	byteswap_uint64_array,	TRUE,	"DSL dataset"		},
	{	zfs_znode_byteswap,	TRUE,	"ZFS znode"		},
	{	zfs_oldacl_byteswap,	TRUE,	"ZFS V0 ACL"		},
	{	byteswap_uint8_array,	FALSE,	"ZFS plain file"	},
	{	zap_byteswap,		TRUE,	"ZFS directory"		},
	{	zap_byteswap,		TRUE,	"ZFS master node"	},
	{	zap_byteswap,		TRUE,	"ZFS delete queue"	},
	{	byteswap_uint8_array,	FALSE,	"zvol object"		},
	{	zap_byteswap,		TRUE,	"zvol prop"		},
	{	byteswap_uint8_array,	FALSE,	"other uint8[]"		},
	{	byteswap_uint64_array,	FALSE,	"other uint64[]"	},
	{	zap_byteswap,		TRUE,	"other ZAP"		},
	{	zap_byteswap,		TRUE,	"persistent error log"	},
	{	byteswap_uint8_array,	TRUE,	"SPA history"		},
	{	byteswap_uint64_array,	TRUE,	"SPA history offsets"	},
	{	zap_byteswap,		TRUE,	"Pool properties"	},
	{	zap_byteswap,		TRUE,	"DSL permissions"	},
	{	zfs_acl_byteswap,	TRUE,	"ZFS ACL"		},
	{	byteswap_uint8_array,	TRUE,	"ZFS SYSACL"		},
	{	byteswap_uint8_array,	TRUE,	"FUID table"		},
	{	byteswap_uint64_array,	TRUE,	"FUID table size"	},
	{	zap_byteswap,		TRUE,	"DSL dataset next clones"},
	{	zap_byteswap,		TRUE,	"scan work queue"	},
	{	zap_byteswap,		TRUE,	"ZFS user/group used"	},
	{	zap_byteswap,		TRUE,	"ZFS user/group quota"	},
	{	zap_byteswap,		TRUE,	"snapshot refcount tags"},
	{	zap_byteswap,		TRUE,	"DDT ZAP algorithm"	},
	{	zap_byteswap,		TRUE,	"DDT statistics"	},
	{	byteswap_uint8_array,	TRUE,	"System attributes"	},
	{	zap_byteswap,		TRUE,	"SA master node"	},
	{	zap_byteswap,		TRUE,	"SA attr registration"	},
	{	zap_byteswap,		TRUE,	"SA attr layouts"	},
	{	zap_byteswap,		TRUE,	"scan translations"	},
	{	byteswap_uint8_array,	FALSE,	"deduplicated block"	},
	{	zap_byteswap,		TRUE,	"DSL deadlist map"	},
	{	byteswap_uint64_array,	TRUE,	"DSL deadlist map hdr"	},
	{	zap_byteswap,		TRUE,	"DSL dir clones"	},
	{	byteswap_uint64_array,	TRUE,	"bpobj subobj"		},
};

SYSCTL_DECL(_vfs_zfs);
SYSCTL_NODE(_vfs_zfs, OID_AUTO, dmu, CTLFLAG_RW, 0, "ZFS DMU");
#define	SYSCTL_COUNTER_U(name, desc)				\
	uint64_t name;						\
	SYSCTL_QUAD(_vfs_zfs_dmu, OID_AUTO, name, CTLFLAG_RD,	\
	    &name, 0, desc)
#define	SYSCTL_REFCOUNT(name, desc)				\
	uint_t name;						\
	SYSCTL_INT(_vfs_zfs_dmu, OID_AUTO, name, CTLFLAG_RD,	\
	    &name, 0, desc)

#ifdef ZFS_DEBUG
SYSCTL_REFCOUNT(dcn_in_flight, "DMU context nodes in flight");
SYSCTL_COUNTER_U(dmu_ctx_total, "total number of DMU contexts");
SYSCTL_COUNTER_U(buf_set_total, "total number of buffer sets");
SYSCTL_REFCOUNT(dmu_ctx_in_flight, "number of DMU contexts in flight");
SYSCTL_REFCOUNT(buf_set_in_flight, "number of buffer sets in flight");
#endif

int
dmu_buf_hold(objset_t *os, uint64_t object, uint64_t offset,
    void *tag, dmu_buf_t **dbp, int flags)
{
	dnode_t *dn;
	uint64_t blkid;
	dmu_buf_impl_t *db;
	int err;
	int db_flags = DB_RF_CANFAIL;

	if (flags & DMU_READ_NO_PREFETCH)
		db_flags |= DB_RF_NOPREFETCH;

	err = dnode_hold(os, object, FTAG, &dn);
	if (err)
		return (err);
	blkid = dbuf_whichblock(dn, offset);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	db = dbuf_hold(dn, blkid, tag);
	rw_exit(&dn->dn_struct_rwlock);
	if (db == NULL) {
		err = EIO;
	} else {
		err = dbuf_read(db, NULL, db_flags);
		if (err) {
			dbuf_rele(db, tag);
			db = NULL;
		}
	}

	dnode_rele(dn, FTAG);
	*dbp = &db->db; /* NULL db plus first field offset is NULL */
	return (err);
}

int
dmu_bonus_max(void)
{
	return (DN_MAX_BONUSLEN);
}

int
dmu_set_bonus(dmu_buf_t *db_fake, int newsize, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	dnode_t *dn;
	int error;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	if (dn->dn_bonus != db) {
		error = EINVAL;
	} else if (newsize < 0 || newsize > db_fake->db_size) {
		error = EINVAL;
	} else {
		dnode_setbonuslen(dn, newsize, tx);
		error = 0;
	}

	DB_DNODE_EXIT(db);
	return (error);
}

int
dmu_set_bonustype(dmu_buf_t *db_fake, dmu_object_type_t type, dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	dnode_t *dn;
	int error;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	if (type > DMU_OT_NUMTYPES) {
		error = EINVAL;
	} else if (dn->dn_bonus != db) {
		error = EINVAL;
	} else {
		dnode_setbonus_type(dn, type, tx);
		error = 0;
	}

	DB_DNODE_EXIT(db);
	return (error);
}

dmu_object_type_t
dmu_get_bonustype(dmu_buf_t *db_fake)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	dnode_t *dn;
	dmu_object_type_t type;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	type = dn->dn_bonustype;
	DB_DNODE_EXIT(db);

	return (type);
}

int
dmu_rm_spill(objset_t *os, uint64_t object, dmu_tx_t *tx)
{
	dnode_t *dn;
	int error;

	error = dnode_hold(os, object, FTAG, &dn);
	dbuf_rm_spill(dn, tx);
	rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
	dnode_rm_spill(dn, tx);
	rw_exit(&dn->dn_struct_rwlock);
	dnode_rele(dn, FTAG);
	return (error);
}

/*
 * returns ENOENT, EIO, or 0.
 */
int
dmu_bonus_hold(objset_t *os, uint64_t object, void *tag, dmu_buf_t **dbp)
{
	dnode_t *dn;
	dmu_buf_impl_t *db;
	int error;

	error = dnode_hold(os, object, FTAG, &dn);
	if (error)
		return (error);

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_bonus == NULL) {
		rw_exit(&dn->dn_struct_rwlock);
		rw_enter(&dn->dn_struct_rwlock, RW_WRITER);
		if (dn->dn_bonus == NULL)
			dbuf_create_bonus(dn);
	}
	db = dn->dn_bonus;

	/* as long as the bonus buf is held, the dnode will be held */
	if (refcount_add(&db->db_holds, tag) == 1) {
		VERIFY(dnode_add_ref(dn, db));
		(void) atomic_inc_32_nv(&dn->dn_dbufs_count);
	}

	/*
	 * Wait to drop dn_struct_rwlock until after adding the bonus dbuf's
	 * hold and incrementing the dbuf count to ensure that dnode_move() sees
	 * a dnode hold for every dbuf.
	 */
	rw_exit(&dn->dn_struct_rwlock);

	dnode_rele(dn, FTAG);

	VERIFY(0 == dbuf_read(db, NULL, DB_RF_MUST_SUCCEED | DB_RF_NOPREFETCH));

	*dbp = &db->db;
	return (0);
}

/*
 * returns ENOENT, EIO, or 0.
 *
 * This interface will allocate a blank spill dbuf when a spill blk
 * doesn't already exist on the dnode.
 *
 * if you only want to find an already existing spill db, then
 * dmu_spill_hold_existing() should be used.
 */
int
dmu_spill_hold_by_dnode(dnode_t *dn, uint32_t flags, void *tag, dmu_buf_t **dbp)
{
	dmu_buf_impl_t *db = NULL;
	int err;

	if ((flags & DB_RF_HAVESTRUCT) == 0)
		rw_enter(&dn->dn_struct_rwlock, RW_READER);

	db = dbuf_hold(dn, DMU_SPILL_BLKID, tag);

	if ((flags & DB_RF_HAVESTRUCT) == 0)
		rw_exit(&dn->dn_struct_rwlock);

	ASSERT(db != NULL);
	err = dbuf_read(db, NULL, flags);
	if (err == 0)
		*dbp = &db->db;
	else
		dbuf_rele(db, tag);
	return (err);
}

int
dmu_spill_hold_existing(dmu_buf_t *bonus, void *tag, dmu_buf_t **dbp)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)bonus;
	dnode_t *dn;
	int err;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	if (spa_version(dn->dn_objset->os_spa) < SPA_VERSION_SA) {
		err = EINVAL;
	} else {
		rw_enter(&dn->dn_struct_rwlock, RW_READER);

		if (!dn->dn_have_spill) {
			err = ENOENT;
		} else {
			err = dmu_spill_hold_by_dnode(dn,
			    DB_RF_HAVESTRUCT | DB_RF_CANFAIL, tag, dbp);
		}

		rw_exit(&dn->dn_struct_rwlock);
	}

	DB_DNODE_EXIT(db);
	return (err);
}

int
dmu_spill_hold_by_bonus(dmu_buf_t *bonus, void *tag, dmu_buf_t **dbp)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)bonus;
	dnode_t *dn;
	int err;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	err = dmu_spill_hold_by_dnode(dn, DB_RF_CANFAIL, tag, dbp);
	DB_DNODE_EXIT(db);

	return (err);
}

void
dmu_prefetch(objset_t *os, uint64_t object, uint64_t offset, uint64_t len)
{
	dnode_t *dn;
	uint64_t blkid;
	int nblks, i, err;

	if (zfs_prefetch_disable)
		return;

	if (len == 0) {  /* they're interested in the bonus buffer */
		dn = DMU_META_DNODE(os);

		if (object == 0 || object >= DN_MAX_OBJECT)
			return;

		rw_enter(&dn->dn_struct_rwlock, RW_READER);
		blkid = dbuf_whichblock(dn, object * sizeof (dnode_phys_t));
		dbuf_prefetch(dn, blkid);
		rw_exit(&dn->dn_struct_rwlock);
		return;
	}

	/*
	 * XXX - Note, if the dnode for the requested object is not
	 * already cached, we will do a *synchronous* read in the
	 * dnode_hold() call.  The same is true for any indirects.
	 */
	err = dnode_hold(os, object, FTAG, &dn);
	if (err != 0)
		return;

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	if (dn->dn_datablkshift) {
		int blkshift = dn->dn_datablkshift;
		nblks = (P2ROUNDUP(offset+len, 1<<blkshift) -
		    P2ALIGN(offset, 1<<blkshift)) >> blkshift;
	} else {
		nblks = (offset < dn->dn_datablksz);
	}

	if (nblks != 0) {
		blkid = dbuf_whichblock(dn, offset);
		for (i = 0; i < nblks; i++)
			dbuf_prefetch(dn, blkid+i);
	}

	rw_exit(&dn->dn_struct_rwlock);

	dnode_rele(dn, FTAG);
}

/*
 * Get the next "chunk" of file data to free.  We traverse the file from
 * the end so that the file gets shorter over time (if we crashes in the
 * middle, this will leave us in a better state).  We find allocated file
 * data by simply searching the allocated level 1 indirects.
 */
static int
get_next_chunk(dnode_t *dn, uint64_t *start, uint64_t limit)
{
	uint64_t len = *start - limit;
	uint64_t blkcnt = 0;
	uint64_t maxblks = DMU_MAX_ACCESS / (1ULL << (dn->dn_indblkshift + 1));
	uint64_t iblkrange =
	    dn->dn_datablksz * EPB(dn->dn_indblkshift, SPA_BLKPTRSHIFT);

	ASSERT(limit <= *start);

	if (len <= iblkrange * maxblks) {
		*start = limit;
		return (0);
	}
	ASSERT(ISP2(iblkrange));

	while (*start > limit && blkcnt < maxblks) {
		int err;

		/* find next allocated L1 indirect */
		err = dnode_next_offset(dn,
		    DNODE_FIND_BACKWARDS, start, 2, 1, 0);

		/* if there are no more, then we are done */
		if (err == ESRCH) {
			*start = limit;
			return (0);
		} else if (err) {
			return (err);
		}
		blkcnt += 1;

		/* reset offset to end of "next" block back */
		*start = P2ALIGN(*start, iblkrange);
		if (*start <= limit)
			*start = limit;
		else
			*start -= 1;
	}
	return (0);
}

static int
dmu_free_long_range_impl(objset_t *os, dnode_t *dn, uint64_t offset,
    uint64_t length, boolean_t free_dnode)
{
	dmu_tx_t *tx;
	uint64_t object_size, start, end, len;
	boolean_t trunc = (length == DMU_OBJECT_END);
	int align, err;

	align = 1 << dn->dn_datablkshift;
	ASSERT(align > 0);
	object_size = align == 1 ? dn->dn_datablksz :
	    (dn->dn_maxblkid + 1) << dn->dn_datablkshift;

	end = offset + length;
	if (trunc || end > object_size)
		end = object_size;
	if (end <= offset)
		return (0);
	length = end - offset;

	while (length) {
		start = end;
		/* assert(offset <= start) */
		err = get_next_chunk(dn, &start, offset);
		if (err)
			return (err);
		len = trunc ? DMU_OBJECT_END : end - start;

		tx = dmu_tx_create(os);
		dmu_tx_hold_free(tx, dn->dn_object, start, len);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err) {
			dmu_tx_abort(tx);
			return (err);
		}

		dnode_free_range(dn, start, trunc ? -1 : len, tx);

		if (start == 0 && free_dnode) {
			ASSERT(trunc);
			dnode_free(dn, tx);
		}

		length -= end - start;

		dmu_tx_commit(tx);
		end = start;
	}
	return (0);
}

int
dmu_free_long_range(objset_t *os, uint64_t object,
    uint64_t offset, uint64_t length)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os, object, FTAG, &dn);
	if (err != 0)
		return (err);
	err = dmu_free_long_range_impl(os, dn, offset, length, FALSE);
	dnode_rele(dn, FTAG);
	return (err);
}

int
dmu_free_object(objset_t *os, uint64_t object)
{
	dnode_t *dn;
	dmu_tx_t *tx;
	int err;

	err = dnode_hold_impl(os, object, DNODE_MUST_BE_ALLOCATED,
	    FTAG, &dn);
	if (err != 0)
		return (err);
	if (dn->dn_nlevels == 1) {
		tx = dmu_tx_create(os);
		dmu_tx_hold_bonus(tx, object);
		dmu_tx_hold_free(tx, dn->dn_object, 0, DMU_OBJECT_END);
		err = dmu_tx_assign(tx, TXG_WAIT);
		if (err == 0) {
			dnode_free_range(dn, 0, DMU_OBJECT_END, tx);
			dnode_free(dn, tx);
			dmu_tx_commit(tx);
		} else {
			dmu_tx_abort(tx);
		}
	} else {
		err = dmu_free_long_range_impl(os, dn, 0, DMU_OBJECT_END, TRUE);
	}
	dnode_rele(dn, FTAG);
	return (err);
}

int
dmu_free_range(objset_t *os, uint64_t object, uint64_t offset,
    uint64_t size, dmu_tx_t *tx)
{
	dnode_t *dn;
	int err = dnode_hold(os, object, FTAG, &dn);
	if (err)
		return (err);
	ASSERT(offset < UINT64_MAX);
	ASSERT(size == -1ULL || size <= UINT64_MAX - offset);
	dnode_free_range(dn, offset, size, tx);
	dnode_rele(dn, FTAG);
	return (0);
}

/*
 * DMU Context based functions.
 */

/* Used for TSD for processing completed asynchronous I/Os. */
uint_t zfs_async_io_key;

void
dmu_context_node_add(list_t *list, dmu_buf_set_t *buf_set)
{
	dmu_context_node_t *dcn = kmem_zalloc(sizeof(dmu_context_node_t),
	    KM_SLEEP);
	dcn->buf_set = buf_set;
	list_insert_tail(list, dcn);
#ifdef ZFS_DEBUG
	refcount_acquire(&dcn_in_flight);
#endif
}

void
dmu_context_node_remove(list_t *list, dmu_context_node_t *dcn)
{
	list_remove(list, dcn);
	kmem_free(dcn, sizeof(dmu_context_node_t));
#ifdef ZFS_DEBUG
	ASSERT(dcn_in_flight > 0);
	refcount_release(&dcn_in_flight);
#endif
}

static void
dmu_buf_read_xuio(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
#ifdef _KERNEL
	dmu_context_t *dmu_ctx = buf_set->dmu_ctx;
	uio_t *uio = (uio_t *)dmu_ctx->data_buf;
	xuio_t *xuio = (xuio_t *)uio;
	dmu_buf_impl_t *dbi = (dmu_buf_impl_t *)db;
	arc_buf_t *dbuf_abuf = dbi->db_buf;
	arc_buf_t *abuf = dbuf_loan_arcbuf(dbi);

	if (dmu_xuio_add(xuio, abuf, off, sz) == 0) {
		uio->uio_resid -= sz;
		uio->uio_loffset += sz;
	}

	if (abuf == dbuf_abuf)
		XUIOSTAT_BUMP(xuiostat_rbuf_nocopy);
	else
		XUIOSTAT_BUMP(xuiostat_rbuf_copied);
#endif
}

static void
dmu_buf_read_uio(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
#ifdef _KERNEL
	uio_t *uio = (uio_t *)buf_set->dmu_ctx->data_buf;
	struct iovec *iov = uio->uio_iov;
	dprintf("%s: uio iov=%p iovcnt=%d base %p len %lu\n",
	    __func__, iov, uio->uio_iovcnt, iov->iov_base,
	    iov->iov_len);
	if (uiomove((char *)db->db_data + off, sz, UIO_READ, uio))
		buf_set->err += 1;
#endif
}
static void
dmu_buf_write_uio(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
#ifdef _KERNEL
	uio_t *uio = (uio_t *)buf_set->dmu_ctx->data_buf;
	struct iovec *iov = uio->uio_iov;
	dprintf("%s: uio iov=%p iovcnt=%d base %p len %lu\n",
	    __func__, iov, uio->uio_iovcnt, iov->iov_base,
	    iov->iov_len);
	if (uiomove((char *)db->db_data + off, sz, UIO_WRITE, uio))
		buf_set->err += 1;
#endif
}

static void
dmu_buf_read_char(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
	char *data = (char *)buf_set->dmu_ctx->data_buf + db->db_offset -
	    buf_set->dmu_ctx->dn_start + off;
	dprintf("%s(set=%p, db=%p, off=%lu, sz=%lu) db_data=%p data=%p\n",
	    __func__, buf_set, db, off, sz, db->db_data + off, data);
	bcopy((char *)db->db_data + off, data, sz);
}
static void
dmu_buf_write_char(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
	char *data = (char *)buf_set->dmu_ctx->data_buf + db->db_offset -
	    buf_set->dmu_ctx->dn_start + off;
	dprintf("%s(set=%p, db=%p, off=%lu, sz=%lu) data=%p db_data=%p\n",
	    __func__, buf_set, db, off, sz, data, db->db_data + off);
	bcopy(data, (char *)db->db_data + off, sz);
}

static void
dmu_buf_write_pages(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
#ifdef sun
	int copied;
	page_t *pp = (page_t *)dmu_context->data_buf;

	for (copied = 0; copied < sz; copied += PAGESIZE) {
		caddr_t va;
		int thiscpy;

		ASSERT3U(pp->p_offset, ==, db->db_offset + off);
		thiscpy = MIN(PAGESIZE, sz - copied);
		va = zfs_map_page(pp, S_READ);
		bcopy(va, (char *)db->db_data + off, thiscpy);
		zfs_unmap_page(pp, va);
		pp = pp->p_next;
		off += PAGESIZE;
	}
#endif
}

static void
dmu_buf_transfer_nofill(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
	dmu_tx_t *tx = DMU_BUF_SET_TX(buf_set);
	dmu_buf_will_not_fill(db, tx);
	/* No need to do any more here. */
}

static void
dmu_buf_transfer_write(dmu_buf_set_t *buf_set, dmu_buf_t *db, uint64_t off,
    uint64_t sz)
{
	dmu_tx_t *tx = DMU_BUF_SET_TX(buf_set);

	if (sz == db->db_size)
		dmu_buf_will_fill(db, tx);
	else
		dmu_buf_will_dirty_range(db, tx, off, sz);
	buf_set->dmu_ctx->move_cb(buf_set, db, off, sz);
	dmu_buf_fill_done(db, tx);
}

void
dmu_buf_set_transfer(dmu_buf_set_t *buf_set)
{
	uint64_t offset, size;
	dmu_context_t *dmu_ctx = buf_set->dmu_ctx;
	dmu_tx_t *tx = dmu_ctx->tx;
	int i;

	/* Initialize the current state. */
	size = buf_set->size;
	offset = buf_set->dn_start;

	/* Perform the I/O copy, one buffer at a time. */
	for (i = 0; i < buf_set->count; i++) {
		dmu_buf_t *db = buf_set->dbp[i];
		uint64_t off = offset - db->db_offset;
		uint64_t sz = MIN(db->db_size - off, size);

		ASSERT(size > 0);
		dmu_ctx->buf_transfer_cb(buf_set, db, off, sz);
		offset += sz;
		size -= sz;
	}
}

void
dmu_buf_set_transfer_write(dmu_buf_set_t *buf_set)
{

	dmu_buf_set_transfer(buf_set);
	ASSERT(buf_set->dmu_ctx->dn != NULL);
	/* Release the dnode immediately before committing the tx. */
	dnode_rele(buf_set->dmu_ctx->dn, buf_set->dmu_ctx->tag);
	buf_set->dmu_ctx->dn = NULL;
}

static void
dmu_buf_set_transfer_write_tx(dmu_buf_set_t *buf_set)
{

	dmu_buf_set_transfer_write(buf_set);
	dmu_tx_commit(buf_set->tx);
}

/**
 * \brief Release a DMU context hold, cleaning up if no holds remain.
 *
 * \param dmu_ctx	DMU context to release.
 */
void
dmu_context_rele(dmu_context_t *dmu_ctx)
{
	dmu_buf_set_t *buf_set;

	if (!refcount_release(&dmu_ctx->holds))
		return;

#ifdef ZFS_DEBUG
	ASSERT(dmu_ctx_in_flight > 0);
	refcount_release(&dmu_ctx_in_flight);
#endif

	if ((dmu_ctx->flags & DMU_CTX_FLAG_NO_HOLD) == 0 && dmu_ctx->dn != NULL)
		dnode_rele(dmu_ctx->dn, dmu_ctx->tag);

	/* At this point, there are no buffer sets left.  Call back. */
	if (dmu_ctx->context_cb != NULL)
		dmu_ctx->context_cb(dmu_ctx);
}

/**
 * \brief Handle a completed buffer set, and its DMU context if necessary.
 *
 * \param buf_set	Buffer set to handle.
 */
static void
dmu_buf_set_complete(dmu_buf_set_t *buf_set)
{
	int i;
	dmu_context_t *dmu_ctx = buf_set->dmu_ctx;

	/* Only perform I/O if no errors occurred for the buffer set. */
	if (buf_set->err == 0) {
		dmu_ctx->buf_set_transfer_cb(buf_set);
		if (buf_set->err == 0)
			atomic_add_64(&dmu_ctx->completed_size, buf_set->size);
	}
	/* Check again in case transfer causes errors. */
	if (buf_set->err)
		atomic_add_int(&dmu_ctx->err, buf_set->err);

	for (i = 0; i < buf_set->count; i++) {
		dmu_buf_impl_t *db = (dmu_buf_impl_t *)buf_set->dbp[i];
		ASSERT(db != NULL);
		dbuf_rele(db, dmu_ctx->tag);
	}

#ifdef ZFS_DEBUG
	ASSERT(buf_set_in_flight > 0);
	refcount_release(&buf_set_in_flight);
#endif

	kmem_free(buf_set, sizeof(dmu_buf_set_t) +
	    buf_set->dbp_length * sizeof(dmu_buf_t *));
	dmu_context_rele(dmu_ctx);
}

int
dmu_thread_context_create(void)
{
	int ret = 0;
#ifdef _KERNEL /* XXX TSD only works in the kernel.  FIXME! */
	dmu_cb_state_t *dcs;

	/* This function should never be called more than once in a thread. */
#ifdef ZFS_DEBUG
	dcs = tsd_get(zfs_async_io_key);
	ASSERT(dcs == NULL);
#endif

	/* Called with taskqueue mutex held. */
	dcs = kmem_zalloc(sizeof(dmu_cb_state_t), KM_SLEEP);
	list_create(&dcs->io_list, sizeof(dmu_context_node_t),
	    offsetof(dmu_context_node_t, dcn_link));

	ret = tsd_set(zfs_async_io_key, dcs);
#ifdef ZFS_DEBUG
	{
		dmu_cb_state_t *check = tsd_get(zfs_async_io_key);
		ASSERT(check == dcs);
	}
#endif
#endif /* _KERNEL */
	return (ret);
}

void
dmu_thread_context_destroy(void *context __unused)
{
	dmu_cb_state_t *dcs;

	dcs = tsd_get(zfs_async_io_key);
	/* This function may be called on a thread that didn't call create. */
	if (dcs == NULL)
		return;

	/*
	 * This function should only get called after a thread has finished
	 * processing its queue.
	 */
	ASSERT(list_is_empty(&dcs->io_list));

	kmem_free(dcs, sizeof(dmu_cb_state_t));
	VERIFY(tsd_set(zfs_async_io_key, NULL) == 0);
}

void
dmu_thread_context_process(void)
{
	dmu_cb_state_t *dcs = tsd_get(zfs_async_io_key);
	dmu_context_node_t *dcn, *next;

	/*
	 * If the current thread didn't register, it doesn't handle queued
	 * async I/O's.  It is probably not a zio thread.  This is needed
	 * because zio_execute() can be called from non-zio threads.
	 */
	if (dcs == NULL)
		return;

	for (dcn = list_head(&dcs->io_list); dcn != NULL; dcn = next) {
		next = list_next(&dcs->io_list, dcn);
		dmu_buf_set_complete(dcn->buf_set);
		dmu_context_node_remove(&dcs->io_list, dcn);
	}
}

/**
 * \brief Release a buffer set for a given dbuf.
 *
 * \param buf_set	Buffer set to release.
 * \param err		Whether an error occurred.
 *
 * \invariant		If specified, the dbuf's mutex must be held.
 */
void
dmu_buf_set_rele(dmu_buf_set_t *buf_set, boolean_t err)
{
	dmu_context_t *dmu_ctx = buf_set->dmu_ctx;

	/* Report an error, if any. */
	if (err)
		atomic_add_int(&buf_set->err, 1);

	/* If we are finished, schedule this buffer set for delivery. */
	ASSERT(buf_set->holds > 0);
	if (refcount_release(&buf_set->holds)) {
		dmu_cb_state_t *dcs = tsd_get(zfs_async_io_key);

		if (dcs != NULL && (dmu_ctx->flags & DMU_CTX_FLAG_ASYNC)) {
			dmu_context_node_add(&dcs->io_list, buf_set);
		} else {
			/*
			 * The current thread doesn't have anything
			 * registered in its TSD, so it must not handle
			 * queued delivery.  Dispatch this set now.
			 */
			dmu_buf_set_complete(buf_set);
		}
	}
}

/**
 * \brief Set up the buffers for a given set.
 *
 * \param buf_set	Buffer set to set up buffers for.
 *
 * \retval errno	If any buffer could not be held for this buffer set.
 * \retval 0		Success.
 */
static int
dmu_buf_set_setup_buffers(dmu_buf_set_t *buf_set)
{
	dmu_context_t *dmu_ctx = buf_set->dmu_ctx;
	dnode_t *dn = dmu_ctx->dn;
	uint64_t blkid;
	int dbuf_flags;
	int i;

	dbuf_flags = DB_RF_CANFAIL | DB_RF_NEVERWAIT | DB_RF_HAVESTRUCT;
	if ((dmu_ctx->flags & DMU_CTX_FLAG_PREFETCH) == 0 ||
	    buf_set->size > zfetch_array_rd_sz)
		dbuf_flags |= DB_RF_NOPREFETCH;

	blkid = dbuf_whichblock(dn, dmu_ctx->dn_offset);
	/*
	 * Note that while this loop is running, any zio's set up for async
	 * reads are not executing, therefore access to this buf_set is
	 * serialized within this function; i.e. atomics are not needed here.
	 */
	for (i = 0; i < buf_set->count; i++) {
		dmu_buf_impl_t *db = NULL;
		int err = dbuf_hold_impl(dn, /*level*/0, blkid + i,
		    /*fail_sparse*/FALSE, dmu_ctx->tag, &db, buf_set);
		uint64_t bufoff, bufsiz;

		if (db == NULL) {
			/* Only include counts for the processed buffers. */
			buf_set->count = i;
			buf_set->holds = i + 1 /*initiator*/;
			zio_nowait(buf_set->zio);
			return (err);
		}
		/* initiate async i/o */
		if (dmu_ctx->flags & DMU_CTX_FLAG_READ)
			(void) dbuf_read(db, buf_set->zio, dbuf_flags);
#ifdef _KERNEL
		else
			curthread->td_ru.ru_oublock++;
#endif

		/* Calculate the amount of data this buffer contributes. */
		ASSERT(dmu_ctx->dn_offset >= db->db.db_offset);
		bufoff = dmu_ctx->dn_offset - db->db.db_offset;
		bufsiz = (int)MIN(db->db.db_size - bufoff, buf_set->resid);
		buf_set->resid -= bufsiz;
		/* Update the caller's data to let them know what's next. */
		dmu_ctx->dn_offset += bufsiz;
		dmu_ctx->resid -= bufsiz;
		/* Put this dbuf in the buffer set's list. */
		buf_set->dbp[i] = &db->db;
	}
	return (0);
}

/**
 * \brief Set up a new transaction for the DMU context.
 *
 * \param dmu_ctx	DMU context to set up new transaction for.
 * \param txp		Address to store dmu_tx_t pointer.
 * \param dnp		Address to store dnode_t pointer for new dnode.
 */
static int
dmu_context_setup_tx(dmu_context_t *dmu_ctx, dmu_tx_t **txp, dnode_t **dnp,
    uint64_t size)
{
	int err;

	/* Readers and writers with a context transaction do not apply. */
	if ((dmu_ctx->flags & DMU_CTX_FLAG_READ) || dmu_ctx->tx != NULL)
		return (0);

	*txp = dmu_tx_create(dmu_ctx->os);
	dmu_tx_hold_write(*txp, dmu_ctx->object, dmu_ctx->dn_offset, size);
	err = dmu_tx_assign(*txp, TXG_WAIT);
	if (err)
		goto out;

	/*
	 * Writer without caller TX: dnode hold is done here rather
	 * than in dmu_context_init().
	 */
	err = dnode_hold(dmu_ctx->os, dmu_ctx->object, dmu_ctx->tag, dnp);
	if (err)
		goto out;
	dmu_ctx->dn = *dnp;

out:
	if (err && *txp != NULL) {
		dmu_tx_abort(*txp);
		*txp = NULL;
	}
	return (err);
}

/**
 * \brief Initialize a buffer set of a certain size.
 *
 * \param dmu_ctx	DMU context to associate the buffer set with.
 * \param buf_set_p	Pointer to set to the new buffer set's address.
 * \param size		Requested size of the buffer set.
 *
 * \retval 0		Success.
 * \retval EIO		I/O error: tried to access past the end of the dnode,
 * 			or dmu_buf_set_setup_buffers() failed.
 */
static int
dmu_buf_set_init(dmu_context_t *dmu_ctx, dmu_buf_set_t **buf_set_p,
    uint64_t size)
{
	dmu_buf_set_t *buf_set;
	dmu_tx_t *tx = NULL;
	size_t set_size;
	int err, nblks;
	dnode_t *dn = dmu_ctx->dn;

	ASSERT(dmu_ctx != NULL);
	ASSERT(dmu_ctx->holds > 0);

	/*
	 * Create a transaction for writes, if needed.  This must be done
	 * first in order to hold the correct struct_rwlock, use the
	 * correct values for dn_datablksz, etc.
	 */
	err = dmu_context_setup_tx(dmu_ctx, &tx, &dn, size);
	if (err)
		return (err);

	rw_enter(&dn->dn_struct_rwlock, RW_READER);

	/* Figure out how many blocks are needed for the requested size. */
	if (dn->dn_datablkshift) {
		nblks = P2ROUNDUP(dmu_ctx->dn_offset + size, dn->dn_datablksz);
		nblks -= P2ALIGN(dmu_ctx->dn_offset, dn->dn_datablksz);
		nblks >>= dn->dn_datablkshift;
	} else {
		if ((dmu_ctx->dn_offset + size) > dn->dn_datablksz) {
			zfs_panic_recover("zfs: accessing past end of object "
			    "%llx/%llx (size=%u access=%llu+%llu)",
			    (longlong_t)dn->dn_objset->
			    os_dsl_dataset->ds_object,
			    (longlong_t)dn->dn_object, dn->dn_datablksz,
			    (longlong_t)dmu_ctx->dn_offset,
			    (longlong_t)size);
			err = EIO;
			goto out;
		}
		nblks = 1;
	}

	/* Create the new buffer set. */
	set_size = sizeof(dmu_buf_set_t) + nblks * sizeof(dmu_buf_t *);
	buf_set = kmem_zalloc(set_size, KM_SLEEP);

	/* Initialize a new buffer set. */
#ifdef ZFS_DEBUG
	refcount_acquire(&buf_set_in_flight);
	atomic_add_64(&buf_set_total, 1);
#endif
	buf_set->size = size;
	buf_set->resid = size;
	buf_set->dn_start = dmu_ctx->dn_offset;
	buf_set->count = nblks;
	buf_set->dbp_length = nblks;
	buf_set->tx = tx;

	/* Include a refcount for the initiator. */
	if (dmu_ctx->flags & DMU_CTX_FLAG_READ)
		refcount_init(&buf_set->holds, nblks + 1);
	else
		/* For writes, dbufs never need to call us back. */
		refcount_init(&buf_set->holds, 1);
	buf_set->dmu_ctx = dmu_ctx;
	refcount_acquire(&dmu_ctx->holds);
	/* Either we're a reader or we have a transaction somewhere. */
	ASSERT((dmu_ctx->flags & DMU_CTX_FLAG_READ) || DMU_BUF_SET_TX(buf_set));
	buf_set->zio = zio_root(dn->dn_objset->os_spa, NULL, NULL,
	    ZIO_FLAG_CANFAIL);
	*buf_set_p = buf_set;

	err = dmu_buf_set_setup_buffers(buf_set);

out:
	if (err && tx != NULL)
		dmu_tx_abort(tx);
	if (dn != NULL)
		rw_exit(&dn->dn_struct_rwlock);
	return (err);
}

/**
 * \brief Process the I/Os queued for a given buffer set.
 *
 * \param buf_set	Buffer set to process I/Os for.
 *
 * \retval errno	Errors from zio_wait or a buffer went UNCACHED.
 * \retval 0		Success.
 */
static int
dmu_buf_set_process_io(dmu_buf_set_t *buf_set)
{
	int err, i, syncing;
	dsl_pool_t *dp = NULL;
	hrtime_t start = 0;
	dmu_context_t *dmu_ctx = buf_set->dmu_ctx;
	dnode_t *dn = dmu_ctx->dn;

	/*
	 * If the I/O is asynchronous, issue the I/O's without waiting.
	 * Writes do not need to wait for any ZIOs.
	 */
	if ((dmu_ctx->flags & DMU_CTX_FLAG_ASYNC) ||
	    (dmu_ctx->flags & DMU_CTX_FLAG_READ) == 0) {
		zio_nowait(buf_set->zio);
		return (0);
	}

	/* Time accounting for sync context. */
	if (dn->dn_objset->os_dsl_dataset)
		dp = dn->dn_objset->os_dsl_dataset->ds_dir->dd_pool;
	if (dp && dsl_pool_sync_context(dp))
		start = gethrtime();

	/* Wait for async i/o. */
	err = zio_wait(buf_set->zio);

	/* Track read overhead when we are in sync context. */
	if (start)
		dp->dp_read_overhead += gethrtime() - start;
	if (err)
		return (err);

	/* wait for other io to complete */
	for (i = 0; i < buf_set->count; i++) {
		dmu_buf_impl_t *db = (dmu_buf_impl_t *)buf_set->dbp[i];
		mutex_enter(&db->db_mtx);
		while (db->db_state & (DB_READ|DB_FILL))
			cv_wait(&db->db_changed, &db->db_mtx);
		if (db->db_state == DB_UNCACHED)
			err = EIO;
		mutex_exit(&db->db_mtx);
		if (err)
			return (err);
	}
	return (0);
}

/**
 * \brief Issue the I/O specified in the given DMU context.
 *
 * \param dmu_ctx	The DMU context.
 *
 * \return errno	Errors executing I/O chunks.
 * \return 0		If a DMU callback is specified; the callback
 *			receives any errors.
 * \return 0		If no DMU callback is specified: Success.
 */
int
dmu_issue(dmu_context_t *dmu_ctx)
{
	int err = 0;
	uint64_t io_size;
	dmu_buf_set_t *buf_set;

	/* If this context is async, it must have a context callback. */
	ASSERT((dmu_ctx->flags & DMU_CTX_FLAG_ASYNC) == 0 ||
	    dmu_ctx->context_cb != NULL);

	/*
	 * For writers, if a tx was specified but a dnode wasn't, hold here.
	 * This could be done in dmu_context_set_dmu_tx(), but that would
	 * require dmu.h to include a dnode_hold() prototype.
	 */
	if (dmu_ctx->tx != NULL && dmu_ctx->dn == NULL) {
		err = dnode_hold(dmu_ctx->os, dmu_ctx->object, dmu_ctx->tag,
		    &dmu_ctx->dn);
		if (err)
			return (err);
	}

	/* While there is work left to do, execute the next chunk. */
	dprintf("%s(%p) -> buf %p off %lu sz %lu\n", __func__, dmu_ctx,
	    dmu_ctx->data_buf, dmu_ctx->dn_offset, dmu_ctx->resid);
	while (dmu_ctx->resid > 0 && err == 0) {
		io_size = MIN(dmu_ctx->resid, DMU_MAX_ACCESS/2);

		dprintf("%s(%p@%lu+%lu) chunk %lu\n", __func__, dmu_ctx,
		    dmu_ctx->dn_offset, dmu_ctx->resid, io_size);
		err = dmu_buf_set_init(dmu_ctx, &buf_set, io_size);

		/* Process the I/O requests, if the initialization passed. */
		if (err == 0)
			err = dmu_buf_set_process_io(buf_set);

		dmu_buf_set_rele(buf_set, err ? B_TRUE : B_FALSE);
	}
	/*
	 * At this point, either this I/O is async, or all buffer sets
	 * have finished processing.
	 */
	ASSERT((dmu_ctx->flags & DMU_CTX_FLAG_ASYNC) || dmu_ctx->holds == 1);

	return (err);
}

/**
 * \brief Set up a DMU context.
 *
 * \param dmu_ctx	The DMU context.
 * \param dn		A held dnode to associate with the context, or NULL.
 * \param os		The object set associated with the context.
 * \param object	The object ID associated with the context.
 * \param size		Size of the I/O to be performed.
 * \param offset	Offset into the dnode to perform the I/O.
 * \param data_buf	Data buffer to perform I/O transfers with.
 * \param tag		Hold tag to use.
 * \param flags		DMU context flags.
 *
 * \note	The dnode must not be NULL, unless this is a writer.
 * \note	The dnode, if specified, must be held, unless the
 *		DMU_CTX_FLAG_NO_HOLD flag is specified.
 */
int
dmu_context_init(dmu_context_t *dmu_ctx, struct dnode *dn, objset_t *os,
    uint64_t object, uint64_t offset, uint64_t size, void *data_buf, void *tag,
    uint32_t flags)
{
	boolean_t reader = (flags & DMU_CTX_FLAG_READ) != 0;
	int err;

#ifdef ZFS_DEBUG
	refcount_acquire(&dmu_ctx_in_flight);
	atomic_add_64(&dmu_ctx_total, 1);
	/* Make sure the dnode is passed in appropriately. */
	if (dn == NULL)
		ASSERT(os != NULL);
	else
		ASSERT(!refcount_is_zero(&dn->dn_holds) ||
		    (flags & DMU_CTX_FLAG_NO_HOLD));
#endif
#ifndef sun
	ASSERT((flags & DMU_CTX_FLAG_SUN_PAGES) == 0);
#endif

	/* Make sure the flags are compatible with the I/O type. */
	ASSERT(reader || ((flags & DMU_CTX_READER_FLAGS) == 0));
	ASSERT(!reader || ((flags & DMU_CTX_WRITER_FLAGS) == 0));
	/* The NOFILL flag and a NULL data_buf go hand in hand. */
	ASSERT(((flags & DMU_CTX_FLAG_NOFILL) != 0) ^ (data_buf != NULL));

	/*
	 * If the caller is a reader and didn't pass in a dnode, hold it.
	 * Writers (re-)hold a dnode in dmu_context_setup_tx(), or if a tx
	 * is specified, in dmu_issue().
	 */
	if (dn == NULL && (flags & DMU_CTX_FLAG_READ)) {
		err = dnode_hold(os, object, tag, &dn);
		if (err)
			return (err);
	}

	/* All set, actually initialize the context! */
	bzero(dmu_ctx, sizeof(dmu_context_t));
	dmu_ctx->dn = dn;
	dmu_ctx->os = os;
	dmu_ctx->object = object;
	dmu_ctx->size = size;
	dmu_context_seek(dmu_ctx, offset, size, data_buf);
	dmu_ctx->tag = tag;
	dmu_ctx->flags = flags;

	/* Initialize default I/O callbacks. */
	if (dmu_ctx->flags & DMU_CTX_FLAG_UIO) {
#ifdef UIO_XUIO
		uio_t *uio = (uio_t *)dmu_ctx->data_buf;
		if (uio->uio_extflg == UIO_XUIO) {
			ASSERT(reader);
			dmu_ctx->move_cb = dmu_buf_read_xuio;
		} else
#endif
		{
			dmu_ctx->move_cb = reader ? dmu_buf_read_uio :
			    dmu_buf_write_uio;
		}
	} else if (dmu_ctx->flags & DMU_CTX_FLAG_SUN_PAGES) {
		/* implies writer */
		dmu_ctx->move_cb = dmu_buf_write_pages;
	} else {
		dmu_ctx->move_cb = reader ? dmu_buf_read_char :
		    dmu_buf_write_char;
	}
	dmu_ctx->buf_set_transfer_cb = reader ? dmu_buf_set_transfer :
	    dmu_buf_set_transfer_write_tx;
	if ((dmu_ctx->flags & DMU_CTX_FLAG_NOFILL) == 0) {
		dmu_ctx->buf_transfer_cb = reader ? dmu_ctx->move_cb :
		    dmu_buf_transfer_write;
	} else
		dmu_ctx->buf_transfer_cb = dmu_buf_transfer_nofill;

	/* Initialize including a refcount for the initiator. */
	refcount_init(&dmu_ctx->holds, 1);
	return (0);
}

/**
 * \brief Update a DMU context for the next call.
 *
 * \param dmu_ctx	The DMU context.
 * \param data_buf	The updated destination data buffer.
 * \param offset	The offset into the dnode.
 * \param size		The size of the next call.
 */
void
dmu_context_seek(dmu_context_t *dmu_ctx, uint64_t offset, uint64_t size,
    void *data_buf)
{
	dnode_t *dn = dmu_ctx->dn;

#ifdef ZFS_DEBUG
#ifdef _KERNEL
	if (dmu_ctx->flags & DMU_CTX_FLAG_UIO) {
		uio_t *uio = (uio_t *)data_buf;
		/* Make sure UIO callers pass in the correct offset. */
		ASSERT(uio->uio_loffset == offset);
	}
#endif
	/* Make sure non-char * pointers stay the same. */
	if (!DMU_CTX_BUF_IS_CHAR(dmu_ctx))
		ASSERT(dmu_ctx->data_buf == NULL ||
		    dmu_ctx->data_buf == data_buf);
#endif /* ZFS_DEBUG */

	/*
	 * Deal with odd block sizes, where there can't be data past
	 * the first block.  If we ever do the tail block optimization,
	 * we will need to handle that here as well.
	 */
	if ((dmu_ctx->flags & DMU_CTX_FLAG_READ) && dn->dn_maxblkid == 0 &&
	    DMU_CTX_BUF_IS_CHAR(dmu_ctx)) {
		int newsz = offset > dn->dn_datablksz ? 0 :
		    MIN(size, dn->dn_datablksz - offset);
		bzero((char *)data_buf + newsz, size - newsz);
		size = newsz;
	}
	dmu_ctx->dn_offset = offset;
	dmu_ctx->dn_start = offset;
	dmu_ctx->resid = size;
	dmu_ctx->data_buf = data_buf;
}

int
dmu_read(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    void *data_buf, uint32_t flags)
{
	int err;
	dmu_context_t dmu_ctx;

	err = dmu_context_init(&dmu_ctx, /*dnode*/NULL, os, object, offset,
	    size, data_buf, FTAG, flags|DMU_CTX_FLAG_READ);
	if (err)
		return (err);

	err = dmu_issue(&dmu_ctx);
	dmu_context_rele(&dmu_ctx);

	return (err);
}

void
dmu_write(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    const void *data_buf, dmu_tx_t *tx)
{
	void *data_bufp = (void *)(uintptr_t)data_buf;
	dmu_context_t dmu_ctx;
	int err;

	err = dmu_context_init(&dmu_ctx, /*dnode*/NULL, os, object, offset,
	    size, data_bufp, FTAG, /*flags*/0);
	VERIFY(err == 0);
	dmu_context_set_dmu_tx(&dmu_ctx, tx);

	(void) dmu_issue(&dmu_ctx);
	dmu_context_rele(&dmu_ctx);
}

int
dmu_prealloc(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    dmu_tx_t *tx)
{
	uint32_t flags = DMU_CTX_FLAG_NOFILL;
	dmu_context_t dmu_ctx;
	int err;

	if (size == 0)
		return (0);

	err = dmu_context_init(&dmu_ctx, /*dnode*/NULL, os, object, offset,
	    size, /*data_buf*/NULL, FTAG, flags);
	if (err)
		return (err);

	dmu_context_set_dmu_tx(&dmu_ctx, tx);
	err = dmu_issue(&dmu_ctx);
	dmu_context_rele(&dmu_ctx);

	return (err);
}

/*
 * DMU support for xuio
 */
kstat_t *xuio_ksp = NULL;

int
dmu_xuio_init(xuio_t *xuio, int nblk)
{
	dmu_xuio_t *priv;
	uio_t *uio = &xuio->xu_uio;

	uio->uio_iovcnt = nblk;
	uio->uio_iov = kmem_zalloc(nblk * sizeof (iovec_t), KM_SLEEP);

	priv = kmem_zalloc(sizeof (dmu_xuio_t), KM_SLEEP);
	priv->cnt = nblk;
	priv->bufs = kmem_zalloc(nblk * sizeof (arc_buf_t *), KM_SLEEP);
	priv->iovp = uio->uio_iov;
	XUIO_XUZC_PRIV(xuio) = priv;

	if (XUIO_XUZC_RW(xuio) == UIO_READ)
		XUIOSTAT_INCR(xuiostat_onloan_rbuf, nblk);
	else
		XUIOSTAT_INCR(xuiostat_onloan_wbuf, nblk);

	return (0);
}

void
dmu_xuio_fini(xuio_t *xuio)
{
	dmu_xuio_t *priv = XUIO_XUZC_PRIV(xuio);
	int nblk = priv->cnt;

	kmem_free(priv->iovp, nblk * sizeof (iovec_t));
	kmem_free(priv->bufs, nblk * sizeof (arc_buf_t *));
	kmem_free(priv, sizeof (dmu_xuio_t));

	if (XUIO_XUZC_RW(xuio) == UIO_READ)
		XUIOSTAT_INCR(xuiostat_onloan_rbuf, -nblk);
	else
		XUIOSTAT_INCR(xuiostat_onloan_wbuf, -nblk);
}

/*
 * Initialize iov[priv->next] and priv->bufs[priv->next] with { off, n, abuf }
 * and increase priv->next by 1.
 */
int
dmu_xuio_add(xuio_t *xuio, arc_buf_t *abuf, offset_t off, size_t n)
{
	struct iovec *iov;
	uio_t *uio = &xuio->xu_uio;
	dmu_xuio_t *priv = XUIO_XUZC_PRIV(xuio);
	int i = priv->next++;

	ASSERT(i < priv->cnt);
	ASSERT(off + n <= arc_buf_size(abuf));
	iov = uio->uio_iov + i;
	iov->iov_base = (char *)abuf->b_data + off;
	iov->iov_len = n;
	priv->bufs[i] = abuf;
	return (0);
}

int
dmu_xuio_cnt(xuio_t *xuio)
{
	dmu_xuio_t *priv = XUIO_XUZC_PRIV(xuio);
	return (priv->cnt);
}

arc_buf_t *
dmu_xuio_arcbuf(xuio_t *xuio, int i)
{
	dmu_xuio_t *priv = XUIO_XUZC_PRIV(xuio);

	ASSERT(i < priv->cnt);
	return (priv->bufs[i]);
}

void
dmu_xuio_clear(xuio_t *xuio, int i)
{
	dmu_xuio_t *priv = XUIO_XUZC_PRIV(xuio);

	ASSERT(i < priv->cnt);
	priv->bufs[i] = NULL;
}

static void
xuio_stat_init(void)
{
	xuio_ksp = kstat_create("zfs", 0, "xuio_stats", "misc",
	    KSTAT_TYPE_NAMED, sizeof (xuio_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (xuio_ksp != NULL) {
		xuio_ksp->ks_data = &xuio_stats;
		kstat_install(xuio_ksp);
	}
}

static void
xuio_stat_fini(void)
{
	if (xuio_ksp != NULL) {
		kstat_delete(xuio_ksp);
		xuio_ksp = NULL;
	}
}

void
xuio_stat_wbuf_copied()
{
	XUIOSTAT_BUMP(xuiostat_wbuf_copied);
}

void
xuio_stat_wbuf_nocopy()
{
	XUIOSTAT_BUMP(xuiostat_wbuf_nocopy);
}

#ifdef _KERNEL
int
dmu_read_uio(objset_t *os, uint64_t object, uio_t *uio, uint64_t size)
{
	dmu_context_t dmu_ctx;
	uint32_t dmu_flags = DMU_CTX_FLAG_READ|DMU_CTX_FLAG_UIO;
	int err;

	err = dmu_context_init(&dmu_ctx, /*dnode*/NULL, os, object,
	    uio->uio_loffset, size, uio, FTAG, dmu_flags);
	if (err)
		return (err);

	err = dmu_issue(&dmu_ctx);
	dmu_context_rele(&dmu_ctx);
	return (err);
}

int
dmu_write_uio_dbuf(dmu_buf_t *zdb, uio_t *uio, uint64_t size,
    dmu_tx_t *tx)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)zdb;
	dnode_t *dn;
	dmu_context_t dmu_ctx;
	int err;
	uint32_t flags = DMU_CTX_FLAG_UIO|DMU_CTX_FLAG_NO_HOLD;

	if (size == 0)
		return (0);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	err = dmu_context_init(&dmu_ctx, dn, dn->dn_objset, dn->dn_object,
	    uio->uio_loffset, size, uio, FTAG, flags);
	if (err == 0) {
		dmu_context_set_dmu_tx(&dmu_ctx, tx);
		err = dmu_issue(&dmu_ctx);
		dmu_context_rele(&dmu_ctx);
	}
	DB_DNODE_EXIT(db);

	return (err);
}

int
dmu_write_uio(objset_t *os, uint64_t object, uio_t *uio, uint64_t size,
    dmu_tx_t *tx)
{
	dmu_context_t dmu_ctx;
	uint32_t dmu_flags = DMU_CTX_FLAG_UIO;
	int err;

	if (size == 0)
		return (0);

	err = dmu_context_init(&dmu_ctx, /*dnode*/NULL, os, object,
	    uio->uio_loffset, size, uio, FTAG, dmu_flags);
	if (err)
		return (err);

	dmu_context_set_dmu_tx(&dmu_ctx, tx);
	err = dmu_issue(&dmu_ctx);
	dmu_context_rele(&dmu_ctx);
	return (err);
}

#ifdef sun
int
dmu_write_pages(objset_t *os, uint64_t object, uint64_t offset, uint64_t size,
    page_t *pp, dmu_tx_t *tx)
{
	dmu_context_t dmu_ctx;
	uint32_t dmu_flags = DMU_CTX_FLAG_SUN_PAGES;
	int err;

	if (size == 0)
		return (0);

	err = dmu_context_init(&dmu_ctx, /*dnode*/NULL, os, object, offset,
	    size, pp, FTAG, dmu_flags);
	if (err)
		return (err);

	dmu_context_set_dmu_tx(&dmu_ctx, tx);
	err = dmu_issue(&dmu_ctx);
	dmu_context_rele(&dmu_ctx);
	return (err);
}
#endif	/* sun */
#endif

/*
 * Allocate a loaned anonymous arc buffer.
 */
arc_buf_t *
dmu_request_arcbuf(dmu_buf_t *handle, int size)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)handle;
	spa_t *spa;

	DB_GET_SPA(&spa, db);
	return (arc_loan_buf(spa, size));
}

/*
 * Free a loaned arc buffer.
 */
void
dmu_return_arcbuf(arc_buf_t *buf)
{
	arc_return_buf(buf, FTAG);
	VERIFY(arc_buf_remove_ref(buf, FTAG) == 1);
}

/*
 * When possible directly assign passed loaned arc buffer to a dbuf.
 * If this is not possible copy the contents of passed arc buf via
 * dmu_write().
 */
void
dmu_assign_arcbuf(dmu_buf_t *handle, uint64_t offset, arc_buf_t *buf,
    dmu_tx_t *tx)
{
	dmu_buf_impl_t *dbuf = (dmu_buf_impl_t *)handle;
	dnode_t *dn;
	dmu_buf_impl_t *db;
	uint32_t blksz = (uint32_t)arc_buf_size(buf);
	uint64_t blkid;

	DB_DNODE_ENTER(dbuf);
	dn = DB_DNODE(dbuf);
	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	blkid = dbuf_whichblock(dn, offset);
	VERIFY((db = dbuf_hold(dn, blkid, FTAG)) != NULL);
	rw_exit(&dn->dn_struct_rwlock);
	DB_DNODE_EXIT(dbuf);

	if (offset == db->db.db_offset && blksz == db->db.db_size) {
		dbuf_assign_arcbuf(db, buf, tx);
		dbuf_rele(db, FTAG);
	} else {
		objset_t *os;
		uint64_t object;

		DB_DNODE_ENTER(dbuf);
		dn = DB_DNODE(dbuf);
		os = dn->dn_objset;
		object = dn->dn_object;
		DB_DNODE_EXIT(dbuf);

		dbuf_rele(db, FTAG);
		dmu_write(os, object, offset, blksz, buf->b_data, tx);
		dmu_return_arcbuf(buf);
		XUIOSTAT_BUMP(xuiostat_wbuf_copied);
	}
}

typedef struct {
	dbuf_dirty_record_t	*dsa_dr;
	dmu_sync_cb_t		*dsa_done;
	zgd_t			*dsa_zgd;
	dmu_tx_t		*dsa_tx;
} dmu_sync_arg_t;

/* ARGSUSED */
static void
dmu_sync_ready(zio_t *zio, arc_buf_t *buf, void *varg)
{
	dmu_sync_arg_t *dsa = varg;
	dmu_buf_t *db = dsa->dsa_zgd->zgd_db;
	blkptr_t *bp = zio->io_bp;

	if (zio->io_error == 0) {
		if (BP_IS_HOLE(bp)) {
			/*
			 * A block of zeros may compress to a hole, but the
			 * block size still needs to be known for replay.
			 */
			BP_SET_LSIZE(bp, db->db_size);
		} else {
			ASSERT(BP_GET_LEVEL(bp) == 0);
			bp->blk_fill = 1;
		}
	}
}

static void
dmu_sync_late_arrival_ready(zio_t *zio)
{
	dmu_sync_ready(zio, NULL, zio->io_private);
}

/* ARGSUSED */
static void
dmu_sync_done(zio_t *zio, arc_buf_t *buf, void *varg)
{
	dmu_sync_arg_t *dsa = varg;
	dbuf_dirty_record_t *dr = dsa->dsa_dr;
	dmu_buf_impl_t *db = dr->dr_dbuf;

	mutex_enter(&db->db_mtx);
	ASSERT(dr->dt.dl.dr_override_state == DR_IN_DMU_SYNC);
	if (zio->io_error == 0) {
		dr->dt.dl.dr_overridden_by = *zio->io_bp;
		dr->dt.dl.dr_override_state = DR_OVERRIDDEN;
		dr->dt.dl.dr_copies = zio->io_prop.zp_copies;
		if (BP_IS_HOLE(&dr->dt.dl.dr_overridden_by))
			BP_ZERO(&dr->dt.dl.dr_overridden_by);
	} else {
		dr->dt.dl.dr_override_state = DR_NOT_OVERRIDDEN;
	}
	cv_broadcast(&db->db_changed);
	mutex_exit(&db->db_mtx);

	dsa->dsa_done(dsa->dsa_zgd, zio->io_error);

	kmem_free(dsa, sizeof (*dsa));
}

static void
dmu_sync_late_arrival_done(zio_t *zio)
{
	blkptr_t *bp = zio->io_bp;
	dmu_sync_arg_t *dsa = zio->io_private;

	if (zio->io_error == 0 && !BP_IS_HOLE(bp)) {
		ASSERT(zio->io_bp->blk_birth == zio->io_txg);
		ASSERT(zio->io_txg > spa_syncing_txg(zio->io_spa));
		zio_free(zio->io_spa, zio->io_txg, zio->io_bp);
	}

	dmu_tx_commit(dsa->dsa_tx);

	dsa->dsa_done(dsa->dsa_zgd, zio->io_error);

	kmem_free(dsa, sizeof (*dsa));
}

static int
dmu_sync_late_arrival(zio_t *pio, objset_t *os, dmu_sync_cb_t *done, zgd_t *zgd,
    zio_prop_t *zp, zbookmark_t *zb)
{
	dmu_sync_arg_t *dsa;
	dmu_tx_t *tx;

	tx = dmu_tx_create(os);
	dmu_tx_hold_space(tx, zgd->zgd_db->db_size);
	if (dmu_tx_assign(tx, TXG_WAIT) != 0) {
		dmu_tx_abort(tx);
		return (EIO);	/* Make zl_get_data do txg_waited_synced() */
	}

	dsa = kmem_alloc(sizeof (dmu_sync_arg_t), KM_SLEEP);
	dsa->dsa_dr = NULL;
	dsa->dsa_done = done;
	dsa->dsa_zgd = zgd;
	dsa->dsa_tx = tx;

	zio_nowait(zio_write(pio, os->os_spa, dmu_tx_get_txg(tx), zgd->zgd_bp,
	    zgd->zgd_db->db_data, zgd->zgd_db->db_size, zp,
	    dmu_sync_late_arrival_ready, dmu_sync_late_arrival_done, dsa,
	    ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_CANFAIL, zb));

	return (0);
}

/*
 * Intent log support: sync the block associated with db to disk.
 * N.B. and XXX: the caller is responsible for making sure that the
 * data isn't changing while dmu_sync() is writing it.
 *
 * Return values:
 *
 *	EEXIST: this txg has already been synced, so there's nothing to to.
 *		The caller should not log the write.
 *
 *	ENOENT: the block was dbuf_free_range()'d, so there's nothing to do.
 *		The caller should not log the write.
 *
 *	EALREADY: this block is already in the process of being synced.
 *		The caller should track its progress (somehow).
 *
 *	EIO: could not do the I/O.
 *		The caller should do a txg_wait_synced().
 *
 *	0: the I/O has been initiated.
 *		The caller should log this blkptr in the done callback.
 *		It is possible that the I/O will fail, in which case
 *		the error will be reported to the done callback and
 *		propagated to pio from zio_done().
 */
int
dmu_sync(zio_t *pio, uint64_t txg, dmu_sync_cb_t *done, zgd_t *zgd)
{
	blkptr_t *bp = zgd->zgd_bp;
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)zgd->zgd_db;
	objset_t *os = db->db_objset;
	dsl_dataset_t *ds = os->os_dsl_dataset;
	dbuf_dirty_record_t *dr;
	dmu_sync_arg_t *dsa;
	zbookmark_t zb;
	zio_prop_t zp;
	dnode_t *dn;

	ASSERT(pio != NULL);
	ASSERT(BP_IS_HOLE(bp));
	ASSERT(txg != 0);

	SET_BOOKMARK(&zb, ds->ds_object,
	    db->db.db_object, db->db_level, db->db_blkid);

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);
	dmu_write_policy(os, dn, db->db_level, WP_DMU_SYNC, &zp);
	DB_DNODE_EXIT(db);

	/*
	 * If we're frozen (running ziltest), we always need to generate a bp.
	 */
	if (txg > spa_freeze_txg(os->os_spa))
		return (dmu_sync_late_arrival(pio, os, done, zgd, &zp, &zb));

	/*
	 * Grabbing db_mtx now provides a barrier between dbuf_sync_leaf()
	 * and us.  If we determine that this txg is not yet syncing,
	 * but it begins to sync a moment later, that's OK because the
	 * sync thread will block in dbuf_sync_leaf() until we drop db_mtx.
	 */
	mutex_enter(&db->db_mtx);

	if (txg <= spa_last_synced_txg(os->os_spa)) {
		/*
		 * This txg has already synced.  There's nothing to do.
		 */
		mutex_exit(&db->db_mtx);
		return (EEXIST);
	}

	if (txg <= spa_syncing_txg(os->os_spa)) {
		/*
		 * This txg is currently syncing, so we can't mess with
		 * the dirty record anymore; just write a new log block.
		 */
		mutex_exit(&db->db_mtx);
		return (dmu_sync_late_arrival(pio, os, done, zgd, &zp, &zb));
	}

	for (dr = list_head(&db->db_dirty_records); dr != NULL;
	    dr = list_next(&db->db_dirty_records, dr)) {
		if (dr->dr_txg == txg)
			break;
	}

	if (dr == NULL) {
		/*
		 * There's no dr for this dbuf, so it must have been freed.
		 * There's no need to log writes to freed blocks, so we're done.
		 */
		mutex_exit(&db->db_mtx);
		return (ENOENT);
	}

	/*
	 * XXX TEMP
	 * If the dirty record is not CACHED, then the dmu_sync call needs
	 * to wait for it to reach that state.  Thus, it needs to issue the
	 * READ if necessary.  Then, it needs to wait for that read to
	 * complete, which should cause the dbuf to become CACHED after
	 * resolving the applicable write ranges.  At that point, the sync
	 * can be completed.
	 */
	if (db->db_state != DB_CACHED) {
		if (db->db_state & (DB_UNCACHED|DB_PARTIAL))
			dbuf_transition_to_read(db);

		while (db->db_state & (DB_READ|DB_FILL))
			cv_wait(&db->db_changed, &db->db_mtx);

		/* The dbuf had an I/O error or was freed in flight */
		if (db->db_state == DB_UNCACHED) {
			mutex_exit(&db->db_mtx);
			return (ENOENT);
		}
	}
	ASSERT(db->db_state == DB_CACHED);

	ASSERT(dr->dr_txg == txg);
	if (dr->dt.dl.dr_override_state == DR_IN_DMU_SYNC ||
	    dr->dt.dl.dr_override_state == DR_OVERRIDDEN) {
		/*
		 * We have already issued a sync write for this buffer,
		 * or this buffer has already been synced.  It could not
		 * have been dirtied since, or we would have cleared the state.
		 */
		mutex_exit(&db->db_mtx);
		return (EALREADY);
	}

	ASSERT(dr->dt.dl.dr_override_state == DR_NOT_OVERRIDDEN);
	dr->dt.dl.dr_override_state = DR_IN_DMU_SYNC;
	mutex_exit(&db->db_mtx);

	dsa = kmem_alloc(sizeof (dmu_sync_arg_t), KM_SLEEP);
	dsa->dsa_dr = dr;
	dsa->dsa_done = done;
	dsa->dsa_zgd = zgd;
	dsa->dsa_tx = NULL;

	zio_nowait(arc_write(pio, os->os_spa, txg,
	    bp, dr->dt.dl.dr_data, DBUF_IS_L2CACHEABLE(db), &zp,
	    dmu_sync_ready, dmu_sync_done, dsa,
	    ZIO_PRIORITY_SYNC_WRITE, ZIO_FLAG_CANFAIL, &zb));

	return (0);
}

int
dmu_object_set_blocksize(objset_t *os, uint64_t object, uint64_t size, int ibs,
	dmu_tx_t *tx)
{
	dnode_t *dn;
	int err;

	err = dnode_hold(os, object, FTAG, &dn);
	if (err)
		return (err);
	err = dnode_set_blksz(dn, size, ibs, tx);
	dnode_rele(dn, FTAG);
	return (err);
}

void
dmu_object_set_checksum(objset_t *os, uint64_t object, uint8_t checksum,
	dmu_tx_t *tx)
{
	dnode_t *dn;

	/* XXX assumes dnode_hold will not get an i/o error */
	(void) dnode_hold(os, object, FTAG, &dn);
	ASSERT(checksum < ZIO_CHECKSUM_FUNCTIONS);
	dn->dn_checksum = checksum;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

void
dmu_object_set_compress(objset_t *os, uint64_t object, uint8_t compress,
	dmu_tx_t *tx)
{
	dnode_t *dn;

	/* XXX assumes dnode_hold will not get an i/o error */
	(void) dnode_hold(os, object, FTAG, &dn);
	ASSERT(compress < ZIO_COMPRESS_FUNCTIONS);
	dn->dn_compress = compress;
	dnode_setdirty(dn, tx);
	dnode_rele(dn, FTAG);
}

int zfs_mdcomp_disable = 0;
TUNABLE_INT("vfs.zfs.mdcomp_disable", &zfs_mdcomp_disable);
SYSCTL_DECL(_vfs_zfs);
SYSCTL_INT(_vfs_zfs, OID_AUTO, mdcomp_disable, CTLFLAG_RW,
    &zfs_mdcomp_disable, 0, "Disable metadata compression");

void
dmu_write_policy(objset_t *os, dnode_t *dn, int level, int wp, zio_prop_t *zp)
{
	dmu_object_type_t type = dn ? dn->dn_type : DMU_OT_OBJSET;
	boolean_t ismd = (level > 0 || dmu_ot[type].ot_metadata ||
	    (wp & WP_SPILL));
	enum zio_checksum checksum = os->os_checksum;
	enum zio_compress compress = os->os_compress;
	enum zio_checksum dedup_checksum = os->os_dedup_checksum;
	boolean_t dedup;
	boolean_t dedup_verify = os->os_dedup_verify;
	int copies = os->os_copies;

	/*
	 * Determine checksum setting.
	 */
	if (ismd) {
		/*
		 * Metadata always gets checksummed.  If the data
		 * checksum is multi-bit correctable, and it's not a
		 * ZBT-style checksum, then it's suitable for metadata
		 * as well.  Otherwise, the metadata checksum defaults
		 * to fletcher4.
		 */
		if (zio_checksum_table[checksum].ci_correctable < 1 ||
		    zio_checksum_table[checksum].ci_eck)
			checksum = ZIO_CHECKSUM_FLETCHER_4;
	} else {
		checksum = zio_checksum_select(dn->dn_checksum, checksum);
	}

	/*
	 * Determine compression setting.
	 */
	if (ismd) {
		/*
		 * XXX -- we should design a compression algorithm
		 * that specializes in arrays of bps.
		 */
		compress = zfs_mdcomp_disable ? ZIO_COMPRESS_EMPTY :
		    ZIO_COMPRESS_LZJB;
	} else {
		compress = zio_compress_select(dn->dn_compress, compress);
	}

	/*
	 * Determine dedup setting.  If we are in dmu_sync(), we won't
	 * actually dedup now because that's all done in syncing context;
	 * but we do want to use the dedup checkum.  If the checksum is not
	 * strong enough to ensure unique signatures, force dedup_verify.
	 */
	dedup = (!ismd && dedup_checksum != ZIO_CHECKSUM_OFF);
	if (dedup) {
		checksum = dedup_checksum;
		if (!zio_checksum_table[checksum].ci_dedup)
			dedup_verify = 1;
	}

	if (wp & WP_DMU_SYNC)
		dedup = 0;

	if (wp & WP_NOFILL) {
		ASSERT(!ismd && level == 0);
		checksum = ZIO_CHECKSUM_OFF;
		compress = ZIO_COMPRESS_OFF;
		dedup = B_FALSE;
	}

	zp->zp_checksum = checksum;
	zp->zp_compress = compress;
	zp->zp_type = (wp & WP_SPILL) ? dn->dn_bonustype : type;
	zp->zp_level = level;
	zp->zp_copies = MIN(copies + ismd, spa_max_replication(os->os_spa));
	zp->zp_dedup = dedup;
	zp->zp_dedup_verify = dedup && dedup_verify;
}

int
dmu_offset_next(objset_t *os, uint64_t object, boolean_t hole, uint64_t *off)
{
	dnode_t *dn;
	int i, err;

	err = dnode_hold(os, object, FTAG, &dn);
	if (err)
		return (err);
	/*
	 * Sync any current changes before
	 * we go trundling through the block pointers.
	 */
	for (i = 0; i < TXG_SIZE; i++) {
		if (list_link_active(&dn->dn_dirty_link[i]))
			break;
	}
	if (i != TXG_SIZE) {
		dnode_rele(dn, FTAG);
		txg_wait_synced(dmu_objset_pool(os), 0);
		err = dnode_hold(os, object, FTAG, &dn);
		if (err)
			return (err);
	}

	err = dnode_next_offset(dn, (hole ? DNODE_FIND_HOLE : 0), off, 1, 1, 0);
	dnode_rele(dn, FTAG);

	return (err);
}

void
dmu_object_info_from_dnode(dnode_t *dn, dmu_object_info_t *doi)
{
	dnode_phys_t *dnp;

	rw_enter(&dn->dn_struct_rwlock, RW_READER);
	mutex_enter(&dn->dn_mtx);

	dnp = dn->dn_phys;

	doi->doi_data_block_size = dn->dn_datablksz;
	doi->doi_metadata_block_size = dn->dn_indblkshift ?
	    1ULL << dn->dn_indblkshift : 0;
	doi->doi_type = dn->dn_type;
	doi->doi_bonus_type = dn->dn_bonustype;
	doi->doi_bonus_size = dn->dn_bonuslen;
	doi->doi_indirection = dn->dn_nlevels;
	doi->doi_checksum = dn->dn_checksum;
	doi->doi_compress = dn->dn_compress;
	doi->doi_physical_blocks_512 = (DN_USED_BYTES(dnp) + 256) >> 9;
	doi->doi_max_offset = (dnp->dn_maxblkid + 1) * dn->dn_datablksz;
	doi->doi_fill_count = 0;
	for (int i = 0; i < dnp->dn_nblkptr; i++)
		doi->doi_fill_count += dnp->dn_blkptr[i].blk_fill;

	mutex_exit(&dn->dn_mtx);
	rw_exit(&dn->dn_struct_rwlock);
}

/*
 * Get information on a DMU object.
 * If doi is NULL, just indicates whether the object exists.
 */
int
dmu_object_info(objset_t *os, uint64_t object, dmu_object_info_t *doi)
{
	dnode_t *dn;
	int err = dnode_hold(os, object, FTAG, &dn);

	if (err)
		return (err);

	if (doi != NULL)
		dmu_object_info_from_dnode(dn, doi);

	dnode_rele(dn, FTAG);
	return (0);
}

/*
 * As above, but faster; can be used when you have a held dbuf in hand.
 */
void
dmu_object_info_from_db(dmu_buf_t *db_fake, dmu_object_info_t *doi)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;

	DB_DNODE_ENTER(db);
	dmu_object_info_from_dnode(DB_DNODE(db), doi);
	DB_DNODE_EXIT(db);
}

/*
 * Faster still when you only care about the size.
 * This is specifically optimized for zfs_getattr().
 */
void
dmu_object_size_from_db(dmu_buf_t *db_fake, uint32_t *blksize,
    u_longlong_t *nblk512)
{
	dmu_buf_impl_t *db = (dmu_buf_impl_t *)db_fake;
	dnode_t *dn;

	DB_DNODE_ENTER(db);
	dn = DB_DNODE(db);

	*blksize = dn->dn_datablksz;
	/* add 1 for dnode space */
	*nblk512 = ((DN_USED_BYTES(dn->dn_phys) + SPA_MINBLOCKSIZE/2) >>
	    SPA_MINBLOCKSHIFT) + 1;
	DB_DNODE_EXIT(db);
}

void
byteswap_uint64_array(void *vbuf, size_t size)
{
	uint64_t *buf = vbuf;
	size_t count = size >> 3;
	int i;

	ASSERT((size & 7) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_64(buf[i]);
}

void
byteswap_uint32_array(void *vbuf, size_t size)
{
	uint32_t *buf = vbuf;
	size_t count = size >> 2;
	int i;

	ASSERT((size & 3) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_32(buf[i]);
}

void
byteswap_uint16_array(void *vbuf, size_t size)
{
	uint16_t *buf = vbuf;
	size_t count = size >> 1;
	int i;

	ASSERT((size & 1) == 0);

	for (i = 0; i < count; i++)
		buf[i] = BSWAP_16(buf[i]);
}

/* ARGSUSED */
void
byteswap_uint8_array(void *vbuf, size_t size)
{
}

void
dmu_init(void)
{
	zfs_dbgmsg_init();
	sa_cache_init();
	xuio_stat_init();
	dmu_objset_init();
	dnode_init();
	dbuf_init();
	zfetch_init();
	arc_init();
	l2arc_init();
}

void
dmu_fini(void)
{
	arc_fini(); /* arc depends on l2arc */
	l2arc_fini();
	zfetch_fini();
	dbuf_fini();
	dnode_fini();
	dmu_objset_fini();
	xuio_stat_fini();
	sa_cache_fini();
	zfs_dbgmsg_fini();
}
