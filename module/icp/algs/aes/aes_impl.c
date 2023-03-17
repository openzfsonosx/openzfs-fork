/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/crypto/icp.h>
#include <sys/crypto/spi.h>
#include <sys/simd.h>
#include <modes/modes.h>
#include <aes/aes_impl.h>

#ifndef _KERNEL
extern void aes_benchmark(void);
#endif

/*
 * Initialize AES encryption and decryption key schedules.
 *
 * Parameters:
 * cipherKey	User key
 * keyBits	AES key size (128, 192, or 256 bits)
 * keysched	AES key schedule to be initialized, of type aes_key_t.
 *		Allocated by aes_alloc_keysched().
 */
void
aes_init_keysched(const uint8_t *cipherKey, uint_t keyBits, void *keysched)
{
	const aes_impl_ops_t *ops = aes_impl_get_ops();
	aes_key_t *newbie = keysched;
	uint_t keysize, i, j;
	union {
		uint64_t	ka64[4];
		uint32_t	ka32[8];
	} keyarr;

	switch (keyBits) {
	case 128:
		newbie->nr = 10;
		break;

	case 192:
		newbie->nr = 12;
		break;

	case 256:
		newbie->nr = 14;
		break;

	default:
		/* should never get here */
		return;
	}
	keysize = CRYPTO_BITS2BYTES(keyBits);

	/*
	 * Generic C implementation requires byteswap for little endian
	 * machines, various accelerated implementations for various
	 * architectures may not.
	 */
	if (!ops->needs_byteswap) {
		/* no byteswap needed */
		if (IS_P2ALIGNED(cipherKey, sizeof (uint64_t))) {
			for (i = 0, j = 0; j < keysize; i++, j += 8) {
				/* LINTED: pointer alignment */
				keyarr.ka64[i] = *((uint64_t *)&cipherKey[j]);
			}
		} else {
			memcpy(keyarr.ka32, cipherKey, keysize);
		}
	} else {
		/* byte swap */
		for (i = 0, j = 0; j < keysize; i++, j += 4) {
			keyarr.ka32[i] =
			    htonl(*(uint32_t *)(void *)&cipherKey[j]);
		}
	}

	ops->generate(newbie, keyarr.ka32, keyBits);
	newbie->ops = ops;

	/*
	 * Note: if there are systems that need the AES_64BIT_KS type in the
	 * future, move setting key schedule type to individual implementations
	 */
	newbie->type = AES_32BIT_KS;
}


/*
 * Encrypt one block using AES.
 * Align if needed and (for x86 32-bit only) byte-swap.
 *
 * Parameters:
 * ks	Key schedule, of type aes_key_t
 * pt	Input block (plain text)
 * ct	Output block (crypto text).  Can overlap with pt
 */
int
aes_encrypt_block(const void *ks, const uint8_t *pt, uint8_t *ct)
{
	aes_key_t	*ksch = (aes_key_t *)ks;
	const aes_impl_ops_t	*ops = ksch->ops;

	if (IS_P2ALIGNED2(pt, ct, sizeof (uint32_t)) && !ops->needs_byteswap) {
		/* LINTED:  pointer alignment */
		ops->encrypt(&ksch->encr_ks.ks32[0], ksch->nr,
		    /* LINTED:  pointer alignment */
		    (uint32_t *)pt, (uint32_t *)ct);
	} else {
		uint32_t buffer[AES_BLOCK_LEN / sizeof (uint32_t)];

		/* Copy input block into buffer */
		if (ops->needs_byteswap) {
			buffer[0] = htonl(*(uint32_t *)(void *)&pt[0]);
			buffer[1] = htonl(*(uint32_t *)(void *)&pt[4]);
			buffer[2] = htonl(*(uint32_t *)(void *)&pt[8]);
			buffer[3] = htonl(*(uint32_t *)(void *)&pt[12]);
		} else
			memcpy(&buffer, pt, AES_BLOCK_LEN);

		ops->encrypt(&ksch->encr_ks.ks32[0], ksch->nr, buffer, buffer);

		/* Copy result from buffer to output block */
		if (ops->needs_byteswap) {
			*(uint32_t *)(void *)&ct[0] = htonl(buffer[0]);
			*(uint32_t *)(void *)&ct[4] = htonl(buffer[1]);
			*(uint32_t *)(void *)&ct[8] = htonl(buffer[2]);
			*(uint32_t *)(void *)&ct[12] = htonl(buffer[3]);
		} else
			memcpy(ct, &buffer, AES_BLOCK_LEN);
	}
	return (CRYPTO_SUCCESS);
}


/*
 * Decrypt one block using AES.
 * Align and byte-swap if needed.
 *
 * Parameters:
 * ks	Key schedule, of type aes_key_t
 * ct	Input block (crypto text)
 * pt	Output block (plain text). Can overlap with pt
 */
int
aes_decrypt_block(const void *ks, const uint8_t *ct, uint8_t *pt)
{
	aes_key_t	*ksch = (aes_key_t *)ks;
	const aes_impl_ops_t	*ops = ksch->ops;

	if (IS_P2ALIGNED2(ct, pt, sizeof (uint32_t)) && !ops->needs_byteswap) {
		/* LINTED:  pointer alignment */
		ops->decrypt(&ksch->decr_ks.ks32[0], ksch->nr,
		    /* LINTED:  pointer alignment */
		    (uint32_t *)ct, (uint32_t *)pt);
	} else {
		uint32_t buffer[AES_BLOCK_LEN / sizeof (uint32_t)];

		/* Copy input block into buffer */
		if (ops->needs_byteswap) {
			buffer[0] = htonl(*(uint32_t *)(void *)&ct[0]);
			buffer[1] = htonl(*(uint32_t *)(void *)&ct[4]);
			buffer[2] = htonl(*(uint32_t *)(void *)&ct[8]);
			buffer[3] = htonl(*(uint32_t *)(void *)&ct[12]);
		} else
			memcpy(&buffer, ct, AES_BLOCK_LEN);

		ops->decrypt(&ksch->decr_ks.ks32[0], ksch->nr, buffer, buffer);

		/* Copy result from buffer to output block */
		if (ops->needs_byteswap) {
			*(uint32_t *)(void *)&pt[0] = htonl(buffer[0]);
			*(uint32_t *)(void *)&pt[4] = htonl(buffer[1]);
			*(uint32_t *)(void *)&pt[8] = htonl(buffer[2]);
			*(uint32_t *)(void *)&pt[12] = htonl(buffer[3]);
		} else
			memcpy(pt, &buffer, AES_BLOCK_LEN);
	}
	return (CRYPTO_SUCCESS);
}


/*
 * Allocate key schedule for AES.
 *
 * Return the pointer and set size to the number of bytes allocated.
 * Memory allocated must be freed by the caller when done.
 *
 * Parameters:
 * size		Size of key schedule allocated, in bytes
 * kmflag	Flag passed to kmem_alloc(9F); ignored in userland.
 */
void *
aes_alloc_keysched(size_t *size, int kmflag)
{
	aes_key_t *keysched;

	keysched = kmem_alloc(sizeof (aes_key_t), kmflag);
	if (keysched != NULL) {
		*size = sizeof (aes_key_t);
		return (keysched);
	}
	return (NULL);
}

/* AES implementation that contains the fastest methods */
static aes_impl_ops_t aes_fastest_impl = {
	.name = "fastest"
};

/* All compiled in implementations */
static const aes_impl_ops_t *aes_all_impl[] = {
	&aes_generic_impl,
#if defined(__x86_64)
	&aes_x86_64_impl,
#endif
#if defined(__x86_64) && defined(HAVE_AES)
	&aes_aesni_impl,
#endif
#if defined(__aarch64__) && defined(HAVE_AESV8)
	&aes_aesv8_impl,
#endif
};

/* Indicate that benchmark has been completed */
static boolean_t aes_impl_initialized = B_FALSE;

/* Select aes implementation */
#define	IMPL_FASTEST	(UINT32_MAX)
#define	IMPL_CYCLE	(UINT32_MAX-1)

#define	AES_IMPL_READ(i) (*(volatile uint32_t *) &(i))

static uint32_t icp_aes_impl = IMPL_FASTEST;
static uint32_t user_sel_impl = IMPL_FASTEST;

/* Hold all supported implementations */
static size_t aes_supp_impl_cnt = 0;
static aes_impl_ops_t *aes_supp_impl[ARRAY_SIZE(aes_all_impl)];

/*
 * Returns the AES operations for encrypt/decrypt/key setup.  When a
 * SIMD implementation is not allowed in the current context, then
 * fallback to the fastest generic implementation.
 */
const aes_impl_ops_t *
aes_impl_get_ops(void)
{
	if (!kfpu_allowed())
		return (&aes_generic_impl);

	const aes_impl_ops_t *ops = NULL;
	const uint32_t impl = AES_IMPL_READ(icp_aes_impl);

	switch (impl) {
	case IMPL_FASTEST:
		ASSERT(aes_impl_initialized);
		ops = &aes_fastest_impl;
		break;
	case IMPL_CYCLE:
		/* Cycle through supported implementations */
		ASSERT(aes_impl_initialized);
		ASSERT3U(aes_supp_impl_cnt, >, 0);
		static size_t cycle_impl_idx = 0;
		size_t idx = (++cycle_impl_idx) % aes_supp_impl_cnt;
		ops = aes_supp_impl[idx];
		break;
	default:
		ASSERT3U(impl, <, aes_supp_impl_cnt);
		ASSERT3U(aes_supp_impl_cnt, >, 0);
		if (impl < ARRAY_SIZE(aes_all_impl))
			ops = aes_supp_impl[impl];
		break;
	}

	ASSERT3P(ops, !=, NULL);

	return (ops);
}

/*
 * Initialize all supported implementations.
 */
void
aes_impl_init(void)
{
	aes_impl_ops_t *curr_impl;
	int i, c;

	/* Move supported implementations into aes_supp_impls */
	for (i = 0, c = 0; i < ARRAY_SIZE(aes_all_impl); i++) {
		curr_impl = (aes_impl_ops_t *)aes_all_impl[i];

		if (curr_impl->is_supported())
			aes_supp_impl[c++] = (aes_impl_ops_t *)curr_impl;
	}

	aes_supp_impl_cnt = c;

	/*
	 * Set the fastest implementation given the assumption that the
	 * hardware accelerated version is the fastest.
	 */
#if defined(__aarch64__)
#if defined(HAVE_AESV8)
	if (aes_aesv8_impl.is_supported()) {
		memcpy(&aes_fastest_impl, &aes_aesv8_impl,
		    sizeof (aes_fastest_impl));
	} else
#endif
#endif
#if defined(__x86_64)
#if defined(HAVE_AES)
	if (aes_aesni_impl.is_supported()) {
		memcpy(&aes_fastest_impl, &aes_aesni_impl,
		    sizeof (aes_fastest_impl));
	} else
#endif
	{
		memcpy(&aes_fastest_impl, &aes_x86_64_impl,
		    sizeof (aes_fastest_impl));
	}
#else
	memcpy(&aes_fastest_impl, &aes_generic_impl,
	    sizeof (aes_fastest_impl));
#endif

	strlcpy(aes_fastest_impl.name, "fastest", AES_IMPL_NAME_MAX);

	/* Finish initialization */
	atomic_swap_32(&icp_aes_impl, user_sel_impl);
	aes_impl_initialized = B_TRUE;

}

static const struct {
	const char *name;
	uint32_t sel;
} aes_impl_opts[] = {
		{ "cycle",	IMPL_CYCLE },
		{ "fastest",	IMPL_FASTEST },
};

/*
 * Function sets desired aes implementation.
 *
 * If we are called before init(), user preference will be saved in
 * user_sel_impl, and applied in later init() call. This occurs when module
 * parameter is specified on module load. Otherwise, directly update
 * icp_aes_impl.
 *
 * @val		Name of aes implementation to use
 * @param	Unused.
 */
int
aes_impl_set(const char *val)
{
	int err = -EINVAL;
	char req_name[AES_IMPL_NAME_MAX];
	uint32_t impl = AES_IMPL_READ(user_sel_impl);
	size_t i;

	/* sanitize input */
	i = strnlen(val, AES_IMPL_NAME_MAX);
	if (i == 0 || i >= AES_IMPL_NAME_MAX)
		return (err);

	strlcpy(req_name, val, AES_IMPL_NAME_MAX);
	while (i > 0 && isspace(req_name[i-1]))
		i--;
	req_name[i] = '\0';

	/* Check mandatory options */
	for (i = 0; i < ARRAY_SIZE(aes_impl_opts); i++) {
		if (strcmp(req_name, aes_impl_opts[i].name) == 0) {
			impl = aes_impl_opts[i].sel;
			err = 0;
			break;
		}
	}

	/* check all supported impl if init() was already called */
	if (err != 0 && aes_impl_initialized) {
		/* check all supported implementations */
		for (i = 0; i < aes_supp_impl_cnt; i++) {
			if (strcmp(req_name, aes_supp_impl[i]->name) == 0) {
				impl = i;
				err = 0;
				break;
			}
		}
	}

	if (err == 0) {
		if (aes_impl_initialized)
			atomic_swap_32(&icp_aes_impl, impl);
		else
			atomic_swap_32(&user_sel_impl, impl);
	}

	return (err);
}

#if defined(_KERNEL)
#if defined(__linux__) || defined(__APPLE__)

static int
icp_aes_impl_set(const char *val, zfs_kernel_param_t *kp)
{
	return (aes_impl_set(val));
}

static int
icp_aes_impl_get(char *buffer, zfs_kernel_param_t *kp)
{
	int i, cnt = 0;
	char *fmt;
	const uint32_t impl = AES_IMPL_READ(icp_aes_impl);

	ASSERT(aes_impl_initialized);

	/* list mandatory options */
	for (i = 0; i < ARRAY_SIZE(aes_impl_opts); i++) {
		fmt = (impl == aes_impl_opts[i].sel) ? "[%s] " : "%s ";
		cnt += kmem_scnprintf(buffer + cnt, PAGE_SIZE - cnt, fmt,
		    aes_impl_opts[i].name);
	}

	/* list all supported implementations */
	for (i = 0; i < aes_supp_impl_cnt; i++) {
		fmt = (i == impl) ? "[%s] " : "%s ";
		cnt += kmem_scnprintf(buffer + cnt, PAGE_SIZE - cnt, fmt,
		    aes_supp_impl[i]->name);
	}

	return (cnt);
}
#endif /* defined(Linux) || defined(APPLE) */

#if defined(__APPLE__)
/* get / set function */
int
param_icp_aes_impl_set(ZFS_MODULE_PARAM_ARGS)
{
	char buf[1024]; /* Linux module string limit */
	int rc = 0;

	/* Always fill in value before calling sysctl_handle_*() */
	if (req->newptr == (user_addr_t)NULL)
		(void) icp_aes_impl_get(buf, NULL);

	rc = sysctl_handle_string(oidp, buf, sizeof (buf), req);
	if (rc || req->newptr == (user_addr_t)NULL)
		return (rc);

	rc = aes_impl_set(buf);
	return (rc);
}
#endif /* defined(APPLE) */



module_param_call(icp_aes_impl, icp_aes_impl_set, icp_aes_impl_get,
    NULL, 0644);
MODULE_PARM_DESC(icp_aes_impl, "Select aes implementation.");
#endif

#ifndef _KERNEL

#include <sys/zio_crypt.h>

void
aes_benchit(void)
{

	const aes_impl_ops_t *ops = aes_impl_get_ops();
	printf("%s(%s)\n", __func__, ops->name);

	unsigned char statickey[32] = {
		0x5c, 0x95, 0x64, 0x42, 0x00, 0x82, 0x1c, 0x9e,
		0xd4, 0xac, 0x01, 0x83, 0xc4, 0x9c, 0x14, 0x97,
		0x1c, 0x93, 0x04, 0xe2, 0x90, 0x99, 0x40, 0xfe,
		0x54, 0xec, 0xf1, 0x8a, 0x54, 0x22, 0x11, 0xff
	};

	unsigned char *plaindata  = NULL;
	unsigned char *cipherdata = NULL;
	unsigned char *mac = NULL;
	unsigned char *out_mac = NULL;
	unsigned char *iv  = NULL;
	unsigned char *salt = NULL;
	int size = 512;
	int saltsize = 8;
	int macsize = 16;
	int ivsize = 12;
	zio_crypt_key_t zkey;
	unsigned char out[180];
	unsigned char d = 0;
	int i, ret = ENOMEM;

	printf("*** ENCRYPTION TEST\n");

	plaindata = kmem_alloc(size, KM_SLEEP);
	if (!plaindata)
		goto out;
	cipherdata = kmem_alloc(size, KM_SLEEP);
	if (!cipherdata)
		goto out;
	mac = kmem_alloc(macsize, KM_SLEEP);
	if (!mac)
		goto out;
	out_mac = kmem_alloc(macsize, KM_SLEEP);
	if (!out_mac)
		goto out;
	iv = kmem_alloc(ivsize, KM_SLEEP);
	if (!iv)
		goto out;
	salt = kmem_alloc(saltsize, KM_SLEEP);
	if (!salt)
		goto out;

	for (i = 0, d = 0; i < size; i++, d++)
		plaindata[i] = d;
	memset(cipherdata, 0, size);

	printf("Setting iv to: \n");
	for (i = 0, d = 0xa8; i < ivsize; i++, d++) {
		iv[i] = d;
		printf("0x%02x ", iv[i]);
	}
	printf("\n");
	printf("Setting salt to: \n");
	for (i = 0, d = 0x61; i < saltsize; i++, d++) {
		salt[i] = d;
		printf("0x%02x ", salt[i]);
	}
	printf("\n");


	// Setup Key
	zkey.zk_crypt = ZIO_CRYPT_AES_256_CCM;
	zkey.zk_version = ZIO_CRYPT_KEY_CURRENT_VERSION;
	zkey.zk_current_tmpl = NULL;
	zkey.zk_salt_count = 0;
	memcpy(zkey.zk_salt, salt, saltsize);
	// zkey.zk_current_key.ck_format = CRYPTO_KEY_RAW;
	zkey.zk_current_key.ck_data = statickey;
	zkey.zk_current_key.ck_length =
	    CRYPTO_BYTES2BITS(sizeof (statickey));
	rw_init(&zkey.zk_salt_lock, NULL, RW_DEFAULT, NULL);
	// key done

	boolean_t no_crypt = B_FALSE;
	ret = zio_do_crypt_data(B_TRUE, &zkey,
	    DMU_OT_PLAIN_FILE_CONTENTS, FALSE, salt,
	    iv, mac, size, plaindata, cipherdata, &no_crypt);

	printf("zio_do_crypt_data encrypt %d\n", ret);

	if (ret)
		goto out;

	/*
	 * 0x5f 0x8a 0xcb 0x82 0xf3 0xb1 0x2b 0xce
	 * 0xa6 0x32 0x90 0x9b 0x08 0x78 0x20 0x12
	 * 0x3b 0x97 0x67 0x1f 0x7e 0x79 0x14 0xab
	 * 0xbb 0x8f 0x5b 0x17 0x9a 0x97 0xb9 0xae
	 *
	 * MAC output: 0x98 0x14 0x82 0xe4 0xbd 0xcb 0xee 0x9f
	 * 0x57 0x3a 0x37 0x55 0xce 0xb6 0xaa 0x57
	 */

	*out = 0;
	for (i = 0; i < 32 /* size */; i++) {
		snprintf((char *)out, sizeof (out), "%s 0x%02x",
		    out, cipherdata[i]);
		if ((i % 8) == 7) {
			printf("%s\n", out);
			*out = 0;
		}
	}
	printf("%s\nMAC output:", out);
	*out = 0;
	for (i = 0; i < 16; i++) {
		snprintf((char *)out, sizeof (out), "%s 0x%02x", out, mac[i]);
	}
	printf("%s\n", out);

	uint8_t valid_mac[] = {
		0x98, 0x14, 0x82, 0xe4, 0xbd, 0xcb, 0xee, 0x9f,
		0x57, 0x3a, 0x37, 0x55, 0xce, 0xb6, 0xaa, 0x57};
	uint8_t valid_crypt[] = {
		0x5f, 0x8a, 0xcb, 0x82, 0xf3, 0xb1, 0x2b, 0xce,
		0xa6, 0x32, 0x90, 0x9b, 0x08, 0x78, 0x20, 0x12,
		0x3b, 0x97, 0x67, 0x1f, 0x7e, 0x79, 0x14, 0xab,
		0xbb, 0x8f, 0x5b, 0x17, 0x9a, 0x97, 0xb9, 0xae};

	if (memcmp(valid_mac, mac, sizeof (valid_mac)) == 0)
		printf("MAC IS VALID\n");
	else
		printf("MAC IS *INVALID*\n");

	if (memcmp(valid_crypt, cipherdata, sizeof (valid_crypt)) == 0)
		printf("CIPHERDATA IS VALID\n");
	else
		printf("CIPHERDATA IS *INVALID*\n");


	printf("*** DECRYPTION TEST\n");



	// unwrap can clear all this if failed.
	zkey.zk_crypt = 5; /* aes-256-ccm */
	zkey.zk_current_tmpl = NULL;
	zkey.zk_salt_count = 0;
	memcpy(zkey.zk_salt, salt, saltsize);
	// zkey.zk_current_key.ck_format = CRYPTO_KEY_RAW;
	zkey.zk_current_key.ck_data = statickey;
	zkey.zk_current_key.ck_length =
	    CRYPTO_BYTES2BITS(sizeof (statickey));



	memset(plaindata, 0, size);
	printf("Setting iv to: \n");
	for (i = 0, d = 0xa8; i < ivsize; i++, d++) {
		iv[i] = d;
		printf("0x%02x ", iv[i]);
	}
	printf("\n");
	printf("Setting salt to: \n");
	for (i = 0, d = 0x61; i < saltsize; i++, d++) {
		salt[i] = d;
		printf("0x%02x ", salt[i]);
	}
	printf("\n");

	zkey.zk_salt_count = 0;
	memcpy(zkey.zk_salt, salt, saltsize);


	ret = zio_do_crypt_data(B_FALSE, &zkey, DMU_OT_NONE, FALSE, salt,
	    iv, mac, size, plaindata, cipherdata, &no_crypt);

	printf("zio_do_crypt_data decrypt %d\n", ret);


	*out = 0;
	for (i = 0; i < 32 /* size */; i++) {
		snprintf((char *)out, sizeof (out), "%s 0x%02x",
		    out, plaindata[i]);
		if ((i % 8) == 7) {
			printf("%s\n", out);
			*out = 0;
		}
	}
	printf("%s\n", out);

	rw_destroy(&zkey.zk_salt_lock);

out:
	if (salt)
		kmem_free(salt, saltsize);
	if (plaindata)
		kmem_free(plaindata, size);
	if (cipherdata)
		kmem_free(cipherdata, size);
	if (mac)
		kmem_free(mac, macsize);
	if (out_mac)
		kmem_free(out_mac, macsize);
	if (iv)
		kmem_free(iv, ivsize);
}
#endif

#ifndef _KERNEL
void
aes_benchmark(void)
{
	aes_impl_set("generic");
	aes_benchit();
	aes_impl_set("aesv8");
	aes_benchit();
}
#endif
