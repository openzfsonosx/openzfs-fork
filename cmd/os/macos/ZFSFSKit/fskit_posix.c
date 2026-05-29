/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * The path→size registry and fskit_fstat_blk implementation have been
 * consolidated into lib/libspl/os/macos/fskit_posix.c so that
 * libzpool.dylib's fstat64_blk → fskit_fstat_blk (bound to libspl.dylib
 * via Mach-O two-level namespace) can access the same registry that
 * ZFSFileSystem.m populates via fskit_register_device().
 *
 * This file is intentionally empty.
 */
