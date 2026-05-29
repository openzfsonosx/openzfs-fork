/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * ZFSVolume.h — FSVolume subclass for one ZFS pool.
 *
 * ZFSVolume implements the FSVolumeOperations protocol (which also pulls in
 * FSVolumePathConfOperations).  For the PoC all mutating operations return
 * EROFS; the read path (getAttributes, lookup, enumerate) is wired to libzpool.
 */

#pragma once

#import <Foundation/Foundation.h>
#import <FSKit/FSKit.h>

NS_ASSUME_NONNULL_BEGIN

/*
 * ZFSItem — FSItem subclass that carries the ZFS DMU object number.
 *
 * FSItem is fully opaque (no public init, no properties).  We subclass it to
 * attach the ZFS object ID we need for every VFS operation.
 * Instantiation: [ZFSItem itemWithObjID:obj_number]
 */
@interface ZFSItem : FSItem
@property (nonatomic) uint64_t objID;
@property (nonatomic) uint64_t parentObjID;   /* parent dir's DMU obj number */
+ (instancetype)itemWithObjID:(uint64_t)objID;
+ (instancetype)itemWithObjID:(uint64_t)objID parentObjID:(uint64_t)parentObjID;
@end

/*
 * ZFSVolume — one imported ZFS pool presented as an FSKit volume.
 *
 * FSVolumeOperations extends FSVolumePathConfOperations, so a single
 * conformance declaration covers both.
 */
@interface ZFSVolume : FSVolume <FSVolumeOperations>

/*
 * The poolGUID must match the GUID used when building the FSContainerIdentifier
 * in probeResource:, because FSKit requires: for unary file systems, the
 * container identifier == the volume identifier (FSContainer.h comment).
 */
- (instancetype)initWithPoolName:(NSString *)poolName poolGUID:(uint64_t)poolGUID;

@end

NS_ASSUME_NONNULL_END
