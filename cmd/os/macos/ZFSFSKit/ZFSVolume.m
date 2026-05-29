/*
 * Copyright (c) 2025 Jorgen Lundman <lundman@lundman.net>
 *
 * ZFSVolume.m — FSVolumeOperations implementation for OpenZFS.
 *
 * Each ZFSVolume wraps one ZFS pool.  VFS operations are forwarded to the
 * embedded ZFS engine via the zfs_fskit.h C helpers that call libzpool/DMU.
 *
 * Item identity: ZFSItem subclasses FSItem and carries the ZFS DMU object
 * number in its objID property.  FSKit is opaque about FSItem internals;
 * we rely entirely on object-pointer identity when FSKit passes items back.
 *
 * Read-only PoC: all mutating operations (create, rename, remove, setAttr,
 * write) return EROFS.
 */

#import "ZFSVolume.h"
#import <FSKit/FSKit.h>
#include <sys/stat.h>
#include "zfs_fskit.h"

/* ------------------------------------------------------------------ */
#pragma mark - ZFSItem

@implementation ZFSItem

+ (instancetype)itemWithObjID:(uint64_t)objID
{
	ZFSItem *item = [[ZFSItem alloc] init];
	item.objID = objID;
	item.parentObjID = 0;
	return (item);
}

+ (instancetype)itemWithObjID:(uint64_t)objID parentObjID:(uint64_t)parentObjID
{
	ZFSItem *item = [[ZFSItem alloc] init];
	item.objID = objID;
	item.parentObjID = parentObjID;
	return (item);
}

@end

/* ------------------------------------------------------------------ */
#pragma mark - ZFSVolume helpers

/* Fill an FSItemAttributes object from a zfs_item_attrs_t C struct. */
static void
fill_fsitem_attrs(FSItemAttributes *dst, const zfs_item_attrs_t *src)
{
	uint32_t mode = src->mode;

	if (S_ISDIR(mode))
		dst.type = FSItemTypeDirectory;
	else if (S_ISLNK(mode))
		dst.type = FSItemTypeSymlink;
	else if (S_ISBLK(mode))
		dst.type = FSItemTypeBlockDevice;
	else if (S_ISCHR(mode))
		dst.type = FSItemTypeCharDevice;
	else if (S_ISFIFO(mode))
		dst.type = FSItemTypeFIFO;
	else if (S_ISSOCK(mode))
		dst.type = FSItemTypeSocket;
	else
		dst.type = FSItemTypeFile;

	dst.mode      = mode & 07777;
	dst.uid       = src->uid;
	dst.gid       = src->gid;
	dst.size      = src->size;
	dst.allocSize = (src->size + 511) & ~(uint64_t)511;
	dst.flags     = src->flags;
	dst.linkCount = src->nlink ? (uint32_t)src->nlink : 1;
	dst.fileID    = (FSItemID)src->obj_id;
	dst.accessTime = src->atime;
	dst.modifyTime = src->mtime;
	dst.changeTime = src->ctime;
	dst.birthTime  = src->btime;
}

/* Extract the ZFS obj_id from any FSItem we previously handed to FSKit. */
static uint64_t
obj_id_of_item(FSItem *item)
{
	if ([item isKindOfClass:[ZFSItem class]])
		return (((ZFSItem *)item).objID);
	/* Unexpected — fall back to root object as a safety net. */
	return (0);
}

/* ------------------------------------------------------------------ */
#pragma mark - ZFSVolume

@interface ZFSVolume () <FSVolumeReadWriteOperations>
@end

@implementation ZFSVolume {
	NSString	*_poolName;
	uint64_t	 _rootObj;	/* ZFS DMU object number of root dir */
}

- (instancetype)initWithPoolName:(NSString *)poolName poolGUID:(uint64_t)poolGUID
{
	/*
	 * Build the volume identifier from the pool GUID — exactly the same
	 * UUID construction used for the FSContainerIdentifier in probeResource:.
	 *
	 * FSKit requires: for FSUnaryFileSystem, the container identifier must
	 * equal the volume identifier (FSContainer.h, volumeIdentifier property
	 * comment).  A mismatch causes loadResource reply to fail with EAGAIN
	 * "unexpected container state".
	 */
	uuid_t uuid;
	memset(uuid, 0, sizeof (uuid));
	memcpy(uuid, &poolGUID, sizeof (poolGUID));

	NSUUID *nsuuid = [[NSUUID alloc] initWithUUIDBytes:uuid];
	FSVolumeIdentifier *vid =
	    [[FSVolumeIdentifier alloc] initWithUUID:nsuuid];
	FSFileName *fname = [FSFileName nameWithString:poolName];

	self = [super initWithVolumeID:vid volumeName:fname];
	if (self) {
		_poolName = [poolName copy];
		_rootObj  = 0; /* resolved in activate */
	}
	return (self);
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeOperations — lifecycle

- (void)activateWithOptions:(FSTaskOptions *)options
               replyHandler:(void (^)(FSItem * _Nullable rootItem,
                                      NSError * _Nullable err))reply
{
	NSLog(@"ZFSVolume(%@): activateWithOptions", _poolName);

	uint64_t root_obj = 0;
	int rc = zfs_fskit_root_obj(_poolName.UTF8String, &root_obj);
	if (rc != 0) {
		NSLog(@"ZFSVolume(%@): root_obj lookup failed: %d", _poolName, rc);
		reply(nil, fs_errorForPOSIXError(rc));
		return;
	}
	_rootObj = root_obj;

	ZFSItem *rootItem = [ZFSItem itemWithObjID:root_obj];
	reply(rootItem, nil);
}

- (void)deactivateWithOptions:(FSDeactivateOptions)options
                 replyHandler:(void (^)(NSError * _Nullable err))reply
{
	NSLog(@"ZFSVolume(%@): deactivate", _poolName);
	zfs_fskit_pool_export(_poolName.UTF8String);
	reply(nil);
}

- (void)mountWithOptions:(FSTaskOptions *)options
            replyHandler:(void (^)(NSError * _Nullable error))reply
{
	NSLog(@"ZFSVolume(%@): mountWithOptions", _poolName);
	reply(nil);
}

- (void)unmountWithReplyHandler:(void (^)(void))reply
{
	NSLog(@"ZFSVolume(%@): unmount", _poolName);
	reply();
}

- (void)synchronizeWithFlags:(FSSyncFlags)flags
                replyHandler:(void (^)(NSError * _Nullable error))reply
{
	reply(nil);
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumePathConfOperations (properties, part of FSVolumeOperations)

- (NSInteger)maximumLinkCount       { return (32767); }
- (NSInteger)maximumNameLength      { return (255); }
- (BOOL)restrictsOwnershipChanges   { return (YES); }
- (BOOL)truncatesLongNames          { return (NO); }

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeOperations — capabilities / statistics

- (FSVolumeSupportedCapabilities *)supportedVolumeCapabilities
{
	FSVolumeSupportedCapabilities *caps =
	    [[FSVolumeSupportedCapabilities alloc] init];
	caps.supportsSymbolicLinks       = YES;
	caps.supportsHardLinks           = YES;
	caps.supportsSparseFiles         = YES;
	caps.supports2TBFiles            = YES;
	caps.supports64BitObjectIDs      = YES;
	caps.supportsPersistentObjectIDs = YES;
	caps.caseFormat = FSVolumeCaseFormatSensitive;
	return (caps);
}

- (FSStatFSResult *)volumeStatistics
{
	FSStatFSResult *st =
	    [[FSStatFSResult alloc] initWithFileSystemTypeName:@"zfs"];
	st.blockSize  = 4096;
	st.totalBlocks = 0;
	st.freeBlocks  = 0;
	return (st);
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeOperations — attribute get / set

- (void)getAttributes:(FSItemGetAttributesRequest *)request
               ofItem:(FSItem *)item
         replyHandler:(void (^)(FSItemAttributes * _Nullable attrs,
                                NSError * _Nullable err))reply
{
	uint64_t obj = obj_id_of_item(item);
	if (obj == 0)
		obj = _rootObj;

	zfs_item_attrs_t raw = {};
	int rc = zfs_fskit_getattr(_poolName.UTF8String, obj, &raw);
	if (rc != 0) {
		reply(nil, fs_errorForPOSIXError(rc));
		return;
	}

	FSItemAttributes *attrs = [[FSItemAttributes alloc] init];
	fill_fsitem_attrs(attrs, &raw);

	/* Set parentID from the item's stored parent obj, if known. */
	if ([item isKindOfClass:[ZFSItem class]]) {
		uint64_t parentObj = ((ZFSItem *)item).parentObjID;
		if (parentObj != 0)
			attrs.parentID = (FSItemID)parentObj;
	}

	reply(attrs, nil);
}

- (void)setAttributes:(FSItemSetAttributesRequest *)newAttributes
               onItem:(FSItem *)item
         replyHandler:(void (^)(FSItemAttributes * _Nullable attrs,
                                NSError * _Nullable err))reply
{
	/* Read-only PoC */
	reply(nil, fs_errorForPOSIXError(EROFS));
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeOperations — namespace

- (void)lookupItemNamed:(FSFileName *)name
            inDirectory:(FSItem *)directory
           replyHandler:(void (^)(FSItem * _Nullable theItem,
                                  FSFileName * _Nullable itemName,
                                  NSError * _Nullable error))reply
{
	uint64_t dir_obj = obj_id_of_item(directory);
	if (dir_obj == 0)
		dir_obj = _rootObj;

	uint64_t child_obj = 0;
	const char *cname = name.string.UTF8String;
	if (cname == NULL) {
		reply(nil, nil, fs_errorForPOSIXError(EINVAL));
		return;
	}

	int rc = zfs_fskit_lookup(_poolName.UTF8String, dir_obj, cname,
	    &child_obj);
	if (rc != 0) {
		reply(nil, nil, fs_errorForPOSIXError(rc));
		return;
	}

	ZFSItem *child = [ZFSItem itemWithObjID:child_obj parentObjID:dir_obj];
	reply(child, name, nil);
}

- (void)reclaimItem:(FSItem *)item
       replyHandler:(void (^)(NSError * _Nullable err))reply
{
	reply(nil);
}

- (void)readSymbolicLink:(FSItem *)item
            replyHandler:(void (^)(FSFileName * _Nullable contents,
                                   NSError * _Nullable error))reply
{
	/* TODO: implement with DMU_OT_PLAIN_FILE_CONTENTS read */
	reply(nil, fs_errorForPOSIXError(ENOTSUP));
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeReadWriteOperations

- (void)readFromFile:(FSItem *)item
              offset:(off_t)offset
              length:(size_t)length
          intoBuffer:(FSMutableFileDataBuffer *)buffer
        replyHandler:(void (^)(size_t actuallyRead,
                               NSError * _Nullable error))reply
{
	uint64_t obj = obj_id_of_item(item);
	if (obj == 0)
		obj = _rootObj;

	size_t toRead = MIN(length, buffer.length);
	void *dst = [buffer mutableBytes];
	size_t actuallyRead = 0;

	int rc = zfs_fskit_read(_poolName.UTF8String, obj,
	    offset, toRead, dst, &actuallyRead);
	if (rc != 0) {
		reply(0, fs_errorForPOSIXError(rc));
		return;
	}
	reply(actuallyRead, nil);
}

- (void)writeContents:(NSData *)contents
               toFile:(FSItem *)item
             atOffset:(off_t)offset
         replyHandler:(void (^)(size_t actuallyWritten,
                                NSError * _Nullable error))reply
{
	reply(0, fs_errorForPOSIXError(EROFS));
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeOperations — directory enumeration

- (void)enumerateDirectory:(FSItem *)directory
          startingAtCookie:(FSDirectoryCookie)cookie
                  verifier:(FSDirectoryVerifier)verifier
       providingAttributes:(FSItemGetAttributesRequest * _Nullable)attributes
               usingPacker:(FSDirectoryEntryPacker *)packer
              replyHandler:(void (^)(FSDirectoryVerifier currentVerifier,
                                      NSError * _Nullable err))reply
{
	uint64_t dir_obj = obj_id_of_item(directory);
	if (dir_obj == 0)
		dir_obj = _rootObj;

	NSLog(@"ZFSVolume(%@): enumerateDirectory obj=%llu cookie=%llu",
	    _poolName, (unsigned long long)dir_obj,
	    (unsigned long long)cookie);

	/*
	 * FSKit docs: when attributes == nil, pack at least "." and "..".
	 * When attributes != nil, skip "." and "..".
	 */
	if (attributes == nil) {
		/* Pack the mandatory dot entries. */
		[packer packEntryWithName:[FSFileName nameWithCString:"."]
		                 itemType:FSItemTypeDirectory
		                   itemID:(FSItemID)dir_obj
		               nextCookie:FSDirectoryCookieInitial
		               attributes:nil];
		[packer packEntryWithName:[FSFileName nameWithCString:".."]
		                 itemType:FSItemTypeDirectory
		                   itemID:FSItemIDParentOfRoot
		               nextCookie:FSDirectoryCookieInitial
		               attributes:nil];
	}

	uint64_t cur_cookie = cookie;

	for (;;) {
		zfs_dirent_t   ent  = {};
		zfs_item_attrs_t raw = {};

		int rc = zfs_fskit_readdir_next(_poolName.UTF8String,
		    dir_obj, cur_cookie, &ent,
		    attributes ? &raw : NULL);

		if (rc != 0) {
			/* ENOENT = end of directory, not an error. */
			if (rc == ENOENT)
				rc = 0;
			reply(FSDirectoryVerifierInitial,
			    rc ? fs_errorForPOSIXError(rc) : nil);
			return;
		}

		FSItemType ftype = FSItemTypeUnknown;
		FSItemAttributes *fAttrs = nil;

		if (attributes != nil) {
			fAttrs = [[FSItemAttributes alloc] init];
			fill_fsitem_attrs(fAttrs, &raw);
			ftype = fAttrs.type;
		} else {
			ftype = ent.is_dir ?
			    FSItemTypeDirectory : FSItemTypeFile;
		}

		FSFileName *fname =
		    [FSFileName nameWithCString:ent.name];

		BOOL canContinue =
		    [packer packEntryWithName:fname
		                     itemType:ftype
		                       itemID:(FSItemID)ent.obj_id
		                   nextCookie:(FSDirectoryCookie)ent.next_cookie
		                   attributes:fAttrs];
		if (!canContinue)
			break;

		cur_cookie = ent.next_cookie;
	}

	reply(FSDirectoryVerifierInitial, nil);
}

/* ------------------------------------------------------------------ */
#pragma mark - FSVolumeOperations — mutating stubs (read-only PoC)

- (void)createItemNamed:(FSFileName *)name
                   type:(FSItemType)type
            inDirectory:(FSItem *)directory
             attributes:(FSItemSetAttributesRequest *)newAttributes
           replyHandler:(void (^)(FSItem * _Nullable newItem,
                                  FSFileName * _Nullable newItemName,
                                  NSError * _Nullable error))reply
{
	reply(nil, nil, fs_errorForPOSIXError(EROFS));
}

- (void)createSymbolicLinkNamed:(FSFileName *)name
                    inDirectory:(FSItem *)directory
                     attributes:(FSItemSetAttributesRequest *)newAttributes
                   linkContents:(FSFileName *)contents
                   replyHandler:(void (^)(FSItem * _Nullable newItem,
                                          FSFileName * _Nullable newItemName,
                                          NSError * _Nullable error))reply
{
	reply(nil, nil, fs_errorForPOSIXError(EROFS));
}

- (void)createLinkToItem:(FSItem *)item
                   named:(FSFileName *)name
             inDirectory:(FSItem *)directory
            replyHandler:(void (^)(FSFileName * _Nullable linkName,
                                   NSError * _Nullable error))reply
{
	reply(nil, fs_errorForPOSIXError(EROFS));
}

- (void)removeItem:(FSItem *)item
             named:(FSFileName *)name
     fromDirectory:(FSItem *)directory
      replyHandler:(void (^)(NSError * _Nullable error))reply
{
	reply(fs_errorForPOSIXError(EROFS));
}

- (void)renameItem:(FSItem *)item
       inDirectory:(FSItem *)sourceDirectory
             named:(FSFileName *)sourceName
        toNewName:(FSFileName *)destinationName
       inDirectory:(FSItem *)destinationDirectory
          overItem:(FSItem * _Nullable)overItem
      replyHandler:(void (^)(FSFileName * _Nullable newName,
                             NSError * _Nullable error))reply
{
	reply(nil, fs_errorForPOSIXError(EROFS));
}

@end
