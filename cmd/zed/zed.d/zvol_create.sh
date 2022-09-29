#!/bin/sh
# shellcheck disable=SC2154
#
# Log the zevent via syslog.
#

# Given POOL and DATASET name for ZVOL
# DEVICE_NAME  for /dev/disk*
# RAW_DEVICE_NAME for /dev/rdisk*
# Create symlink in
# /var/run/zfs/zvol/dsk/POOL/DATASET -> /dev/disk*
# /var/run/zfs/zvol/rdsk/POOL/DATASET -> /dev/rdisk*

ZVOL_ROOT="/var/run/zfs/zvol"

mkdir -p "$(dirname "${ZVOL_ROOT}/rdsk/${ZEVENT_POOL}/${ZEVENT_DATASET}")" "$(dirname "${ZVOL_ROOT}/dsk/${ZEVENT_POOL}/${ZEVENT_DATASET}")"

# Remove them if they already exist. (ln -f is not portable)
rm -f "${ZVOL_ROOT}/rdsk/${ZEVENT_POOL}/${ZEVENT_DATASET}" "${ZVOL_ROOT}/dsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"

ln -s "/dev/${ZEVENT_DEVICE_NAME}" "${ZVOL_ROOT}/dsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"
ln -s "/dev/${ZEVENT_RAW_DEVICE_NAME}" "${ZVOL_ROOT}/rdsk/${ZEVENT_POOL}/${ZEVENT_DATASET}"

logger -t "${ZED_SYSLOG_TAG:=zed}" -p "${ZED_SYSLOG_PRIORITY:=daemon.notice}" \
	eid="${ZEVENT_EID}" class="${ZEVENT_SUBCLASS}" \
	"${ZEVENT_POOL:+pool=$ZEVENT_POOL}/${ZEVENT_DATASET} symlinked ${ZEVENT_DEVICE_NAME}"

echo 0
