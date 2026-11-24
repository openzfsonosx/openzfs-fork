#!/bin/bash
# SPDX-License-Identifier: CDDL-1.0
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# https://opensource.org/license/CDDL-1.0.
#

#exit code 1 means no zfs file systems mounted and no pools imported

echo "Mounted ZFS file system(s) check"
myvar="$(2>/dev/null /usr/bin/lsvfs zfs | /usr/bin/tail -1 | /usr/bin/awk '{print $2}')"
[ ! -z "${myvar##*[!0-9]*}" ] || exit 1
[ $myvar -ne 0 ] && exit 0

# An imported pool keeps the kext loaded even with nothing mounted
# (or on file vdevs), and every imported pool has a kstat.zfs.<pool>.
echo "Imported pool(s) check"
/usr/sbin/sysctl -N kstat.zfs 2>/dev/null | /usr/bin/cut -d. -f3 | \
    /usr/bin/grep -qvxE 'darwin|misc' && exit 0

sysctl -n kstat.zfs.darwin.ldi.handle_count || exit 1
if [ x"$(sysctl -n kstat.zfs.darwin.ldi.handle_count)" != x"0" ]; then exit 0; fi
exit 1
