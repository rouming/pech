#!/bin/bash

set -e

CONF=/etc/ceph/ceph.conf
CLASS_DIR=/var/ceph/lib
REPLICATION=primary-copy
LOG_LEVEL=5
EXTRA_ARGS=
OSD=$1

if [ $# == 0 ]; then
	echo "Usage: <osd_id>"
	exit 1
fi

parse_mon_addrs()
{
	MON_ADDRS=`cat $CONF | perl -ne 'print $1 if /mon[\s+|_]host\s*=\s*(.*)/'`
	MON_ADDRS=`echo $MON_ADDRS | perl -ne 'print join ",", m/v1:([^\s\]]+)/g'`

	echo $MON_ADDRS
}

parse_fsid()
{
	FSID=`cat /var/ceph/dev/osd$OSD/fsid`

	echo $FSID
}

MON_ADDRS=`parse_mon_addrs`
FSID=`parse_fsid`

printf "MON_ADDRS=$MON_ADDRS\n"
printf "FSID=$FSID\n"
printf "REPLICATION=$REPLICATION\n"
printf "LOG_LEVEL=$LOG_LEVEL\n"
printf "EXTRA_ARGS=$EXTRA_ARGS\n"
