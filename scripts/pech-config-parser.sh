#!/bin/bash

set -e

CEPH_PATH=/var/lib/ceph

CONF=$CEPH_PATH/ceph.conf
CLASS_DIR=$CEPH_PATH/lib
REPLICATION=primary-copy
SERVER_IP=0.0.0.0
LOG_LEVEL=5
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
	FSID=`cat $CEPH_PATH/dev/osd$OSD/fsid`

	echo $FSID
}

parse_server_ip()
{
	# Parse first 'pech_osd_inet_dev=XXX' line
	DEV=`cat $CONF | perl -ne '$v=$1, print $1 if !defined $v && /pech[\s+|_]osd[\s+|_]inet[\s+|_]dev\s*=\s*(.*)/'`
	if [ "$DEV" != "" ]; then
		SERVER_IP=`ip -f inet addr show $DEV | sed -En -e 's/.*inet ([0-9.]+).*/\1/p'`
	fi

	echo $SERVER_IP
}

MON_ADDRS=`parse_mon_addrs`
FSID=`parse_fsid`
SERVER_IP=`parse_server_ip`

printf "MON_ADDRS=$MON_ADDRS\n"
printf "FSID=$FSID\n"
printf "CLASS_DIR=$CLASS_DIR\n"
printf "REPLICATION=$REPLICATION\n"
printf "SERVER_IP=$SERVER_IP\n"
printf "LOG_LEVEL=$LOG_LEVEL\n"
