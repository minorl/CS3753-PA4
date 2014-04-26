#!/bin/bash
#$MIRDIR.sh
MIRDIR=$1
MNTPT=$2

echo "----Test empty file write is encrypted-----"
echo "touch $MNTPT/empty"
touch $MNTPT/empty
echo "cat $MNTPT/empty #should be nothing"
cat $MNTPT/empty
echo "cat $MIRDIR/empty #should be encrypted"
cat $MIRDIR/empty

printf "\n\n\n\n"

echo "----Test file write is encrypted----"
echo "cal > $MNTPT/cal"
cal > $MNTPT/cal
echo "cat $MNTPT/cal #should be calendar"
cat $MNTPT/cal
echo "cat $MIRDIR/cal #should be encrypted"
cat $MIRDIR/cal

printf "\n\n\n\n"

echo "---Test file append is encrypted----"
echo "cal >> $MNTPT/cal"
cal >> $MNTPT/cal
echo "cat $MNTPT/cal #should be two calendar"
cat $MNTPT/cal
echo "cat $MIRDIR/cal #should be encrypted"
cat $MIRDIR/cal

printf "\n\n\n\n"

echo "----Test file write to mirrored dir isn't encrypted----"
echo "cal > $MIRDIR/unencrypted_cal"
cal > $MIRDIR/unencrypted_cal
echo "cat $MNTPT/unencrypted_cal #should be calendar"
cat $MNTPT/unencrypted_cal
echo "cat $MIRDIR/unencrypted_cal #should be unencrypted"
cat $MIRDIR/unencrypted_cal

printf "\n\n\n\n"

echo "----Test file append to unecrpted isn't encrypted----"
echo "cal >> $MNTPT/unencrypted_cal"
cal >> $MNTPT/unencrypted_cal
echo "cat $MNTPT/unencrypted_cal #should be 2 calendar"
cat $MNTPT/unencrypted_cal
echo "cat $MIRDIR/unencrypted_cal #should be unencrypted"
cat $MIRDIR/unencrypted_cal
