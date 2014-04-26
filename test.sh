#!/bin/bash
#test.sh


echo "---test empty file write is encrypted"
echo "touch hello/empty"
touch hello/empty
echo "cat hello/empty #should be nothing"
cat hello/empty
echo "cat test/empty #should be encrypted"
cat test/empty

printf "\n\n\n\n"

echo "---test file write is encrypted"
echo "cal > hello/cal"
cal > hello/cal
echo "cat hello/cal #should be calendar"
cat hello/cal
echo "cat test/cal #should be encrypted"
cat test/cal

printf "\n\n\n\n"

echo "---test file append is encrypted"
echo "cal >> hello/cal"
cal >> hello/cal
echo "cat hello/cal #should be two calendar"
cat hello/cal
echo "cat test/cal #should be encrypted"
cat test/cal

printf "\n\n\n\n"

echo "test file write to mirrored dir isn't encrypted"
echo "cal > test/unencrypted_cal"
cal > test/unencrypted_cal
echo "cat hello/unencrypted_cal #should be calendar"
cat hello/unencrypted_cal
echo "cat test/unencrypted_cal #should be unencrypted"
cat test/unencrypted_cal

printf "\n\n\n\n"

echo "test file append to unecrpted isn't encrypted"
echo "cal >> hello/unencrypted_cal"
cal >> hello/unencrypted_cal
echo "cat hello/unencrypted_cal #should be 2 calendar"
cat hello/unencrypted_cal
echo "cat test/unencrypted_cal #should be unencrypted"
cat test/unencrypted_cal
