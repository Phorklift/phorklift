#!/bin/bash

if [ ! -f ../src/phorklift ]; then
	echo 'ERROR: "../src/phorklift" does not exist! Please go to make it first.'
	exit 1
fi

# check invalid confs
for conf in `ls invalid_confs/*.lua`
do
	echo "check $conf"
	err=`grep "ERROR:" $conf | cut -d':' -f2-`
	if ! ../src/phorklift $conf 2>&1 | grep -Fq "$err" ; then
		echo "FAIL!!!"
		echo "expect error: $err; while got:"
		../src/phorklift $conf
		exit 1
	fi
done

# check good confs
for conf in `ls good_confs/*.lua good_confs/modules/*.lua`
do
	echo "check $conf"
	if ! ../src/phorklift $conf > /dev/null ; then
		echo "FAIL!!! canot start."
		exit 2
	fi

	grep "REQUEST" $conf -A1 |
	while read -r line_req ; do
		read -r line_exp
		request=`echo $line_req | cut -d':' -f2-`
		expect=`echo $line_exp | cut -d':' -f2- | sed 's/^ //'`
		if ! eval "$request" 2>&1 | grep -Fq "$expect" ; then
			echo "FAIL!!!"
			echo "expect: $expect"
			exit 3
		fi

		read -r sep
	done

	kill -QUIT `cat phorklift.pid`
done

# done
rm -f *.log
echo "DONE!"
