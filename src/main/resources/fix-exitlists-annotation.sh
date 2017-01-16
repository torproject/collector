#!/bin/bash
#
#  Only for upgrading from 1.1.0 or 1.1.1!!!
#
#  Script for correcting exit-list annotations.
#  See task-21195 for details.
#  Replaces 'torperf' with 'tordnsel' in files
#  and archives.
#
#####
#
#  Please enter absolute paths below.
#
# As in collector.properties
RECENT=
OUT=
ARCHIVE=
#
# temporary path to use
TEMP=

function fix() {
    echo "----> Operating on $1 ..."
    find $1/$2/ -type f -exec sed -i s/torperf/tordnsel/ {} \;
    echo "----> $1 done."
}

echo "-> Starting to fix exit-lists ..."
fix $OUT "exit-lists"
fix $RECENT "exit-lists"

for ym in 2016-10 2016-11 2016-12 2017-01 ; do
    cd $TEMP;
    ARC="$ARCHIVE/exit-lists/exit-list-$ym.tar.xz"
    echo "--> Operating on $ARC ..."
    tar xf $ARC;
    fix $TEMP exit-list-$ym
    mv $ARC $ARC-old;
    tar --remove-files -cf exit-list-$ym.tar exit-list-$ym
    xz -9e exit-list-$ym.tar
    mv $TEMP/exit-list-$ym.tar.xz $ARC
    echo "--> $ARC is done."
done;
echo "-> Done.  Please verify the results and remove $ARCHIVE/*.tar.xz-old files."
exit 0;
