#!/bin/bash
#
# Copyright 2016--2017 The Tor Project
# See LICENSE for licensing information.
#
# Script for creating descriptor tarballs on a CollecTor instance,
# and creating/touching the symlinks for the web-app.
#
####
# Configuration section:
# The following path should be adjusted, if the CollecTor server layout differs.
# All paths should be given absolute.
ARCHIVEDIR="/srv/collector.torproject.org/collector/archive"
WORKDIR="/srv/collector.torproject.org/collector/tarballs"
OUTDIR="/srv/collector.torproject.org/collector/out"
TARBALLTARGETDIR="/srv/collector.torproject.org/collector/data"
### end of configuration section.
#
### script start
echo `date` "Starting"
YEARONE=`date +%Y`
MONTHONE=`date +%m`
YEARTWO=`date --date='7 days ago' +%Y`
MONTHTWO=`date --date='7 days ago' +%m`
CURRENTPATH=`pwd`

mkdir -p $WORKDIR

cd $WORKDIR

if ! test -d $OUTDIR
  then echo "$OUTDIR doesn't exist.  Exiting."
  exit 1
fi

mkdir -p $TARBALLTARGETDIR

TARBALLS=(
  exit-list-$YEARONE-$MONTHONE
  exit-list-$YEARTWO-$MONTHTWO
  torperf-$YEARONE-$MONTHONE
  torperf-$YEARTWO-$MONTHTWO
  certs
  microdescs-$YEARONE-$MONTHONE
  microdescs-$YEARTWO-$MONTHTWO
  consensuses-$YEARONE-$MONTHONE
  consensuses-$YEARTWO-$MONTHTWO
  votes-$YEARONE-$MONTHONE
  votes-$YEARTWO-$MONTHTWO
  server-descriptors-$YEARONE-$MONTHONE
  server-descriptors-$YEARTWO-$MONTHTWO
  extra-infos-$YEARONE-$MONTHONE
  extra-infos-$YEARTWO-$MONTHTWO
  bridge-statuses-$YEARONE-$MONTHONE
  bridge-statuses-$YEARTWO-$MONTHTWO
  bridge-server-descriptors-$YEARONE-$MONTHONE
  bridge-server-descriptors-$YEARTWO-$MONTHTWO
  bridge-extra-infos-$YEARONE-$MONTHONE
  bridge-extra-infos-$YEARTWO-$MONTHTWO
)
TARBALLS=($(printf "%s\n" "${TARBALLS[@]}" | uniq))

DIRECTORIES=(
  $OUTDIR/exit-lists/$YEARONE/$MONTHONE/
  $OUTDIR/exit-lists/$YEARTWO/$MONTHTWO/
  $OUTDIR/torperf/$YEARONE/$MONTHONE/
  $OUTDIR/torperf/$YEARTWO/$MONTHTWO/
  $OUTDIR/relay-descriptors/certs/
  $OUTDIR/relay-descriptors/microdesc/$YEARONE/$MONTHONE
  $OUTDIR/relay-descriptors/microdesc/$YEARTWO/$MONTHTWO
  $OUTDIR/relay-descriptors/consensus/$YEARONE/$MONTHONE
  $OUTDIR/relay-descriptors/consensus/$YEARTWO/$MONTHTWO
  $OUTDIR/relay-descriptors/vote/$YEARONE/$MONTHONE/
  $OUTDIR/relay-descriptors/vote/$YEARTWO/$MONTHTWO/
  $OUTDIR/relay-descriptors/server-descriptor/$YEARONE/$MONTHONE/
  $OUTDIR/relay-descriptors/server-descriptor/$YEARTWO/$MONTHTWO/
  $OUTDIR/relay-descriptors/extra-info/$YEARONE/$MONTHONE/
  $OUTDIR/relay-descriptors/extra-info/$YEARTWO/$MONTHTWO/
  $OUTDIR/bridge-descriptors/$YEARONE/$MONTHONE/statuses/
  $OUTDIR/bridge-descriptors/$YEARTWO/$MONTHTWO/statuses/
  $OUTDIR/bridge-descriptors/$YEARONE/$MONTHONE/server-descriptors/
  $OUTDIR/bridge-descriptors/$YEARTWO/$MONTHTWO/server-descriptors/
  $OUTDIR/bridge-descriptors/$YEARONE/$MONTHONE/extra-infos/
  $OUTDIR/bridge-descriptors/$YEARTWO/$MONTHTWO/extra-infos/
)
DIRECTORIES=($(printf "%s\n" "${DIRECTORIES[@]}" | uniq))

for (( i = 0 ; i < ${#TARBALLS[@]} ; i++ )); do
  if [ ! -d ${TARBALLS[$i]} ]; then
    echo `date` "Creating symlink for" ${TARBALLS[$i]} 
    ln -s ${DIRECTORIES[$i]} ${TARBALLS[$i]}
  else
    # This is a workaround for the "tar u" bug in GNU tar 1.20
    echo `date` "Touching symlink and directories for" ${TARBALLS[$i]} 
    find -L ${TARBALLS[$i]} -type d | xargs touch
  fi
done

for (( i = 0 ; i < ${#TARBALLS[@]} ; i++ )); do
  echo `date` "Creating" ${TARBALLS[$i]}'.tar'
  tar chf ${TARBALLS[$i]}.tar ${TARBALLS[$i]}
  if [ ! -f ${TARBALLS[$i]}.tar.xz ]; then
    echo `date` "Compressing" ${TARBALLS[$i]}'.tar'
    xz -9e ${TARBALLS[$i]}.tar
  fi
done

echo `date` "Moving tarballs into place"
mv *.tar.xz $TARBALLTARGETDIR

cd $CURRENTPATH

echo `date` "Finished tarball creation.  Starting symlink-update ..."

mkdir -p $ARCHIVEDIR/bridge-descriptors/statuses/
ln -f -s -t $ARCHIVEDIR/bridge-descriptors/statuses/ $TARBALLTARGETDIR/bridge-statuses-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/bridge-descriptors/server-descriptors/
ln -f -s -t $ARCHIVEDIR/bridge-descriptors/server-descriptors/ $TARBALLTARGETDIR/bridge-server-descriptors-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/bridge-descriptors/extra-infos/
ln -f -s -t $ARCHIVEDIR/bridge-descriptors/extra-infos/ $TARBALLTARGETDIR/bridge-extra-infos-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/bridge-pool-assignments/
ln -f -s -t $ARCHIVEDIR/bridge-pool-assignments/ $TARBALLTARGETDIR/bridge-pool-assignments-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/exit-lists/
ln -f -s -t $ARCHIVEDIR/exit-lists/ $TARBALLTARGETDIR/exit-list-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/ $TARBALLTARGETDIR/certs.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/consensuses/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/consensuses/ $TARBALLTARGETDIR/consensuses-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/extra-infos/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/extra-infos/ $TARBALLTARGETDIR/extra-infos-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/microdescs/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/microdescs/ $TARBALLTARGETDIR/microdescs-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/server-descriptors/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/server-descriptors/ $TARBALLTARGETDIR/server-descriptors-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/statuses/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/statuses/ $TARBALLTARGETDIR/statuses-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/tor/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/tor/ $TARBALLTARGETDIR/tor-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/relay-descriptors/votes/
ln -f -s -t $ARCHIVEDIR/relay-descriptors/votes/ $TARBALLTARGETDIR/votes-20??-??.tar.xz

mkdir -p $ARCHIVEDIR/torperf/
ln -f -s -t $ARCHIVEDIR/torperf/ $TARBALLTARGETDIR/torperf-20??-??.tar.xz

echo `date` "Finished."
