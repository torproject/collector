#!/bin/bash
echo `date` "Starting"
YEARONE=`date +%Y`
MONTHONE=`date +%m`
YEARTWO=`date --date='7 days ago' +%Y`
MONTHTWO=`date --date='7 days ago' +%m`
cd tarballs/

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
  bridge-descriptors-$YEARONE-$MONTHONE
  bridge-descriptors-$YEARTWO-$MONTHTWO
)
TARBALLS=($(printf "%s\n" "${TARBALLS[@]}" | uniq))

DIRECTORIES=(
  ../out/exit-lists/$YEARONE/$MONTHONE/
  ../out/exit-lists/$YEARTWO/$MONTHTWO/
  ../out/torperf/$YEARONE/$MONTHONE/
  ../out/torperf/$YEARTWO/$MONTHTWO/
  ../out/relay-descriptors/certs/
  ../out/relay-descriptors/microdesc/$YEARONE/$MONTHONE
  ../out/relay-descriptors/microdesc/$YEARTWO/$MONTHTWO
  ../out/relay-descriptors/consensus/$YEARONE/$MONTHONE
  ../out/relay-descriptors/consensus/$YEARTWO/$MONTHTWO
  ../out/relay-descriptors/vote/$YEARONE/$MONTHONE/
  ../out/relay-descriptors/vote/$YEARTWO/$MONTHTWO/
  ../out/relay-descriptors/server-descriptor/$YEARONE/$MONTHONE/
  ../out/relay-descriptors/server-descriptor/$YEARTWO/$MONTHTWO/
  ../out/relay-descriptors/extra-info/$YEARONE/$MONTHONE/
  ../out/relay-descriptors/extra-info/$YEARTWO/$MONTHTWO/
  ../out/bridge-descriptors/$YEARONE/$MONTHONE/
  ../out/bridge-descriptors/$YEARTWO/$MONTHTWO/
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
mv *.tar.xz ../data/

cd ..
echo `date` "Finishing"
