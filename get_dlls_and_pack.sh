#!/bin/sh
EXE_FILE=./MyEncryptedNotes.exe

mkdir -p target
ldd  $EXE_FILE | grep $MINGW_PREFIX | awk '{print $3}' | xargs -i cp {} ./target
cp $EXE_FILE ./target
cp third_party_licenses.txt ./target
cp AppxManifest.xml ./target
cp -r Assets ./target