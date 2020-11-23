#!/bin/bash

set -e

parse_property_file()
{
  local fn=$1

  cat $fn | sed 's/[[:space:]]//g' | perl -n -e '
if(/^CHECK\(init\((\S+)\(\)\),LTL\((\S+)\)\)$/) {
  print "ENTRY=$1\n";
  print "PROP=\"label\"\nLABEL=\"$1\"\n" if($2 =~ /^G!label\((\S+)\)$/);
  print "PROP=\"unreach_call\"\n" if($2 =~ /^G!call\(__VERIFIER_error\(\)\)$/);
  print "PROP=\"unreach_call\"\n" if($2 =~ /^G!call\(reach_error\(\)\)$/);
  print "PROP=\"memsafety\"\n" if($2 =~ /^Gvalid-(free|deref|memtrack)$/);
  print "PROP=\"memcleanup\"\n" if($2 =~ /^Gvalid-memcleanup$/);
  print "PROP=\"overflow\"\n" if($2 =~ /^G!overflow$/);
  print "PROP=\"termination\"\n" if($2 =~ /^Fend$/);
}'
}

BIT_WIDTH="-m64"
BM=""
PROP_FILE=""
WITNESS_FILE=""

while [ -n "$1" ] ; do
  case "$1" in
    -m32|-m64) BIT_WIDTH="$1" ; shift 1 ;;
    --propertyfile) PROP_FILE="$2" ; shift 2 ;;
    --graphml-witness) WITNESS_FILE="$2" ; shift 2 ;;
    --version) echo "0.1" ; exit 0 ;;
    *) BM="$1" ; shift 1 ;;
  esac
done

if [ -z "$BM" ] || [ ! -s "$BM" ] ; then
  echo "Missing or empty benchmark file $BM"
  exit 1
fi

if [ -z "$PROP_FILE" ] || [ ! -s "$PROP_FILE" ] ; then
  echo "Missing or empty property file $PROP_FILE"
  exit 1
fi

if [ -z "$WITNESS_FILE" ] ; then
  echo "Missing witness file"
  exit 1
fi

if [ ! -e "$WITNESS_FILE" ] ; then
  echo "INVALID WITNESS FILE: witness file $WITNESS_FILE does not exist"
  exit 1
fi

if [ ! -s "$WITNESS_FILE" ] ; then
  echo "INVALID WITNESS FILE: witness file $WITNESS_FILE is empty"
  exit 1
fi

eval `parse_property_file $PROP_FILE`

if [ "$PROP" = "" ] ; then
  echo "Unrecognized property specification"
  exit 1
fi

if [ ! -d pycparser-master ] ; then
  wget https://codeload.github.com/eliben/pycparser/zip/master \
    -O pycparser-master.zip
  unzip pycparser-master.zip
fi

if [ ! -d pycparserext-master ] ; then
  wget https://codeload.github.com/tautschnig/pycparserext/zip/master \
    -O pycparserext-master.zip
  unzip pycparserext-master.zip
fi

SCRIPTDIR=$PWD
DATA=`mktemp -d -t witness.XXXXXX`
trap "rm -rf $DATA" EXIT
# echo $DATA

cp "$WITNESS_FILE" "$BM" $DATA
WITNESS_FILE=`basename "$WITNESS_FILE"`
BM=`basename "$BM"`
cd $DATA
PYTHONPATH=$SCRIPTDIR/pycparserext-master:$SCRIPTDIR/pycparser-master \
  python $SCRIPTDIR/process_witness.py \
  $BIT_WIDTH -w "$WITNESS_FILE" -b "$BM" > data
$SCRIPTDIR/TestEnvGenerator.pl < data

SAN_OPTS=""
case $PROP in
  overflow)
    SAN_OPTS="-fsanitize=signed-integer-overflow,shift"
    export UBSAN_OPTIONS="halt_on_error=1"
    perl -p -i -e 's/(void __VERIFIER_error\(\) \{) assert\(0\); (\})/$1$2/' tester.c
    ;;
  memsafety|memcleanup)
    SAN_OPTS="-fsanitize=address"
    if gcc -fsanitize=leak -x c -c /dev/null -o /dev/null > /dev/null 2>&1 ; then
      SAN_OPTS+=" -fsanitize=leak"
    fi
    perl -p -i -e 's/(void __VERIFIER_error\(\) \{) assert\(0\); (\})/$1$2/' tester.c
    ;;
esac

case `uname` in
  Darwin)
    assertion_failure_pattern="Assertion failed: (.*), function .*"
    ;;
  *)
    assertion_failure_pattern="tester: .*Assertion \`.*' failed."
    ;;
esac

ec=0
make -f tester.mk BUILD_FLAGS="-g $BIT_WIDTH -std=gnu99 -fgnu89-inline $SAN_OPTS" > log 2>&1 || ec=$?
# be safe and generate one
touch harness.c
cp harness.c $SCRIPTDIR/
case $PROP in
  unreach_call)
    if ! grep -q "$assertion_failure_pattern" log; then
      cat log 1>&2
      echo "$BM: ERROR - failing assertion not found" 1>&2
      if [ $ec -eq 0 ] ; then
        echo "TRUE"
      else
        echo "UNKNOWN"
      fi
      exit $ec
    fi
    echo "$BM: OK"
    echo "FALSE"
    ;;
  overflow)
    if grep -q "runtime error: signed integer overflow:" log ; then
      echo "$BM: OK"
      echo "FALSE(no-overflow)"
    elif egrep -q "runtime error: left shift of -?[[:digit:]]+ by [[:digit:]]+ places cannot be represented in type '.*'" log ; then
      echo "$BM: OK"
      echo "FALSE(no-overflow)"
    elif egrep -q "runtime error: negation of -?[[:digit:]]+ cannot be represented in type '.*'" log ; then
      echo "$BM: OK"
      echo "FALSE(no-overflow)"
    else
      cat log 1>&2
      echo "$BM: ERROR - failing overflow violation not found" 1>&2
      if [ $ec -eq 0 ] ; then
        echo "TRUE"
      else
        echo "UNKNOWN"
      fi
      exit $ec
    fi
    ;;
  memsafety)
    if egrep -q "^SUMMARY: AddressSanitizer: (bad|double)-free" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-free)"
    elif egrep -q "^SUMMARY: AddressSanitizer: (SEGV|stack-overflow|(stack|heap|global|dynamic-stack)-buffer-overflow)" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-deref)"
    elif egrep -q "^SUMMARY: AddressSanitizer: heap-use-after-free" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-deref)"
    elif egrep -q "^SUMMARY: AddressSanitizer: stack-use-after-scope" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-deref)"
    elif egrep -q "ERROR: AddressSanitizer: SEGV" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-deref)"
    elif grep -q "^SUMMARY: AddressSanitizer: .* leaked in" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-memtrack)"
    elif grep -q "Segmentation fault (core dumped)$" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-deref)"
    else
      cat log 1>&2
      echo "$BM: ERROR - failing memory safety violation not found" 1>&2
      if [ $ec -eq 0 ] ; then
        echo "TRUE"
      else
        echo "UNKNOWN"
      fi
      exit $ec
    fi
    ;;
  memcleanup)
    if grep -q "^SUMMARY: AddressSanitizer: .* leaked in" log ; then
      echo "$BM: OK"
      echo "FALSE(valid-memcleanup)"
    else
      cat log 1>&2
      echo "$BM: ERROR - memory cleanup violation not found" 1>&2
      if [ $ec -eq 0 ] ; then
        echo "TRUE"
      else
        echo "UNKNOWN"
      fi
      exit $ec
    fi
    ;;
  *)
    echo "$BM: property $PROP not yet handled"
    echo "UNKNOWN"
    ;;
esac
