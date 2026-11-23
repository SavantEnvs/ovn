#!/usr/bin/env bash
#
# mayhem/build.sh — build OVN's fuzz harnesses and the test-ovn oracle.
#
# OVN builds on top of Open vSwitch, which upstream ships as the `ovs` git submodule (pinned gitlink;
# mayhem.yml checks it out with `submodules: recursive`, so it is in-image at /mayhem/ovs). Both
# projects are built out of tree under mayhem/_build/ (gitignored by mayhem/.gitignore):
#   _build/fuzz/{ovs,ovn}  — ASan+UBSan + DWARF-3 build; harnesses link libovn.a + libopenvswitch.a
#   _build/test/{ovs,ovn}  — normal-flags build of tests/ovstest (test-ovn), run by mayhem/test.sh
# `ALL_LOCAL=` skips upstream's source-tree lint targets (config-h-check, check-tabs, printf-check, ...),
# which grep `git ls-files` and would lint the mayhem/ harnesses; they build nothing.
# Re-runnable (configure only when no Makefile) and offline (no fetches).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
B="$SRC/mayhem/_build"
OVS_SRC="$SRC/ovs"
[ -f "$OVS_SRC/configure.ac" ] || { echo "ovs submodule missing (git submodule update --init)" >&2; exit 1; }

# Generate the autotools scripts (both are gitignored, so regenerate after a git clean).
[ -x "$OVS_SRC/configure" ] || (cd "$OVS_SRC" && ./boot.sh)
[ -x "$SRC/configure" ] || ./boot.sh

# configure_tree <dir> <cflags> <ldflags>: configure OVS then OVN out of tree in <dir>.
configure_tree() {
  local d="$1" cflags="$2" ldflags="$3"
  mkdir -p "$d/ovs" "$d/ovn"
  if [ ! -f "$d/ovs/Makefile" ]; then
    (cd "$d/ovs" && "$OVS_SRC/configure" CC="$CC" CFLAGS="$cflags" LDFLAGS="$ldflags" \
       --enable-static --disable-shared --disable-ssl --disable-libcapng)
  fi
  make -C "$d/ovs" -j"$MAYHEM_JOBS" ALL_LOCAL=
  if [ ! -f "$d/ovn/Makefile" ]; then
    (cd "$d/ovn" && "$SRC/configure" CC="$CC" CFLAGS="$cflags" LDFLAGS="$ldflags" \
       --enable-static --disable-shared --disable-ssl \
       --with-ovs-source="$OVS_SRC" --with-ovs-build="$d/ovs")
  fi
}

# 1) Sanitized project build (OVS + OVN libraries and the controller objects pinctrl needs).
# -fsanitize=fuzzer-no-link: SanCov edges in the project code, not only the harness.
FUZZ_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS -O1"
configure_tree "$B/fuzz" "$FUZZ_CFLAGS" "$SANITIZER_FLAGS"
make -C "$B/fuzz/ovn" -j"$MAYHEM_JOBS" ALL_LOCAL=

INC=(-I"$SRC" -I"$SRC/include" -I"$SRC/lib" -I"$B/fuzz/ovn" -I"$B/fuzz/ovn/lib" -I"$B/fuzz/ovn/include"
     -I"$OVS_SRC" -I"$OVS_SRC/include" -I"$OVS_SRC/lib" -I"$B/fuzz/ovs" -I"$B/fuzz/ovs/include" -I"$B/fuzz/ovs/lib")
LIBS=("$B/fuzz/ovn/lib/.libs/libovn.a" "$B/fuzz/ovs/lib/.libs/libopenvswitch.a" -lm -lpthread -lrt)

$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/standalone_main.o"

for h in fuzz_lex fuzz_expr fuzz_actions fuzz_addresses; do
  $CC $FUZZ_CFLAGS "${INC[@]}" -c "$SRC/mayhem/harnesses/$h.c" -o "$B/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "$B/lsan_off.o" "${LIBS[@]}" -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$h.o" "$B/standalone_main.o" "$B/lsan_off.o" "${LIBS[@]}" -o "$SRC/$h-standalone"
done

# pinctrl targets: the harness TU includes controller/pinctrl.c, so link every other ovn-controller
# object (not pinctrl.o, ovn-controller.o with main(), or the test-* objects) plus the SB/NB IDL.
CTRL_OBJS=()
for o in "$B"/fuzz/ovn/controller/*.o; do
  case "$(basename "$o")" in pinctrl.o|ovn-controller.o|test-*.o) ;; *) CTRL_OBJS+=("$o") ;; esac
done
for t in fuzz_pinctrl:"" fuzz_pinctrl_dhcpv6:"-DFUZZ_PINCTRL_DHCPV6"; do
  h="${t%%:*}"; def="${t#*:}"
  $CC $FUZZ_CFLAGS $def "${INC[@]}" -I"$SRC/controller" -I"$B/fuzz/ovn/controller" \
      -c "$SRC/mayhem/harnesses/fuzz_pinctrl.c" -o "$B/$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$h.o" "${CTRL_OBJS[@]}" "$B/lsan_off.o" "${LIBS[@]}" -o "$SRC/$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/$h.o" "${CTRL_OBJS[@]}" "$B/standalone_main.o" "$B/lsan_off.o" "${LIBS[@]}" -o "$SRC/$h-standalone"
done

# 2) Test oracle: upstream's tests/ovstest (test-ovn lex / parse-expr / parse-actions ...), NORMAL flags.
configure_tree "$B/test" "-O2 $COVERAGE_FLAGS" "$COVERAGE_FLAGS"
make -C "$B/test/ovn" -j"$MAYHEM_JOBS" ALL_LOCAL=
