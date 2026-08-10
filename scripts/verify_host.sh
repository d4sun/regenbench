#!/bin/sh
set -u

MIN_CORES=4
MIN_RAM_GB=16
MIN_DISK_GB=50
PY_MIN_MAJOR=3
PY_MIN_MINOR=13
CONCURRENCY_TARGET=6
PROBE_IMAGE="docker.io/library/alpine:latest"

PASS=0
FAIL=0
SKIP=0

report() {
    status=$1
    what=$2
    detail=$3
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
    esac
    printf '%-4s  %-42s  %s\n' "$status" "$what" "$detail"
}

cores=$(nproc 2>/dev/null)
if [ "$cores" -ge "$MIN_CORES" ]; then
    report PASS "CPU cores" "${cores} (>=${MIN_CORES})"
else
    report FAIL "CPU cores" "${cores} (<${MIN_CORES})"
fi

ram_total=$(free -g 2>/dev/null | awk '/^Mem:/{print $2}')
ram_avail=$(free -g 2>/dev/null | awk '/^Mem:/{print $7}')
if [ -z "$ram_total" ]; then
    report FAIL "RAM (total GiB)" "free not available"
elif [ "$ram_total" -ge "$MIN_RAM_GB" ]; then
    report PASS "RAM (total GiB)" "${ram_total} (>=${MIN_RAM_GB})"
else
    report FAIL "RAM (total GiB)" "${ram_total} (<${MIN_RAM_GB})"
fi

disk_free=$(df -BG / 2>/dev/null | awk 'NR==2{print $4}' | tr -d 'G')
if [ -z "$disk_free" ]; then
    report FAIL "Free disk (root / GB)" "df not available"
elif [ "$disk_free" -ge "$MIN_DISK_GB" ]; then
    report PASS "Free disk (root / GB)" "${disk_free} (>=${MIN_DISK_GB})"
else
    report FAIL "Free disk (root / GB)" "${disk_free} (<${MIN_DISK_GB})"
fi

runtime=""
if command -v podman >/dev/null 2>&1; then
    runtime="podman"
elif command -v docker >/dev/null 2>&1; then
    runtime="docker"
fi

if [ -z "$runtime" ]; then
    report FAIL "Container runtime" "neither podman nor docker found"
else
    runtime_ver=$("$runtime" --version 2>/dev/null | head -n1)
    report PASS "Container runtime" "${runtime_ver}"
    if [ "$runtime" = "docker" ] && ! docker info >/dev/null 2>&1; then
        report FAIL "Runtime daemon" "docker client present but daemon unreachable"
    else
        report PASS "Runtime daemon" "$runtime daemon reachable"
    fi
fi

python_bin=$(command -v python3 2>/dev/null)
if [ -z "$python_bin" ]; then
    report FAIL "Python" "python3 not found"
else
    py_ver=$("$python_bin" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])' 2>/dev/null)
    py_major=$("$python_bin" -c 'import sys; print(sys.version_info[0])' 2>/dev/null)
    py_minor=$("$python_bin" -c 'import sys; print(sys.version_info[1])' 2>/dev/null)
    if [ "$py_major" -gt "$PY_MIN_MAJOR" ] || { [ "$py_major" -eq "$PY_MIN_MAJOR" ] && [ "$py_minor" -ge "$PY_MIN_MINOR" ]; }; then
        report PASS "Python" "${py_ver} (>=${PY_MIN_MAJOR}.${PY_MIN_MINOR})"
    else
        report FAIL "Python" "${py_ver} (<${PY_MIN_MAJOR}.${PY_MIN_MINOR})"
    fi
fi

if [ -z "$runtime" ]; then
    report SKIP "Concurrency capacity" "no runtime available"
else
    started=0
    i=1
    while [ "$i" -le "$CONCURRENCY_TARGET" ]; do
        if "$runtime" run -d --rm --name verify-host-probe-$i "$PROBE_IMAGE" sleep 20 >/dev/null 2>&1; then
            started=$((started + 1))
        fi
        i=$((i + 1))
    done
    i=1
    while [ "$i" -le "$CONCURRENCY_TARGET" ]; do
        "$runtime" rm -f verify-host-probe-$i >/dev/null 2>&1
        i=$((i + 1))
    done
    if [ "$started" -ge 6 ]; then
        report PASS "Concurrency capacity" "${started}/${CONCURRENCY_TARGET} containers started concurrently"
    else
        report FAIL "Concurrency capacity" "${started}/${CONCURRENCY_TARGET} containers started concurrently"
    fi
fi

printf '\nSummary: %d PASS, %d FAIL, %d SKIP\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]