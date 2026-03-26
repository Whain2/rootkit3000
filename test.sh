# start with "sudo ./test.sh" or "make test"
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0

log()  { echo -e "${GREEN}[TEST]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()  { echo -e "${RED}[FAIL]${NC} $1"; }

pass() { log "  ✓ $1"; PASSED=$((PASSED + 1)); }
fail() { err "  ✗ $1"; FAILED=$((FAILED + 1)); }

CLIENT="./client"
MODULE="kernmod"
VIEWER="./test_viewer"

if [ "$(id -u)" -ne 0 ]; then
    err "This script must be run as root (sudo)"
    exit 1
fi

if [ ! -f "$CLIENT" ]; then
    err "Client not found. Run 'make' first."
    exit 1
fi

# build test_viewer
if [ ! -f "$VIEWER" ]; then
    log "Building test_viewer..."
    gcc -o test_viewer test_viewer.c
fi
chmod +x "$VIEWER"

log "Loading kernel module..."
rmmod $MODULE 2>/dev/null || true
insmod ${MODULE}.ko
sleep 0.5

if lsmod | grep -q "$MODULE"; then
    pass "Module loaded successfully"
else
    fail "Module failed to load"
    exit 1
fi

if [ -c "/dev/kernmod" ]; then
    pass "/dev/kernmod created"
else
    fail "/dev/kernmod not found"
    rmmod $MODULE
    exit 1
fi

# test 1 - File hiding
log ""
log "======================================"
log "        TEST 1: File hiding"
log "======================================"

TEST_DIR=$(mktemp -d)
touch "$TEST_DIR/normal.txt"
touch "$TEST_DIR/secret.txt"
touch "$TEST_DIR/also_secret.txt"

log "Files before hiding:"
ls "$TEST_DIR/"

$CLIENT hide-file "$TEST_DIR/secret.txt"
$CLIENT hide-file "$TEST_DIR/also_secret.txt"

log "Files after hiding (ls):"
ls "$TEST_DIR/"

if ls "$TEST_DIR/" 2>/dev/null | grep -q "secret.txt"; then
    fail "secret.txt still visible in ls"
else
    pass "secret.txt hidden from ls"
fi

if ls "$TEST_DIR/" 2>/dev/null | grep -q "also_secret.txt"; then
    fail "also_secret.txt still visible in ls"
else
    pass "also_secret.txt hidden from ls"
fi

if ls "$TEST_DIR/" 2>/dev/null | grep -q "normal.txt"; then
    pass "normal.txt still visible (not hidden)"
else
    fail "normal.txt disappeared (should be visible)"
fi

# stat not intercepted
if [ -f "$TEST_DIR/secret.txt" ]; then
    pass "Direct access (stat) to hidden file still works"
fi

# double hide
if $CLIENT hide-file "$TEST_DIR/secret.txt" 2>/dev/null; then
    fail "Double hide-file should return error"
else
    pass "Double hide-file correctly returns error"
fi

# return files
$CLIENT unhide-file "$TEST_DIR/secret.txt"
$CLIENT unhide-file "$TEST_DIR/also_secret.txt"

if ls "$TEST_DIR/" 2>/dev/null | grep -q "secret.txt"; then
    pass "secret.txt visible again after unhide"
else
    fail "secret.txt not restored after unhide"
fi

# non-existent file unhide - error ENOENT
if $CLIENT unhide-file "nonexistent_file_12345.txt" 2>/dev/null; then
    fail "Unhide of non-hidden file should return error"
else
    pass "Unhide of non-hidden file correctly returns error"
fi

rm -rf "$TEST_DIR"

# Process hiding
log ""
log "======================================"
log "      TEST 2: Process hiding"
log "======================================"

sleep 3600 &
SLEEP_PID=$!
log "Started sleep process with PID $SLEEP_PID"

if ps -p "$SLEEP_PID" > /dev/null 2>&1; then
    pass "Process $SLEEP_PID visible before hiding"
else
    fail "Process $SLEEP_PID not found (test setup error)"
fi

$CLIENT hide-pid "$SLEEP_PID"

# check through /proc
if ls /proc/ 2>/dev/null | grep -qw "$SLEEP_PID"; then
    fail "PID $SLEEP_PID still visible in /proc listing"
else
    pass "PID $SLEEP_PID hidden from /proc listing"
fi

# double hide
if $CLIENT hide-pid "$SLEEP_PID" 2>/dev/null; then
    fail "Double hide-pid should return error"
else
    pass "Double hide-pid correctly returns error"
fi

$CLIENT unhide-pid "$SLEEP_PID"

if ls /proc/ 2>/dev/null | grep -qw "$SLEEP_PID"; then
    pass "PID $SLEEP_PID visible again after unhide"
else
    fail "PID $SLEEP_PID not restored after unhide"
fi

kill $SLEEP_PID 2>/dev/null || true
wait $SLEEP_PID 2>/dev/null || true

# test 3 - Module hiding
log ""
log "======================================"
log "      TEST 3: Module hiding"
log "======================================"

log "Module in lsmod before hiding:"
lsmod | grep $MODULE || true

$CLIENT hide-module "$MODULE"

if lsmod | grep -q "$MODULE"; then
    fail "Module still visible in lsmod"
else
    pass "Module hidden from lsmod"
fi

if grep -q "$MODULE" /proc/modules 2>/dev/null; then
    fail "Module still in /proc/modules"
else
    pass "Module hidden from /proc/modules"
fi

if [ -d "/sys/module/$MODULE" ]; then
    # /sys/module hidden through hidden_files
    warn "/sys/module/$MODULE still accessible via stat (expected)"
else
    pass "Module hidden from /sys/module"
fi

# double hide
if $CLIENT hide-module "$MODULE" 2>/dev/null; then
    fail "Double hide-module should return error"
else
    pass "Double hide-module correctly returns error"
fi

$CLIENT unhide-module "$MODULE"

if lsmod | grep -q "$MODULE"; then
    pass "Module visible again in lsmod"
else
    fail "Module not restored after unhide"
fi

# test 4 - Trusted process
log ""
log "======================================"
log " TEST 4: Trusted processes (allow-pid)"
log "======================================"

TEST_DIR2=$(mktemp -d)
touch "$TEST_DIR2/visible.txt"
touch "$TEST_DIR2/hidden_file.txt"

$CLIENT hide-file "$TEST_DIR2/hidden_file.txt"

if ls "$TEST_DIR2/" 2>/dev/null | grep -q "hidden_file.txt"; then
    fail "hidden_file.txt should be hidden from ls"
else
    pass "hidden_file.txt hidden from ls"
fi

# using FIFO for test_viewer control
FIFO=$(mktemp -u)
mkfifo "$FIFO"
VIEWER_OUT=$(mktemp)

log "Starting test_viewer on $TEST_DIR2 ..."

# start viewer
$VIEWER "$TEST_DIR2" < "$FIFO" > "$VIEWER_OUT" 2>&1 &
VIEWER_PID=$!

sleep 0.5

log "  viewer PID: $VIEWER_PID"

$CLIENT allow-pid "$VIEWER_PID"
pass "allow-pid $VIEWER_PID executed"

# send enter
echo "" > "$FIFO"

wait $VIEWER_PID 2>/dev/null || true

log "  viewer output:"
cat "$VIEWER_OUT" | sed 's/^/    /'

VIEWER_OUTPUT=$(cat "$VIEWER_OUT")

if echo "$VIEWER_OUTPUT" | grep -q "hidden_file.txt"; then
    pass "Trusted process CAN see hidden_file.txt"
else
    fail "Trusted process should see hidden_file.txt but doesn't"
fi

if echo "$VIEWER_OUTPUT" | grep -q "visible.txt"; then
    pass "Trusted process also sees visible.txt"
else
    fail "Trusted process should see visible.txt"
fi

$CLIENT disallow-pid "$VIEWER_PID"
pass "disallow-pid $VIEWER_PID executed"

rm -f "$FIFO" "$VIEWER_OUT"

UNTRUSTED_OUTPUT=$(ls "$TEST_DIR2/" 2>/dev/null)
if echo "$UNTRUSTED_OUTPUT" | grep -q "hidden_file.txt"; then
    fail "Untrusted ls should NOT see hidden_file.txt"
else
    pass "Untrusted ls correctly does NOT see hidden_file.txt"
fi

$CLIENT unhide-file "$TEST_DIR2/hidden_file.txt"
rm -rf "$TEST_DIR2"

# test 5 - Status
log ""
log "======================================"
log "       TEST 5: Status command"
log "======================================"

TEST_DIR3=$(mktemp -d)
touch "$TEST_DIR3/status_test.txt"
$CLIENT hide-file "$TEST_DIR3/status_test.txt"

sleep 3600 &
STATUS_PID=$!
$CLIENT hide-pid "$STATUS_PID"

STATUS_OUTPUT=$($CLIENT status)
log "Status output:"
echo "$STATUS_OUTPUT" | sed 's/^/    /'

if echo "$STATUS_OUTPUT" | grep -q "Hidden files"; then
    pass "Status shows hidden files section"
else
    fail "Status missing hidden files section"
fi

if echo "$STATUS_OUTPUT" | grep -q "Hidden PIDs"; then
    pass "Status shows hidden PIDs section"
else
    fail "Status missing hidden PIDs section"
fi

if echo "$STATUS_OUTPUT" | grep -q "status_test.txt"; then
    pass "Status lists our hidden file"
else
    fail "Status doesn't list our hidden file"
fi

if echo "$STATUS_OUTPUT" | grep -q "$STATUS_PID"; then
    pass "Status lists our hidden PID"
else
    fail "Status doesn't list our hidden PID"
fi

# clear
$CLIENT unhide-pid "$STATUS_PID"
$CLIENT unhide-file "$TEST_DIR3/status_test.txt"
kill $STATUS_PID 2>/dev/null || true
wait $STATUS_PID 2>/dev/null || true
rm -rf "$TEST_DIR3"

# test 6 - Input validation
log ""
log "======================================"
log "      TEST 6: Input validation"
log "======================================"

if $CLIENT hide-pid "0" 2>/dev/null; then
    fail "hide-pid 0 should be rejected"
else
    pass "hide-pid 0 correctly rejected"
fi

if $CLIENT hide-pid "-1" 2>/dev/null; then
    fail "hide-pid -1 should be rejected"
else
    pass "hide-pid -1 correctly rejected"
fi

if $CLIENT hide-pid "abc" 2>/dev/null; then
    fail "hide-pid abc should be rejected"
else
    pass "hide-pid abc correctly rejected"
fi

if $CLIENT hide-module "nonexistent_module_xyz" 2>/dev/null; then
    fail "hide-module for non-existent module should fail"
else
    pass "hide-module for non-existent module correctly fails"
fi

# Clean
log ""
log "======================================"
log "              Cleanup"
log "======================================"

rmmod $MODULE
if lsmod | grep -q "$MODULE"; then
    fail "Module still loaded after rmmod"
else
    pass "Module unloaded cleanly"
fi

log ""
log "=== Kernel log (last 30 lines) ==="
dmesg | tail -30

log ""
log "======================================"
log "  RESULTS: ${GREEN}$PASSED passed${NC}, ${RED}$FAILED failed${NC}"
log "======================================"

if [ "$FAILED" -gt 0 ]; then
    exit 1
fi