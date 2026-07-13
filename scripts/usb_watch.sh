#!/bin/bash
# Watch for a B210 USB disconnect while a capture loads the bus, and capture the
# kernel's reason (dmesg) at the moment it drops. Root cause = the dmesg lines
# immediately before the "USB disconnect".
LOG=/tmp/usb_watch.log
STREAM=/tmp/dmesg_stream.log
B=https://192.168.0.107:8443
: > "$LOG"; : > "$STREAM"
say(){ echo "[$(date +%T)] $*" | tee -a "$LOG"; }

say "=== USB disconnect watch start ==="
curl -sk --max-time 10 -c /tmp/lte_cookies.txt -X POST "$B/api/login" \
  -H "Content-Type: application/json" -d '{"username":"admin","password":"buchris"}' >/dev/null
ST=$(curl -sk --max-time 15 -b /tmp/lte_cookies.txt -X POST "$B/api/capture/start")
say "capture start -> $(echo "$ST" | python3 -c 'import sys,json;s=json.load(sys.stdin)["state"];print("running",s["running"],"pid",s["pid"])' 2>/dev/null)"

# follow kernel log with human timestamps into a file
sudo -n dmesg -wT > "$STREAM" 2>&1 &
DPID=$!

prev=$(lsusb | grep -c 2500:0020)
say "baseline: ettus_usb=$prev (expect 2)"
DET=0
for i in $(seq 1 360); do          # ~12 min @2s
  cur=$(lsusb | grep -c 2500:0020)
  ovf=$(curl -sk --max-time 5 "$B/metrics" 2>/dev/null | grep -E "ltesniffer_overflow_total " | grep -v "#\|created" | awk '{print $2}')
  if [ "$cur" -lt "$prev" ]; then
    say "*** USB DISCONNECT: ettus_usb $prev -> $cur  (overflow_total=$ovf) ***"
    DET=1
    sleep 3                         # let kernel flush the reason
    {
      echo "=== KERNEL LOG around the disconnect (USB/xhci) ==="
      grep -iE "usb|xhci|2500|over-?current|disconnect|error|reset|not accepting|descriptor|cannot enable" "$STREAM" | tail -50
    } >> "$LOG"
    break
  fi
  [ "$cur" -gt "$prev" ] && say "reconnect: ettus_usb $prev -> $cur"
  prev=$cur
  sleep 2
done

kill $DPID 2>/dev/null
curl -sk --max-time 12 -b /tmp/lte_cookies.txt -X POST "$B/api/capture/stop" >/dev/null
[ "$DET" -eq 0 ] && say "no disconnect caught in the watch window"
say "=== watch end ==="
echo; echo "---------- FULL LOG ----------"; cat "$LOG"
