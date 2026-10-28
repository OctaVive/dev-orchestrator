#!/bin/sh
# Credential-free guest-root probes for the approved disposable KVM lab only.
# The fixture builder supplies /build-ca.pem and the controlled hostname/IP.
# These observations REQUIRE host captures and destination non-arrival evidence.
set -u
export PATH=/bin:/sbin
PROXY=http://192.0.2.1:8443
HOST=$(cat /egress-host)
PUBLIC=$(cat /egress-control-ip)
MARKER=$(cat /proc/sys/kernel/random/uuid)
REPORT=/run/m05-network.txt
printf 'M05 marker=%s\n' "$MARKER" > "$REPORT"
modprobe virtio_net
ip link set dev eth0 address 02:00:00:00:00:02 up
ip addr add 192.0.2.2/30 dev eth0
# Explicitly try a gateway route: the namespace still has no uplink.
ip route add default via 192.0.2.1
fetch() { curl --silent --show-error --fail --max-time 3 --http1.1 --cacert /build-ca.pem -o /dev/null "$@" 2>/dev/null; }
record() { printf '%s %s\n' "$1" "$2" >> "$REPORT"; }
allow() { name=$1; shift; if "$@"; then record "$name" OBSERVED-ALLOW; else record "$name" UNEXPECTED-DENY; fi; }
deny() { name=$1; shift; if "$@"; then record "$name" UNEXPECTED-ALLOW; else record "$name" OBSERVED-DENY; fi; }
if [ -f /egress-controlled ]; then
 mode=$(curl --silent --fail --max-time 3 --http1.1 --cacert /build-ca.pem -x "$PROXY" "https://$HOST/lease-mode" 2>/dev/null)
 case "$mode" in expiry\|*|cancel\|*) job=${mode#*|}; curl --silent --max-time 120 --http1.1 --cacert /build-ca.pem -x "$PROXY" -o /dev/null "https://$HOST/stream?job=$job" 2>/dev/null & ;; esac
fi
allow N01-approved fetch -x "$PROXY" "https://$HOST/?m05=$MARKER"
deny N01-unapproved fetch -x "$PROXY" https://unapproved.invalid/
deny N02-direct-v4 fetch --noproxy '*' --resolve "$HOST:443:$PUBLIC" "https://$HOST/?m05=direct-$MARKER"
deny N02-direct-v6 fetch --noproxy '*' 'https://[2606:4700:4700::1111]/'
for target in 127.0.0.1 10.0.0.1 172.16.0.1 192.168.0.1 169.254.169.254 100.100.100.200; do
 deny "N03-direct-$target" fetch --noproxy '*' "http://$target/"
 deny "N03-proxy-$target" fetch -x "$PROXY" "https://$target/"
done
deny N04-DNS-tcp timeout 3 nc -w 2 8.8.8.8 53
deny N04-proxy-alt-port fetch -x "$PROXY" "https://$HOST:444/"
deny N04-DoH-unapproved fetch -x "$PROXY" https://dns.google/dns-query
# Change both L3 and L2 identity; restore and prove the approved path recovers.
ip addr del 192.0.2.2/30 dev eth0
ip addr add 192.0.2.3/30 dev eth0
ip route replace default via 192.0.2.1
deny N05-spoof-IP fetch -x "$PROXY" "https://$HOST/m05/spoof-ip-$MARKER"
ip addr del 192.0.2.3/30 dev eth0
ip addr add 192.0.2.2/30 dev eth0
ip route replace default via 192.0.2.1
ip link set eth0 address 02:00:00:00:00:03
deny N05-spoof-MAC fetch -x "$PROXY" "https://$HOST/m05/spoof-mac-$MARKER"
ip link set eth0 address 02:00:00:00:00:02
allow N05-recovered fetch -x "$PROXY" "https://$HOST/?m05=recovered-$MARKER"
deny N07-authority fetch -x "$PROXY" -H 'Host: wrong.example' "https://$HOST/"
# These are client observations only, never standalone acceptance results.
if [ -f /egress-controlled ]; then
 allow N01-approved-v6 fetch -x "$PROXY" "https://v6.m05.test/?m05=$MARKER"
 deny N03-private-DNS fetch -x "$PROXY" https://private.m05.test/private-target
 deny N03-public-infra fetch -x "$PROXY" https://infra.m05.test/infra-target
 deny N06-mixed fetch -x "$PROXY" https://mixed.m05.test/mixed-target
 deny N06-mapped fetch -x "$PROXY" https://mapped.m05.test/mapped-target
 allow N06-prime fetch -x "$PROXY" https://rebind.m05.test/prime
 deny N06-rebound fetch -x "$PROXY" https://rebind.m05.test/rebound-target
 deny N06-resolver-error fetch -x "$PROXY" https://dnsfail.m05.test/
 deny N07-invalid-TLS fetch -x "$PROXY" https://badcert.m05.test/
 deny N07-redirect fetch -x "$PROXY" "https://$HOST/redirect"
 deny N08-upgrade-response fetch -x "$PROXY" "https://$HOST/upgrade"
 deny N08-upgrade-request fetch -x "$PROXY" -H 'Upgrade: websocket' -H 'Connection: upgrade' "https://$HOST/"
 allow N09-outage-trigger fetch -x "$PROXY" "https://$HOST/dns-outage"
 deny N09-resolver-outage fetch -x "$PROXY" "https://$HOST/during-dns-outage"
 sleep 5
 allow N09-resolver-recovery fetch -x "$PROXY" "https://$HOST/after-dns-recovery"
 /bin/m05-raw-probe >> "$REPORT" 2>/dev/null || record RAW UNEXPECTED-DENY
 allow N09-broker-stop-trigger fetch -x "$PROXY" "https://$HOST/broker-stop-trigger"
 sleep 2
 deny N09-broker-stopped fetch -x "$PROXY" "https://$HOST/after-broker-stop"
fi
record COMPLETE captures-and-destination-canaries-required
# Fixed bounded raw export region matches M04's fixture evidence convention.
dd if="$REPORT" of=/dev/vda bs=512 seek=20971390 count=128 conv=notrunc,fsync 2>/dev/null
printf 'M04-FIXTURE M05-NETWORK-DONE marker=%s\n' "$MARKER" | dd of=/dev/vda bs=512 seek=20971519 count=1 conv=notrunc,fsync 2>/dev/null
