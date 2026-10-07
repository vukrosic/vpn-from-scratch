#!/bin/sh
# Runs every step in order and prints what the video shows. A few seconds.
set -e
cd "$(dirname "$0")"
for f in step1_packet step2_network step3_tunnel step4_keys step5_encrypt step6_replay step7_vpn step8_real_socket exercise_leak; do
  echo "== $f"
  python3 $f.py
done
echo "== exercise_leak fixed"
python3 exercise_leak.py fixed
