#!/usr/bin/env bash

set -euo pipefail

readonly LEFT_NS="wgmini-left"
readonly RIGHT_NS="wgmini-right"
readonly LEFT_VETH="veth-left"
readonly RIGHT_VETH="veth-right"

usage() {
	cat <<EOF
Usage: $0 {up|down|status}

  up      create the two-network-namespace lab
  down    remove the lab
  status  show its interfaces and addresses
EOF
}

namespace_exists() {
	ip netns list | awk '{print $1}' | grep -Fxq "$1"
}

down() {
	# Deleting a namespace also removes the interfaces contained in it.
	sudo ip netns del "$LEFT_NS" 2>/dev/null || true
	sudo ip netns del "$RIGHT_NS" 2>/dev/null || true
}

up() {
	if namespace_exists "$LEFT_NS" || namespace_exists "$RIGHT_NS"; then
		echo "lab already exists; run '$0 down' first" >&2
		exit 1
	fi

	# If setup fails halfway through, leave the host clean.
	trap down ERR

	sudo ip netns add "$LEFT_NS"
	sudo ip netns add "$RIGHT_NS"

	sudo ip link add "$LEFT_VETH" type veth peer name "$RIGHT_VETH"
	sudo ip link set "$LEFT_VETH" netns "$LEFT_NS"
	sudo ip link set "$RIGHT_VETH" netns "$RIGHT_NS"

	sudo ip -n "$LEFT_NS" addr add 192.0.2.1/24 dev "$LEFT_VETH"
	sudo ip -n "$RIGHT_NS" addr add 192.0.2.2/24 dev "$RIGHT_VETH"
	sudo ip -n "$LEFT_NS" link set "$LEFT_VETH" up
	sudo ip -n "$RIGHT_NS" link set "$RIGHT_VETH" up
	sudo ip -n "$LEFT_NS" link set lo up
	sudo ip -n "$RIGHT_NS" link set lo up

	trap - ERR
	echo "lab is up"
	echo "underlay: 192.0.2.1 ($LEFT_NS) <-> 192.0.2.2 ($RIGHT_NS)"
}

status() {
	for namespace in "$LEFT_NS" "$RIGHT_NS"; do
		if ! namespace_exists "$namespace"; then
			echo "$namespace: not found"
			continue
		fi

		echo "$namespace:"
	sudo ip -n "$namespace" -brief address show
	done
}

case "${1:-}" in
	up)
		up
		;;
	down)
		down
		echo "lab is down"
		;;
	status)
		status
		;;
	*)
		usage >&2
		exit 2
		;;
esac
