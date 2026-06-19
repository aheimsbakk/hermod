#!/bin/bash

SESSION_NAME="demo"

tmux kill-session -t $SESSION_NAME 2>/dev/null

# --- Layout ---
# --- Layout ---
tmux new-session -d -s $SESSION_NAME
tmux split-window -v -b -l 6 -t $SESSION_NAME
tmux split-window -h -t $SESSION_NAME:.2

# --- Per-pane command lists ---
# Use array syntax. Each entry is one command sent with Enter.
# Add, remove, or reorder entries freely per pane.

pane1_commands=(
	"ssh -lroot 192.168.122.11"
	"reset"
	"# Download latest hermod for your architecture"
	"curl -sSLO https://github.com/aheimsbakk/hermod/releases/download/v1.0.3/hermod-linux-amd64"
    ""
	"# Make it executable"
	"chmod +x ./hermod-linux-amd64"
    "reset"
    "# Start the signaling server on a reachable address"
	"./hermod-linux-amd64 serve"
)

pane2_commands=(
	"ssh -lroot 192.168.122.12"
	"reset"
	"# Download latest hermod for your architecture"
	"curl -sSLO https://github.com/aheimsbakk/hermod/releases/download/v1.0.3/hermod-linux-amd64"
    ""
	"# Make it executable"
	"chmod +x ./hermod-linux-amd64"
	"reset"
	"# First trust server (once)"
	"# TOFU trust in the demo"
	"# Option for verify with --fingerprint"
	"./hermod-linux-amd64 trust 192.168.122.11"
    ""
    "# Send text"
    "./hermod-linux-amd64 send \"Sent with quantum safe encryption\""
)

pane3_commands=(
	"ssh -lroot 192.168.122.13"
	"reset"
	"# Download latest hermod for your architecture"
	"curl -sSLO https://github.com/aheimsbakk/hermod/releases/download/v1.0.3/hermod-linux-amd64"
    ""
	"# Make it executable"
	"chmod +x ./hermod-linux-amd64"
	"reset"
	"# First trust server (once)"
    "# TOFU trust in the demo"
	"# Option for verify with --fingerprint"
	"./hermod-linux-amd64 trust 192.168.122.11"
    ""
)

# --- Helper ---
# Iterates over a command array and sends each line as a keystroke sequence.
send_to_pane() {
	local pane_id=$1
	shift
	for cmd in "$@"; do
		# Send one character at a time with a small delay, like human typing
		local len=${#cmd}
		for ((i = 0; i < len; i++)); do
			tmux send-keys -t "$SESSION_NAME:.${pane_id}" "${cmd:$i:1}"
			sleep 0.1
		done
		tmux send-keys -t "$SESSION_NAME:.${pane_id}" C-m
	done
}

# --- Execute all panes in parallel ---
send_to_pane 1 "${pane1_commands[@]}" &
send_to_pane 2 "${pane2_commands[@]}" &
send_to_pane 3 "${pane3_commands[@]}" &


(
	sleep 10m
	tmux kill-session -t "$SESSION_NAME" 2>/dev/null
) &

tmux attach-session -t $SESSION_NAME

wait