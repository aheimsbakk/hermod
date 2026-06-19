#!/bin/bash

SESSION_NAME="hermod_demo"

# Kill the session if it already exists to prevent duplication errors
tmux kill-session -t $SESSION_NAME 2>/dev/null

# 1. Start a new detached tmux session (Initial full-screen window, Pane index starts at 1)
tmux new-session -d -s $SESSION_NAME

# 2. Split the window vertically to create the bottom pane (Creates Pane 2)
# The -l 5 parameter forces the new bottom pane to be 5 lines high.
tmux split-window -v -l 5 -t $SESSION_NAME

# 3. Target the top pane (Pane 1) and split it horizontally (-h)
# This divides the top half into two equal left and right panes (Pane 1 and Pane 3).
tmux split-window -h -t $SESSION_NAME:.1

# Send commands to Pane 1 (Top Left)
tmux send-keys -t $SESSION_NAME:.1 "ssh -lroot 192.168.122.12" C-m
tmux send-keys -t $SESSION_NAME:.1 "reset" C-m
tmux send-keys -t $SESSION_NAME:.1 "curl -sSLO https://github.com/aheimsbakk/hermod/releases/download/v1.0.3/hermod-linux-amd64" C-m

# Send commands to Pane 3 (Top Right)
tmux send-keys -t $SESSION_NAME:.2 "ssh -lroot 192.168.122.13" C-m
tmux send-keys -t $SESSION_NAME:.2 "reset" C-m
tmux send-keys -t $SESSION_NAME:.2 "curl -sSLO https://github.com/aheimsbakk/hermod/releases/download/v1.0.3/hermod-linux-amd64" C-m

# Send commands to Pane 2 (Bottom Full-Width, 5 lines high)
# Uses corrected 'ip -br a' syntax.
tmux send-keys -t $SESSION_NAME:.3 "ssh -lroot 192.168.122.11" C-m
tmux send-keys -t $SESSION_NAME:.3 "reset" C-m
tmux send-keys -t $SESSION_NAME:.3 "curl -sSLO https://github.com/aheimsbakk/hermod/releases/download/v1.0.3/hermod-linux-amd64" C-m
#tmux send-keys -t $SESSION_NAME:.3 

# Attach to the session to display it
tmux attach-session -t $SESSION_NAME

sleep 10
tmux kill-server -t $SESSION_NAME
