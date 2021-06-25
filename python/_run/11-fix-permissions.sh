#!/bin/bash
set -euo pipefail

# Colorize me baby
green() { printf '\e[1;32m%b\e[0m\n' "$@"; }
yellow() { printf '\e[1;33m%b\e[0m\n' "$@"; }
red() { printf '\e[1;31m%b\e[0m\n' "$@"; }

# Do not run on PRELOAD builds
if [ "${PRELOAD:-null}" == "true" ]; then
    echo "PRELOAD Build: Skipping run of $(basename "$0")"
    exit
fi

RUN_USER="chrome"
APP_DIR="$(pwd)"

# Calculate user/group ids and set if required. (Mostly for linux)
USER_DEFAULT=$(id -u $RUN_USER)

green "Checking permissions of working dir: $APP_DIR"

# If the permissions of the application root directory do not contain the $RUN_USER uid...
if [[ -z "$(ls -n "$APP_DIR" | awk '{print $3}' | grep "$USER_DEFAULT")" ]]; then
    yellow "The working dir is not set to $RUN_USER..."

    # Get the UID and GID from the folder or existing environment variables.
    RUN_USER_UID=${RUN_USER_UID:-$(ls -ldn "$APP_DIR" | awk '{print $3}')}
    RUN_USER_GID=${RUN_USER_GID:-$(ls -ldn "$APP_DIR" | awk '{print $4}')}

    export RUN_USER_UID
    export RUN_USER_GID

    # If the new uid is not 0 and is not the uid of $RUN_USER, set the uid and gid of $RUN_USER to the new values.
    if [ "$RUN_USER_UID" != "0" ] && [ "$RUN_USER_UID" != "$(id -u $RUN_USER)" ]; then
        yellow "Changing $RUN_USER UID and GID to ${RUN_USER_UID} and ${RUN_USER_GID}."
        usermod -u "$RUN_USER_UID" "$RUN_USER"
        groupmod -g "$RUN_USER_GID" "$RUN_USER"
        chown -R $RUN_USER:$RUN_USER "$APP_DIR"
        yellow "Changed $RUN_USER UID and GID to ${RUN_USER_UID} and ${RUN_USER_GID}."
        green "Permissions are now correct!"
    else
        red "Unable to change UID from $RUN_USER_DEFAULT to $RUN_USER_UID"
    fi
else
    green "Permissions are correct!"
fi
