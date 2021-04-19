#!/bin/bash

if [[ ! -z $RUST_SUDO ]]; then
    exec sudo -E $@
else
	exec $@
fi
