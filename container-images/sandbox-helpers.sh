# SPDX-License-Identifier: GPL-3.0-only
# Sourced via BASH_ENV in agent containers.

command_not_found_handle()
{
	echo 'This sandbox has no tools installed except for podman
TRY AGAIN: Run tools via podman containers:
    podman run --rm -v "$PWD":"$PWD" -w "$PWD" IMAGE COMMAND [ARGS]
To install packages, build an image:
    printf "FROM alpine:3.21\\nRUN apk add --no-cache PKG\\n" | podman build -t name -
Common images: python, golang, gcc, rust, ruby, node, php, perl.'
	# Return an error that is NOT command not found so TRY AGAIN will work.
	return 2
}
