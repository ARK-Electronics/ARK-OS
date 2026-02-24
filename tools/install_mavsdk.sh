#!/bin/bash
set -euo pipefail

# Pinned MAVSDK version — bump as needed
MAVSDK_VERSION="v3.15.0"

function git_clone_retry() {
	local url="$1" dir="$2" branch="${3:-}" retries=3 delay=5

	local clone_args=(--recurse-submodules)
	if [ -n "$branch" ]; then
		clone_args+=(-b "$branch")
	else
		clone_args+=(--depth=1 --shallow-submodules)
	fi

	until git clone "${clone_args[@]}" "$url" "$dir"; do
		((retries--)) || return 1
		echo "git clone failed, retrying in $delay seconds..."
		rm -rf "$dir" &>/dev/null
		sleep $delay
	done
}

codename=$(lsb_release -c | awk '{print $2}')

if [ "$codename" = "focal" ]; then
	echo "Ubuntu 20.04 detected, building MAVSDK ${MAVSDK_VERSION} from source"
	sudo rm -rf ~/code/MAVSDK
	git_clone_retry https://github.com/mavlink/MAVSDK.git ~/code/MAVSDK "$MAVSDK_VERSION"
	pushd ~/code/MAVSDK
	cmake -B build/default -DCMAKE_BUILD_TYPE=Release -H.
	cmake --build build/default -j$(nproc)
	sudo cmake --build build/default --target install
	sudo ldconfig
	popd

elif [ "$codename" = "jammy" ] || [ "$codename" = "bookworm" ]; then
	echo "Installing MAVSDK ${MAVSDK_VERSION} .deb package"
	# Strip leading 'v' for the download URL
	version_num="${MAVSDK_VERSION#v}"
	file_name="libmavsdk-dev_${version_num}_debian12_arm64.deb"
	download_url="https://github.com/mavlink/MAVSDK/releases/download/${MAVSDK_VERSION}/${file_name}"

	max_attempts=5
	attempt_num=1
	success=false

	while [ $attempt_num -le $max_attempts ]; do
		echo "Attempt $attempt_num: Downloading $download_url..."
		curl -sSL "$download_url" -o "$file_name" && success=true && break
		echo "Attempt $attempt_num failed, retrying in 5 seconds..."
		sleep 5
		((attempt_num++))
	done

	if [ "$success" = true ]; then
		echo "Installing $file_name"
		for attempt in {1..5}; do
			sudo dpkg -i "$file_name" && break || sleep 5
		done

		if [ $attempt -eq 5 ]; then
			echo "Failed to install $file_name after 5 attempts."
			exit 1
		fi

		rm -f "$file_name"
		sudo ldconfig
	else
		echo "Failed to download after $max_attempts attempts."
		exit 1
	fi
else
	echo "Unsupported distro: $codename"
	exit 1
fi
