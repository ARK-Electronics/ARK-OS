#!/bin/bash
source $(dirname $BASH_SOURCE)/functions.sh

# Check if we are on 20.04 or 22.04
codename=$(lsb_release -c | awk '{print $2}')
if [ "$codename" = "focal" ]; then
	echo "Ubuntu 20.04 detected, building MAVSDK from source"
	pushd .
	sudo rm -rf ~/code/MAVSDK
	git_clone_retry https://github.com/mavlink/MAVSDK.git ~/code/MAVSDK
	cd ~/code/MAVSDK
	cmake -Bbuild/default -DCMAKE_BUILD_TYPE=Release -H.
	cmake --build build/default -j$(nproc)
	sudo cmake --build build/default --target install
	sudo ldconfig
	popd
elif [ "$codename" = "jammy" ] || [ "$codename" = "bookworm" ]; then
	echo "Debian 12 detected, downloading the latest release of mavsdk"
	release_info=$(curl -s https://api.github.com/repos/mavlink/MAVSDK/releases/latest)
	# Assumes arm64
	download_url=$(echo "$release_info" | grep "browser_download_url.*debian12_arm64.deb" | awk -F '"' '{print $4}')
	file_name=$(echo "$release_info" | grep "name.*debian12_arm64.deb" | awk -F '"' '{print $4}')

	if [ -z "$download_url" ]; then
		echo "Download URL not found for arm64.deb package"
		exit 1
	fi

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
	echo "Downloading completed successfully."
	echo "Installing $file_name"

	for attempt in {1..5}; do
		sudo dpkg -i "$file_name" && break || sleep 5
	done

	if [ $attempt -eq 5 ]; then
		echo "Failed to install $file_name after 5 attempts."
		exit 1
	fi

	sudo rm "$file_name"
	sudo ldconfig
else
		echo "Failed to download the file after $max_attempts attempts."
	fi
else
	echo "Unsupported Ubuntu version, not installing MAVSDK"
fi
