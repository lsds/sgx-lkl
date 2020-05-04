#!/bin/bash


home=$(echo ~)
cd ~
sudo rm -rf openenclave/
openenclave_status_file_path="$home/.openenclave_last_successful_build_commit_id"
openenclave_install_dir="/opt/openenclave/"
openenclave_source_file="$openenclave_install_dir/share/openenclave/openenclaverc"
git clone -b feature/sgx-lkl-support https://github.com/openenclave/openenclave.git
cd openenclave
current_head_commit=$(git log --pretty=%H | head -1)
if [ -f "$openenclave_status_file_path" ]; then 
    last_successful_build=$(cat $openenclave_status_file_path)
    echo "Openenclave fetched HEAD ID           - $current_head_commit"
    echo "Current Openenclave installed from ID - $last_successful_build"
    
    if [[ "$current_head_commit" == "$last_successful_build" ]]; then
        echo "Openenclave installation is latest."
        if [ -f "$openenclave_source_file" ]; then
            exit 0
        else
            echo "Unable to locate $openenclave_source_file. Openenclave needs to reinstall."
        fi
    else
    echo "Openenclave needs to reinstall."
    fi
fi

# Don't build tests.
# TODO replace with build option https://github.com/openenclave/openenclave/issues/2894
sed -i '/add_subdirectory(tests)/d' CMakeLists.txt

sudo bash scripts/ansible/install-ansible.sh
sudo ansible-playbook scripts/ansible/oe-contributors-acc-setup-no-driver.yml

mkdir -p build
cd build
cmake -G "Ninja" ..
sudo ninja
sudo ninja install
if [[ "$?" == "0" ]]; then
    git log --pretty=%H | head -1 > $openenclave_status_file_path
fi
