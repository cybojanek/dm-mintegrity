#!/bin/bash
set -e
set -x
BASEDIR=$(dirname `readlink -f $0`)

################################################
# CONFIGURE THIS CORRECTLY
HDD=/dev/sda3
SSD=/dev/sdb
MOUNTPOINT=/mnt/scratch
MKMINT=${BASEDIR}/../mkmint/mkmint
################################################
# Leave ths alone
ALGORITHM_HASH=sha256
ALGORITHM_HMAC=sha256
JOURNAL_BLOCKS=16384 # 64 MiB
BLOCK_SIZE=4096
SALT=0011223344556677
SECRET=012345abcd

declare -A mkfs_commands
mkfs_commands["ext4_regular"]="mkfs.ext4 -F -E lazy_itable_init=0"
mkfs_commands["ext4_journal"]="mkfs.ext4 -F -E lazy_itable_init=0"
mkfs_commands["fat32"]="mkfs.vfat -F 32 -I"
mkfs_commands["xfs"]="mkfs.xfs -f"
mkfs_commands["ntfs"]="mkfs.ntfs -F -f"

declare -A mount_commands
mount_commands["ext4_regular"]="-t ext4 -o noatime"
mount_commands["ext4_journal"]="-t ext4 -o noatime,data=journal"
mount_commands["fat32"]="-t vfat -o noatime,uid=`id -u`"
mount_commands["xfs"]="-t xfs -o noatime"
mount_commands["ntfs"]="-t ntfs -o noatime"

declare -A block_devices
block_devices["none_ssd"]=$SSD
block_devices["none_hdd"]=$HDD
block_devices["sector_ssd"]="/dev/mapper/meow"
block_devices["sector_hdd"]="/dev/mapper/meow"
block_devices["full_ssd"]=$SSD
block_devices["full_hdd"]="/dev/mapper/meow"
block_devices["sector_shdd"]="/dev/mapper/meow"
block_devices["full_shdd"]="/dev/mapper/meow"

declare -A mkmint_devices
mkmint_devices["sector_ssd"]="$SSD $SSD"
mkmint_devices["sector_hdd"]="$HDD $HDD"
mkmint_devices["full_ssd"]="$SSD"
mkmint_devices["full_hdd"]="$HDD"
mkmint_devices["sector_shdd"]="$SSD $HDD"
mkmint_devices["full_shdd"]="$SSD $HDD"

declare -A journal_modes
journal_modes["sector_ssd"]="sector"
journal_modes["sector_hdd"]="sector"
journal_modes["full_ssd"]=""
journal_modes["full_hdd"]=""
journal_modes["sector_shdd"]="sector"
journal_modes["full_shdd"]=""

declare -A file_systems
file_systems["none_ssd"]="ext4_regular ext4_journal"
file_systems["none_hdd"]=${file_systems["none_ssd"]}
file_systems["sector_ssd"]="ext4_regular"
file_systems["sector_hdd"]="ext4_regular"
file_systems["full_ssd"]="ext4_regular"
file_systems["full_hdd"]="ext4_regular"
file_systems["sector_shdd"]="ext4_regular"
file_systems["full_shdd"]="ext4_regular"

drop_cache() {
    echo "Dropping caches..."
    echo 3 | sudo tee --append /proc/sys/vm/drop_caches > /dev/null
    echo "Sleeping 10 seconds..."
    sleep 10
}

DD_STREAM_SIZE=4096 # 4096 MiB

# Turn off and on tests here FALSE / TRUE, or comma seperater / empty
DD=FALSE
DATABASE=FALSE
LINUX_UNTAR=FALSE
FILEBENCHMARKS="filemicro_rread.f filemicro_rwritefsync.f filemicro_seqread.f filemicro_seqwritefsync.f varmail.f"
FILEBENCHMARKS="filemicro_rwritefsync.f"
#FILEBENCHMARKS="filemicro_seqwritefsync.f filemicro_rwritefsync.f"
#MODES="none_ssd none_hdd sector_ssd sector_hdd full_ssd full_hdd sector_shdd full_shdd"
#MODES="none_hdd full_hdd none_ssd full_ssd full_shdd"
#MODES="full_shdd"
MODES="full_ssd"


for MODE in $MODES; do
    echo "Running tests for ${MODE}"
    DIRECTORY=${BASEDIR}/results
    FILE_PREFIX="${MODE}""_crypt"
    #BLOCK_DEVICE=${block_devices[${MODE}]}
    BLOCK_DEVICE=${block_devices[${MODE}]}

    if [ ! -d $DIRECTORY ]; then
        mkdir $DIRECTORY
    fi


    if [ ${mkmint_devices[$MODE]+_} ]; then
        echo "Mkmint formatting disk..."
        COMMAND=`eval sudo ${MKMINT} ${mkmint_devices[$MODE]} ${BLOCK_SIZE} ${JOURNAL_BLOCKS} ${ALGORITHM_HASH} ${SALT} ${ALGORITHM_HMAC} ${SECRET} lazy ${journal_modes[$MODE]} | tail -1`
	#COMMAND=`eval sudo ${MKMINT} /dev/mapper/crypt ${BLOCK_SIZE} ${JOURNAL_BLOCKS} ${ALGORITHM_HASH} ${SALT} ${ALGORITHM_HMAC} ${SECRET} lazy ${journal_modes[$MODE]} | tail -1`
        if [ $? -ne 0 ]; then
            echo "Failed to run mkmint"
            exit 1
        fi
        echo "Mounting deivce mapper..." $COMMAND
        eval "sudo ${COMMAND}"
        if [ $? -ne 0 ]; then
            echo "Failed to run dmsetup create"
            exit 1
        fi
    fi

    # Dm-crypt Stacking over all modes
    sudo cryptsetup -s 512 luksFormat ${BLOCK_DEVICE}
    sudo cryptsetup open --type luks ${BLOCK_DEVICE} crypt
   
    if [ "$DD" == "TRUE" ]; then 
        drop_cache
        echo "Running dd read...${BLOCK_DEVICE}"
        sudo dd if=${BLOCK_DEVICE} of=/dev/null bs=1M count=${DD_STREAM_SIZE} &>> ${DIRECTORY}/${FILE_PREFIX}_dd_read.txt
        sudo dd if=${BLOCK_DEVICE} of=/dev/null bs=1M count=${DD_STREAM_SIZE} &>> ${DIRECTORY}/${FILE_PREFIX}_dd_read.txt
        
        drop_cache
        echo "Running dd write...${BLOCK_DEVICE}"
        sudo dd of=${BLOCK_DEVICE} if=/dev/zero bs=1M count=${DD_STREAM_SIZE} conv=fsync &>> ${DIRECTORY}/${FILE_PREFIX}_dd_write.txt
        sudo dd of=${BLOCK_DEVICE} if=/dev/zero bs=1M count=${DD_STREAM_SIZE} conv=fsync &>> ${DIRECTORY}/${FILE_PREFIX}_dd_write.txt
    fi
    

    for FILESYSTEM in ${file_systems[$MODE]}; do
        FILE_PREFIX="${MODE}""_crypt_""${FILESYSTEM}"
        # Format
        echo "Formatting disk...for ${FILESYSTEM}"
        eval "sudo ${mkfs_commands[${FILESYSTEM}]} /dev/mapper/crypt"
        #eval "sudo ${mkfs_commands[${FILESYSTEM}]} ${BLOCK_DEVICE}"
        if [ $? -ne 0 ]; then
            echo "Failed to format disk";
            exit 1;
        fi

        # Mount
        if [ ! -d $MOUNTPOINT ]; then
            sudo mkdir -p $MOUNTPOINT
        fi
        eval "sudo mount ${mount_commands[${FILESYSTEM}]} /dev/mapper/crypt ${MOUNTPOINT}"
        #eval "sudo mount ${mount_commands[${FILESYSTEM}]} ${BLOCK_DEVICE} ${MOUNTPOINT}"
        if [ $? -ne 0 ]; then
            echo "Failed to mount file system"
            exit 1
        fi

        # Modify for usage
        sudo chmod 777 ${MOUNTPOINT}
        sudo chmod -R 777 ${MOUNTPOINT}

        if [ "$LINUX_UNTAR" == "TRUE" ]; then
            echo "Copying and untaring Linux..."
            pushd ${MOUNTPOINT}
            if [ -d linux ]; then
                rm -rf linux
            fi
            mkdir linux
            cd linux
            cp ${BASEDIR}/linux-3.17.4.tar.xz .
            if [ $? -ne 0 ]; then
                echo "Failed to copy linux";
                exit 1;
            fi
            drop_cache
            { time tar -xf linux-3.17.4.tar.xz ; } &>> ${DIRECTORY}/${FILE_PREFIX}_linux_untar.txt
            if [ $? -ne 0 ]; then
               echo "Failed to untar linux";
            fi
            rm -rf linux-3.17.4
            { time tar -xf linux-3.17.4.tar.xz ; } &>> ${DIRECTORY}/${FILE_PREFIX}_linux_untar.txt
            if [ $? -ne 0 ]; then
                echo "Failed to untar linux";
            fi
#	    done
            popd
        fi

        if [ "$DATABASE" == "TRUE" ]; then
            echo "Running postgres benchmark..."
            sudo chmod -R 1777 /var/run/postgresql/
            # Run Postgres benchmark
            pushd ${MOUNTPOINT}
            if [ -d database ]; then
                rm -rf database
            fi
            mkdir database
            cd database
            /usr/lib/postgresql/9.4/bin/initdb . &>> ${DIRECTORY}/${FILE_PREFIX}_db.log
            if [ $? -ne 0 ]; then
                echo "Failed to create database"
                exit 1
            fi
    
            /usr/lib/postgresql/9.4/bin/pg_ctl -D . -l logfile start &>> ${DIRECTORY}/${FILE_PREFIX}_db.log
            if [ $? -ne 0 ]; then
                echo "Failed to start database"
                exit 1
            fi
    
            createdb pgbench
            if [ $? -ne 0 ]; then
                echo "Failed to create database"
                exit 1
            fi
    
            pgbench -i -s 100 pgbench &>> ${DIRECTORY}/${FILE_PREFIX}_db.log
            if [ $? -ne 0 ]; then
                echo "Failed to initialize database data"
            fi
   
            for x in `seq 1 2`; do 
                pgbench -c 10 -j 10 -t 1000 pgbench &>> ${DIRECTORY}/${FILE_PREFIX}_db.log
                if [ $? -ne 0 ]; then
                    echo "Failed to pgbench"
                fi
            done

          #  /usr/lib/postgresql/9.3/bin/pg_ctl -D . -l logfile stop &>> ${DIRECTORY}/${FILE_PREFIX}_db.log
            dropdb pgbench 
	    popd
        fi

        # Filebench
        for FILEBENCH in ${FILEBENCHMARKS}; do
            FILE_PREFIX=${MODE}"_crypt_"${FILESYSTEM}"_"${FILEBENCH}
            for x in `seq 1 2`; do
                drop_cache
                echo "Running filebench: ${MODE} ${FILESYSTEM} ${FILEBENCH}"
                sudo filebench -f ${FILEBENCH} &>> ${DIRECTORY}/${FILE_PREFIX}.log
            done
        done

        # Unmount
        sudo umount ${MOUNTPOINT}
        if [ $? -ne 0 ]; then
            echo "Failed to unmount filesystem"
        fi
    done
    sync

    #Closing the dm-crypt
    dm-crypt close
    sudo cryptsetup close crypt

    if [ ${mkmint_devices[$MODE]+_} ]; then
        sudo dmsetup suspend meow
        if [ $? -ne 0 ]; then
            echo "Failed to suspend device mapper"
            exit 1;
        fi
    
        sudo dmsetup remove meow
        if [ $? -ne 0 ]; then
            echo "Failed to remove device mapper"
            exit 1;
        fi
    fi
done    
