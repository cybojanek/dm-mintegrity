import kmod
import losetup

import os
import struct
import subprocess
import time
import unittest

BLOCK_SIZE = 4096
MB = 256
ZERO_BLOCK = "\x00" * BLOCK_SIZE
ONE_BLOCK = "\xFF" * BLOCK_SIZE
TEST_DISK = "TEST_DISK"
TEST_DISK_SIZE = 32 * MB
DM_REMOVE_ATTEMPTS = 30

JOURNAL_TRANSACTIONS = 1024
DATA_HASH_ALGO = "sha256"
HMAC_HASH_ALGO = "sha512"
SALT = "828a718f254536493328a359e173c44b"
INNER_PAD = "600fcc692203645093e6137132afc29ea10f71a83fb7864a18d2dac8d32e2583"
OUTER_PAD = "6937b814514dfdb8ace887741c2243a14c45a8c0e0b678bb4e3b35aa2e94d6b1"
DM_NAME = "meow"
DM_PATH = "/dev/mapper/%s" % DM_NAME


class TestMintegrity(unittest.TestCase):

    def setUp(self):
        kmod.modprobe("dm-bufio")
        kmod.insmod("dm-mintegrity/dm-mintegrity.ko", "dm_mintegrity")

        with open(TEST_DISK, "wb") as f:
            for i in range(TEST_DISK_SIZE):
                f.write(ZERO_BLOCK)

        self.loop = losetup.LoopbackDevice()
        self.loop.mount(TEST_DISK)

    def tearDown(self):
        kmod.rmmod("dm-mintegrity")
        kmod.rmmod("dm-bufio")
        self.loop.unmount()
        # os.remove(TEST_DISK)

    def _mkmint(self):
        p = subprocess.Popen(
            ["./mkmint/mkmint", self.loop.devices[0], str(BLOCK_SIZE),
             str(JOURNAL_TRANSACTIONS), DATA_HASH_ALGO, SALT, HMAC_HASH_ALGO,
             INNER_PAD, OUTER_PAD],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if(p.returncode != 0):
            raise Exception("Failed to mkmint")
        self.mkmint_command = out.split("\n")[-2]
        self.root_digest = self.mkmint_command.split()[13]
        self.hash_blocks = int(self.mkmint_command.split()[9])
        self.journal_blocks = int(self.mkmint_command.split()[10])
        self.data_blocks = int(self.mkmint_command.split()[11])

    def _dm_create(self):
        p = subprocess.Popen(
            ["dmsetup", "create", DM_NAME, "--table",
             "0 %s mintegrity %s %s %s %s %s %s %s %s %s %s %s" % (
                 self.data_blocks * (BLOCK_SIZE / 512),
                 self.loop.devices[0], str(BLOCK_SIZE), str(self.hash_blocks),
                 str(self.journal_blocks), str(self.data_blocks),
                 DATA_HASH_ALGO, self.root_digest, SALT, HMAC_HASH_ALGO,
                 INNER_PAD, OUTER_PAD)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if(p.returncode != 0):
            raise Exception("Failed to dmsetup create: %s", err)

    def _dm_remove(self):
        for x in range(DM_REMOVE_ATTEMPTS):
            p = subprocess.Popen(["dmsetup", "remove", DM_NAME],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate()
            if(p.returncode == 0):
                return
            elif x == DM_REMOVE_ATTEMPTS - 1:
                raise Exception("Failed to dmsetup remove: %s" % err)
            time.sleep(1)

    def _drop_caches(self):
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("3")
        time.sleep(2)

    def test_read_write(self):
        self._mkmint()
        self._dm_create()

        # Read all zeros
        with open(DM_PATH, "r") as f:
            for i in range(self.data_blocks):
                b = f.read(BLOCK_SIZE)
                assert b == ZERO_BLOCK

        # Write sequential integers
        with open(DM_PATH, "w") as f:
            for i in range(self.data_blocks * BLOCK_SIZE / 8):
                f.write(struct.pack("Q", i))
            f.flush()
            os.fsync(f)
        self._drop_caches()

        # Read sequential integers
        with open(DM_PATH, "r") as f:
            for i in range(self.data_blocks * BLOCK_SIZE / 8):
                b = f.read(8)
                n = struct.unpack("Q", b)[0]
                assert n == i

        # Write all ones
        with open(DM_PATH, "w") as f:
            for i in range(self.data_blocks):
                f.write(ONE_BLOCK)
            f.flush()
            os.fsync(f)
        self._drop_caches()

        # Read all ones
        with open(DM_PATH, "r") as f:
            for i in range(self.data_blocks):
                b = f.read(BLOCK_SIZE)
                assert b == ONE_BLOCK
        self._dm_remove()

    def test_data_corruption(self):
        self._mkmint()

        # Corrupt data
        with open(self.loop.devices[0], "w") as f:
            f.seek((self.hash_blocks + self.journal_blocks + 2) * BLOCK_SIZE)
            f.write(ONE_BLOCK)
            f.flush()
            os.fsync(f)

        self._dm_create()

        # Try reading corrupt data
        with open(DM_PATH, "r") as f:
            # First data block is ok
            b = f.read(BLOCK_SIZE)
            assert b == ZERO_BLOCK
            # Second will generate an IOError
            caught = False
            try:
                b = f.read(BLOCK_SIZE)
            except IOError:
                caught = True
            assert caught

        self._dm_remove()

    def test_hash_corruption(self):
        self._mkmint()

        # Corrupt root hash
        with open(self.loop.devices[0], "w") as f:
            f.seek(1 * BLOCK_SIZE)
            f.write(ONE_BLOCK)
            f.flush()
            os.fsync(f)

        self._dm_create()

        # Try reading ok data but corrupt hash block
        with open(DM_PATH, "r") as f:
            # Will generate an IOError
            caught = False
            try:
                b = f.read(BLOCK_SIZE)
            except IOError:
                caught = True
            assert caught

        self._dm_remove()

    def test_journal(self):
        return
        self._mkmint()
        self._dm_create()
        self._dm_remove()
