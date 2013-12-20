import subprocess


class LoopbackDevice(object):
    """docstring for LoopbackDevice"""
    def __init__(self):
        super(LoopbackDevice, self).__init__()
        self.filename = None
        self.devices = []

    def _update_devices(self):
        """Update list of device that use this file

        Exception:
        raise Exception on losetup error

        """
        # Record loopback device
        p = subprocess.Popen(["losetup", "-j", self.filename],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if(p.returncode != 0):
            raise Exception("Failed to losetup list %s, %s" % (self.filename,
                                                               err))
        for line in out.split("\n"):
            device = line.split(":")[0]
            if(device != ''):
                self.devices.append(device)

    def mount(self, filename):
        """Attach a file to a loopback device

        Arguments:
        filename - file to attach

        Exception:
        raise Exception on losetup error

        """
        self.filename = filename
        # Attach file to loopback device
        p = subprocess.Popen(["losetup", "-f", filename],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if(p.returncode != 0):
            raise Exception("Failed to losetup %s, %s" % (filename, err))

        # Update list
        self._update_devices()

        # Check that its not 0
        if(len(self.devices)) == 0:
            raise Exception("Failed to get list of attached devices")

    def unmount(self):
        """Unmount all devices attached

        Exception:
        raise Exception on losetup error

        """
        # Detatch all devices
        for device in self.devices:
            p = subprocess.Popen(["losetup", "-d", device],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            out, err = p.communicate()
            if(p.returncode != 0):
                raise Exception("Failed to losetup -d %s, %s" % (device, err))

        self.devices = []
