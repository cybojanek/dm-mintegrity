import os
import subprocess


class KModule(object):
    """Kernel module
    """

    def __init__(self, name, size, used_by=None):
        """Kernel module

        Argument:
        name - kernel module name
        size - kernel module size in bytes

        Keyword Arguments:
        used_by - set of other KModule that use this module

        """
        super(KModule, self).__init__()
        self.name = name
        self.size = size
        self.used_by = used_by if used_by is not None else set()


def loaded():
    """Get a dictionary of loaded kernel modules

    Return:
    dictionary of string -> KModule

    Exception:
    raise Exception on lsmod error

    """
    p = subprocess.Popen(["lsmod"], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()
    if(p.returncode != 0):
        raise Exception("Failed to get kernel modules: %s" % err)
    modules = {}

    # List of all modules
    for line in out.split("\n")[1:]:
        line = line.rstrip().split()
        if(len(line) < 3):
            continue
        name, size, n = line[0:3]
        modules[name] = KModule(name, int(size))

    # Get dependencies
    for line in out.split("\n")[1:]:
        line = line.rstrip().split()
        if(len(line) < 3):
            continue
        name, size, n = line[0:3]
        used_by = [] if len(line) < 4 else line[3].split(",")
        for m in used_by:
            modules[name].used_by.add(modules[m])
    return modules


def insmod(name, mod_name):
    """Load a .ko file. Not loaded if already in kernel

    Arguments:
    name - path to .ko file

    Exception:
    raise Exception on insmod error

    """
    modules = loaded()
    if mod_name in modules:
        return
    p = subprocess.Popen(["insmod", name], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()
    if(p.returncode != 0):
        raise Exception("Faild to insmod: %s, %s" % (name, err))


def modprobe(name):
    """Load a module. Not loaded if already in kernel

    Arguments:
    name - name of module

    Exception:
    raise Exception on modprobe error

    """
    modules = loaded()
    if name in modules:
        return
    p = subprocess.Popen(["modprobe", name], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()
    if(p.returncode != 0):
        raise Exception("Faild to modprobe: %s, %s" % (name, err))


def rmmod(name):
    """Unload a module. Not unlodaded if not in kernel

    Arguments:
    name of module

    Exception:
    raise Exception on rmmod error

    """
    modules = loaded()
    if name not in modules:
        return
    p = subprocess.Popen(["rmmod", name], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    out, err = p.communicate()
    if(p.returncode != 0):
        raise Exception("Faield to rmmod: %s, %s" % (name, err))
