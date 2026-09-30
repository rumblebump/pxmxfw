#!/usr/bin/env python3
"""Boot the pxmxfw VM image in QEMU and check it over the serial console.

Usage: tests/vm-boot.py IMAGE.qcow2

Like a Proxmox VM: VirtIO SCSI disk, net0 (eth0, the WAN, DHCP from QEMU's
user network) and net1 (eth1, the LAN). Logs in as root on ttyS0, checks
that first boot set up the firewall, then presses the ACPI power button
the way Proxmox's Shutdown does and waits for the VM to power off.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time

image = sys.argv[1]
tmp = tempfile.mkdtemp()
serial_path = os.path.join(tmp, "serial.sock")
monitor_path = os.path.join(tmp, "monitor.sock")
log = open("vm-serial.log", "wb")

accel = ["-enable-kvm", "-cpu", "host"] if os.access("/dev/kvm", os.W_OK) else []
qemu = subprocess.Popen([
    "qemu-system-x86_64", *accel, "-m", "512", "-smp", "2", "-display", "none",
    "-drive", f"file={image},if=none,id=d0,snapshot=on",
    "-device", "virtio-scsi-pci", "-device", "scsi-hd,drive=d0",
    "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
    "-netdev", "socket,id=n1,listen=127.0.0.1:40001", "-device", "virtio-net-pci,netdev=n1",
    "-serial", f"unix:{serial_path},server=on,wait=off",
    "-monitor", f"unix:{monitor_path},server=on,wait=off",
])


def connect(path):
    for _ in range(100):
        try:
            s = socket.socket(socket.AF_UNIX)
            s.connect(path)
            return s
        except OSError:
            time.sleep(0.1)
    sys.exit(f"cannot connect to {path}")


serial = connect(serial_path)
buf = b""


def expect(text, timeout):
    """Read the serial console until text shows up; return what was read."""
    global buf
    end = time.time() + timeout
    while text.encode() not in buf:
        if qemu.poll() is not None:
            sys.exit("QEMU exited")
        left = end - time.time()
        if left <= 0:
            sys.stdout.write(buf.decode(errors="replace"))
            sys.exit(f"timed out waiting for {text!r}")
        serial.settimeout(left)
        try:
            data = serial.recv(4096)
        except socket.timeout:
            continue
        log.write(data)
        log.flush()
        buf += data
    i = buf.index(text.encode()) + len(text)
    out, buf = buf[:i], buf[i:]
    return out.decode(errors="replace")


def send(line):
    serial.sendall(line.encode() + b"\n")


fail = False


def check(ok, what):
    global fail
    print(("ok   " if ok else "FAIL ") + what)
    fail = fail or not ok


expect("login:", 300)
send("root")
expect("# ", 30)
send("stty -echo; export PS1='# '")
expect("# ", 10)
# the WAN's DHCP lease may still be on its way
send("for i in $(seq 30); do ip -4 addr show eth0 | grep -q inet && break; sleep 1; done; echo ready")
expect("ready", 60)
send("pxmxfw status; echo ===; pxmxfw check; echo ===; ip -4 -o addr; nft list tables; "
     "rc-service pxmxfw-webui status; netstat -ltn; uname -r; echo END-OF-CHECKS")
out = expect("END-OF-CHECKS", 60)
print(out)
status, checks, rest = (out.split("===") + ["", ""])[:3]
check("target=vm" in status, "status says target=vm")
check("firewall=active" in status, "firewall rules are loaded")
check("ip_forward=1" in status, "IPv4 forwarding is on")
words = " ".join(rest.split())
check("eth0 inet 10.0.2.15/24" in words, "WAN eth0 got its address by DHCP")
check("eth1 inet 192.168.10.1/24" in words, "LAN eth1 has the default 192.168.10.1/24")
check("table inet pxmxfw" in rest, "nftables table inet pxmxfw exists")
check(":8443" in rest, "web UI listens on 8443")
fails = [l for l in checks.splitlines() if l.startswith("fail")]
check(not fails, "pxmxfw check has no failures" + ("".join("\n     " + l for l in fails)))

# Proxmox's Shutdown button without the guest agent: an ACPI power button press
mon = connect(monitor_path)
mon.sendall(b"system_powerdown\n")
try:
    qemu.wait(90)
    check(True, "VM powered off on the ACPI power button")
except subprocess.TimeoutExpired:
    check(False, "VM powered off on the ACPI power button")
    qemu.kill()

sys.exit(1 if fail else 0)
