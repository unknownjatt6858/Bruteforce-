import multiprocessing
import time
from hashlib import sha256, new as hashlib_new
from base58 import b58encode_check
from ecdsa import SECP256k1, SigningKey

input_file = "btc.txt"
output_file = "found_key.txt"

def priv_to_addr(privkey_int, compressed=True):
    sk = SigningKey.from_secret_exponent(privkey_int, curve=SECP256k1)
    vk = sk.get_verifying_key()

    if compressed:
        prefix = b'\x02' if vk.pubkey.point.y() % 2 == 0 else b'\x03'
        pubkey = prefix + vk.to_string()[:32]
    else:
        pubkey = b'\x04' + vk.to_string()

    sha = sha256(pubkey).digest()
    rip = hashlib_new('ripemd160', sha).digest()
    return b58encode_check(b"\x00" + rip).decode()

def worker(worker_id, start_range, end_range, result_queue, stats_queue):
    checked = 0
    for privkey_int in range(start_range, end_range + 1):
        addr_c = priv_to_addr(privkey_int, compressed=True)
        addr_u = priv_to_addr(privkey_int, compressed=False)

        if addr_c in addresses:
            result_queue.put((worker_id, privkey_int, addr_c, "Compressed"))
        if addr_u in addresses:
            result_queue.put((worker_id, privkey_int, addr_u, "Uncompressed"))

        checked += 1
        if checked % 1000 == 0:  # every 1000 keys send update
            stats_queue.put(checked)

    stats_queue.put(checked)  # final update

def load_addresses():
    with open(input_file, "r") as f:
        return set(line.strip() for line in f if line.strip())

def split_range(start, end, parts):
    total = end - start + 1
    step = total // parts
    ranges = []
    for i in range(parts):
        s = start + i * step
        e = start + (i + 1) * step - 1 if i < parts - 1 else end
        ranges.append((s, e))
    return ranges

def main():
    global addresses
    addresses = load_addresses()

    try:
        start_range = int(input("[?] Enter start range (hex): "), 16)
        end_range = int(input("[?] Enter end range (hex): "), 16)
        if start_range > end_range:
            print("[!] Start range must be less than End range.")
            return
    except ValueError:
        print("[!] Invalid hex input.")
        return

    try:
        cores = int(input("[?] Enter number of CPU cores to use: "))
    except ValueError:
        cores = 1

    result_queue = multiprocessing.Queue()
    stats_queue = multiprocessing.Queue()

    ranges = split_range(start_range, end_range, cores)
    workers = []

    print("\n[~] Launching workers...\n")
    for i in range(cores):
        p = multiprocessing.Process(target=worker, args=(i, ranges[i][0], ranges[i][1], result_queue, stats_queue))
        p.start()
        workers.append(p)

    total_checked = 0
    last_time = time.time()

    try:
        while any(w.is_alive() for w in workers):
            time.sleep(0.5)

            while not stats_queue.empty():
                total_checked += stats_queue.get()

            now = time.time()
            if now - last_time >= 2:  # show total checked every 2 seconds
                print(f"[~] Total Checked: {total_checked:,} keys")
                last_time = now

            while not result_queue.empty():
                wid, priv, addr, addr_type = result_queue.get()
                print(f"[+] MATCH FOUND by Worker-{wid:02}:")
                print(f"    Private Key: {hex(priv)}")
                print(f"    Address    : {addr} ({addr_type})\n")
                with open(output_file, "a") as f:
                    f.write(f"Worker-{wid:02}: PrivateKey: {hex(priv)} --> Address: {addr} ({addr_type})\n")

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")

    for w in workers:
        w.terminate()

if __name__ == "__main__":
    main()