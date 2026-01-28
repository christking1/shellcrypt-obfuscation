# shellcrypt.py - shellcode-xor 

import argparse
import sys

def xor_dra_på(shellcode: bytes, nyckel: bytes) -> bytes:
    # xor ar allting, nyckeln loopar om den är kortare än shellcode
    result = bytearray()
    for i in range(len(shellcode)):
        result.append(shellcode[i] ^ nyckel[i % len(nyckel)])
    return bytes(result)


def gör_till_c_array(bytes_grej: bytes, namn="buf") -> str:
    # typ sån där C-array som många malware använder
    lines = [f"unsigned char {namn}[] = {{"]
    for i, byte in enumerate(bytes_grej):
        if i % 12 == 0 and i != 0:
            lines[-1] += ","
            lines.append("    ")
        else:
            if i > 0:
                lines[-1] += ", "
        lines[-1] += f"0x{byte:02x}"
    
    lines[-1] += " };"
    lines.append(f"unsigned int {namn}_len = {len(bytes_grej)};")  # längden behövs nästan alltid
    return "\n".join(lines)


def gör_till_python_array(bytes_grej: bytes, namn="buf") -> str:
    # python grej, bytearray som man kan kopiera in i loadern
    lines = [f"{namn} = bytearray(["]
    for i, byte in enumerate(bytes_grej):
        if i % 12 == 0 and i != 0:
            lines[-1] += ","
            lines.append("    ")
        else:
            if i > 0:
                lines[-1] += ", "
        lines[-1] += f"0x{byte:02x}"
    lines[-1] += "])"
    return "\n".join(lines)


def fixa_nyckel(nyckel_str: str) -> bytes:
    # tar emot typ 0xAA eller deadbeef eller AA BB eller vanlig text
    nyckel_str = nyckel_str.lower().replace("0x", "").replace(" ", "").replace(",", "")
    try:
        return bytes.fromhex(nyckel_str)
    except:
        # om det inte är hex så blir det ascii bytes istället
        return nyckel_str.encode("utf-8")


def main():
    print("=== shellcrypt v1.0 - göm din shellcode===")
    print("   (koden funkar\n")

    parser = argparse.ArgumentParser(description="XOR:ar shellcode")
    
    parser.add_argument("--input", required=True, help="filen med rå shellcode (typ raw.bin)")
    parser.add_argument("--out", help="vart ska resultatet sparas? (annars bara print)")
    parser.add_argument("--key", required=True, help="nyckeln, typ 0xAA eller deadbeef eller mysecret")
    parser.add_argument("--format", choices=["raw", "python", "c"], default="c",
                        help="typ av output: c (vanligast), python eller raw")
    parser.add_argument("--var", default="buf", help="vad ska arrayen heta i C/python? (default buf)")

    args = parser.parse_args()

    # läs in shellcoden
    try:
        with open(args.input, "rb") as f:
            original = f.read()
        print(f"[+] Läste {len(original)} bytes från {args.input}")
    except Exception as e:
        print(f"[-] Hittade inte filen eller nåt sket sig: {args.input}")
        print(f"    Fel: {e}")
        sys.exit(1)

    # fixa nyckeln
    try:
        key_bytes = fixa_nyckel(args.key)
        print(f"[+] Nyckel: {key_bytes.hex()} ({len(key_bytes)} bytes)")
    except:
        print("[-] Nyckeln ser ok ut... typ 0xAA, AA, deadbeef")
        sys.exit(1)

    # kör xor 
    encrypted = xor_dra_på(original, key_bytes)
    print(f"[+] XOR klart! {len(encrypted)} bytes nu")

    # välj format och gör output
    if args.format == "c":
        content = gör_till_c_array(encrypted, args.var).encode()
        binary = False
        print("[+] Gjorde C-array, perfekt för loaders")
    elif args.format == "python":
        content = gör_till_python_array(encrypted, args.var).encode()
        binary = False
        print("[+] Gjorde python bytearray, nice")
    else:  # raw
        content = encrypted
        binary = True
        print("[+] Rå bytes, bara encryptad")

    # skriv eller printa
    if args.out:
        mode = "wb" if binary else "w"
        try:
            with open(args.out, mode) as f:
                f.write(content)
            print(f"[+] Sparade till: {args.out}")
        except Exception as e:
            print(f"[-] Kunde inte skriva till {args.out}: {e}")
            sys.exit(1)
    else:
        if binary:
            sys.stdout.buffer.write(content)
        else:
            print(content.decode(errors="ignore"))

    print("\nKlar!")


if __name__ == "__main__":
    main()
