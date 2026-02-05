# shellcrypt.py - shellcode XOR encryptor

import argparse
import sys
import os


def xor_dra_på(shellcode: bytes, nyckel: bytes) -> bytes:
    """XOR-krypterar shellcode med nyckel (nyckeln loopar vid behov)."""
    result = bytearray()
    for i in range(len(shellcode)):
        result.append(shellcode[i] ^ nyckel[i % len(nyckel)])
    return bytes(result)


def gör_till_c_array(bytes_grej: bytes, namn="buf") -> str:
    """Skapar en snygg C-style array-sträng."""
    if not bytes_grej:
        return f"unsigned char {namn}[] = {{ }};\nunsigned int {namn}_len = 0;"

    hex_bytes = []
    for i, b in enumerate(bytes_grej):
        if i % 12 == 0 and i > 0:
            hex_bytes.append("\n    ")
        hex_bytes.append(f"0x{b:02x}")
        if i < len(bytes_grej) - 1:
            hex_bytes.append(", ")

    content = f"unsigned char {namn}[] = {{\n    " + "".join(hex_bytes) + "\n}};\n"
    content += f"unsigned int {namn}_len = {len(bytes_grej)};"
    return content


def gör_till_python_array(bytes_grej: bytes, namn="buf") -> str:
    """Skapar en snygg Python bytearray-sträng."""
    if not bytes_grej:
        return f"{namn} = bytearray([])"

    hex_bytes = []
    for i, b in enumerate(bytes_grej):
        if i % 12 == 0 and i > 0:
            hex_bytes.append("\n    ")
        hex_bytes.append(f"0x{b:02x}")
        if i < len(bytes_grej) - 1:
            hex_bytes.append(", ")

    return f"{namn} = bytearray([\n    " + "".join(hex_bytes) + "\n])"


def fixa_nyckel(nyckel_str: str) -> bytes:
    """Konverterar nyckel från hex-sträng eller vanlig text till bytes."""
    nyckel_str = nyckel_str.lower().replace("0x", "").replace(" ", "").replace(",", "")
    try:
        return bytes.fromhex(nyckel_str)
    except ValueError:
        return nyckel_str.encode("utf-8")


def skapa_testfil(filnamn="raw.bin"):
    """Skapar en liten test-shellcode-fil om den inte finns."""
    test_bytes = bytes([
        0x90, 0x90, 0xCC,              # NOP NOP INT3
        0xFC, 0x48, 0x83, 0xE4, 0xF0,  # vanliga shellcode-start bytes
    ])
    with open(filnamn, "wb") as f:
        f.write(test_bytes)
    print(f"[*] Skapade testfil '{filnamn}' med {len(test_bytes)} bytes för felsökning")


def main():
    print("=== shellcrypt v1.2 - göm din shellcode ===\n")

    parser = argparse.ArgumentParser(description="XOR-obfuskerar shellcode och skapar C/Python/raw output.")
    
    parser.add_argument("--in", "--input", required=True, dest="input",
                        help="Inputfil med rå shellcode (binär fil, t.ex. raw.bin)")
    parser.add_argument("--out", 
                        help="Outputfil (annars skrivs resultatet ut i terminalen)")
    parser.add_argument("--key", required=True, 
                        help="XOR-nyckel, t.ex. AA, 0xAA, deadbeef, mysecret")
    parser.add_argument("--format", choices=["raw", "python", "c"], default="c",
                        help="Outputformat: c (standard), python eller raw")
    parser.add_argument("--var", default="buf",
                        help="Namn på arrayen i C eller Python (standard: buf)")
    parser.add_argument("--test", action="store_true",
                        help="Skapar automatiskt en liten testfil 'raw.bin' om den inte finns")

    args = parser.parse_args()

    # Skapa testfil om --test är satt och filen saknas
    if args.test and not os.path.exists(args.input):
        skapa_testfil(args.input)

    # Läs shellcode
    try:
        with open(args.input, "rb") as f:
            original = f.read()
        
        if not original:
            print(f"[-] FEL: Filen '{args.input}' är tom (0 bytes).")
            print("    Tips för Windows:")
            print("    1. Kör scriptet med --test för att skapa en liten testfil automatiskt")
            print("    2. Eller skapa manuellt i Python:")
            print("       with open('raw.bin', 'wb') as f: f.write(bytes([0x90, 0x90, 0xCC]))")
            print("    3. Eller i PowerShell:")
            print("       [byte[]]$b = 0x90,0x90,0xCC; [IO.File]::WriteAllBytes('raw.bin',$b)")
            sys.exit(1)
        
        print(f"[+] Läste {len(original)} bytes från {args.input}")
    except FileNotFoundError:
        print(f"[-] FEL: Filen '{args.input}' hittades inte.")
        print("    Tips: Kör med --test för att skapa en testfil automatiskt")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Kunde inte läsa filen '{args.input}': {e}")
        sys.exit(1)

    # Fixa nyckel
    try:
        key_bytes = fixa_nyckel(args.key)
        if not key_bytes:
            print("[-] FEL: Nyckeln blev tom.")
            sys.exit(1)
        print(f"[+] Nyckel: {key_bytes.hex()} ({len(key_bytes)} bytes)")
    except Exception as e:
        print(f"[-] Kunde inte tolka nyckeln '{args.key}': {e}")
        sys.exit(1)

    # XOR:a
    encrypted = xor_dra_på(original, key_bytes)
    print(f"[+] XOR klar – {len(encrypted)} bytes")

    # Skapa innehåll
    if args.format == "c":
        content = gör_till_c_array(encrypted, args.var)
        binary = False
        print("[+] Skapade C-array")
    elif args.format == "python":
        content = gör_till_python_array(encrypted, args.var)
        binary = False
        print("[+] Skapade Python bytearray")
    else:  # raw
        content = encrypted
        binary = True
        print("[+] Skapade rå binär output")

    # Spara eller skriv ut
    if args.out:
        mode = "wb" if binary else "w"
        try:
            with open(args.out, mode) as f:
                if binary:
                    f.write(content)
                else:
                    f.write(content)
            print(f"[+] Sparad till: {args.out}")
        except Exception as e:
            print(f"[-] Kunde inte skriva till '{args.out}': {e}")
            sys.exit(1)
    else:
        print("\nResultat:\n")
        if binary:
            # För raw – visa hex istället för att dumpa binärt till terminal
            print(" ".join(f"{b:02x}" for b in content))
        else:
            print(content)

    print("\nKlar!")


if __name__ == "__main__":
    main()
