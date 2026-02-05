# Shellcode XOR Encryptor

Ett Python-verktyg som **XOR-obfuskerar** rå shellcode. Verktyget läser binär shellcode från en fil, utför XOR med en given nyckel och genererar utdata i olika format som är praktiska för användning i loaders.

**Viktigt:** Detta är **obfuskering** (inte stark kryptering). Syftet är att göra shellcoden svårare att upptäcka med enkla signaturbaserade verktyg (t.ex. antivirus eller EDR).

## Funktioner

- Läser rå binär shellcode från fil
- XOR-kryptering med valfri nyckel (loopar om nyckeln är kortare än shellcoden)
- Stöd för tre utdataformat:
  - **C** – klassisk `unsigned char` array + längdvariabel
  - **Python** – `bytearray` syntax
  - **Raw** – ren binär fil med krypterade bytes
- Enkel kommandoradsanvändning med `argparse`
- Automatisk skapande av testfil med `--test`

## Krav

- Python 3.x  
Inga externa bibliotek krävs

## Installation & användning

1. Placera `shellcrypt.py` i din projektmapp
2. Öppna terminalen (PowerShell eller VS Code terminal) i samma mapp

### Grundläggande kommando

```powershell
python shellcrypt.py --in raw.bin --key AA --format c --out payload.h

python shellcrypt.py --in raw.bin --key 0x42 --format c --out test_payload.h --test




Alla exempelkommandon
1. Generera C-array (standardformat)
PowerShellpython shellcrypt.py --in raw.bin --key AA --format c --out payload.h
2. Använd hex-nyckel med 0x-prefix
PowerShellpython shellcrypt.py --in raw.bin --key 0xAA --format c --out payload_aa.h --test
3. Python bytearray-format
PowerShellpython shellcrypt.py --in raw.bin --key deadbeef --format python --out loader.py
4. Spara som rå binär fil
PowerShellpython shellcrypt.py --in raw.bin --key beef --format raw --out encrypted.bin
5. Anpassat variabelnamn i C-koden
PowerShellpython shellcrypt.py --in raw.bin --key mysecret --format c --var shellcode_buf --out payload.h
6. Visa resultatet direkt i terminalen (utan att spara fil)
PowerShellpython shellcrypt.py --in raw.bin --key AA --format c
7. Test med längre nyckel (multi-byte)
PowerShellpython shellcrypt.py --in raw.bin --key mylongsecret123 --format c --out payload_longkey.h --t
