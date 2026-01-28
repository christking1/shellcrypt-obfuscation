
# Shellcode XOR Encryptor

Detta är ett Python-verktyg som XOR-obfuskerar shellcode. Verktyget läser rå shellcode från en fil, krypterar (obfuskerar) den med en XOR-nyckel och skapar utdata i olika format.

Verktyget används ofta i säkerhetsprojekt för att dölja shellcode så att det blir svårare för antivirus och EDR att upptäcka det direkt. Obfuskeringen görs bara med XOR – det är ingen stark kryptering.

## Vad verktyget gör

 Läser rå shellcode från en binär fil t.ex raw.bin
 XOR:ar varje byte med en given nyckel (nyckeln upprepas om den är kortare än shellcoden)
 Skapar utdata i ett av tre format:
 raw (krypterade bytes direkt till fil)
 python (bytearray i Python-syntax)
c (C-array med unsigned char och längd)

## Hur man kör verktyget

Använd följande kommandon (kör från samma mapp som filen shellcrypt.py):

```bash
# Skapa C-array (vanligast för loaders)
python shellcrypt.py --in raw.bin --key AA --format c --out payload.h

# Visa resultatet direkt i terminalen
python shellcrypt.py --in raw.bin --key deadbeef --format python

# Spara som rå binär fil
python shellcrypt.py --in raw.bin --key 0x42 --format raw --out encrypted.bin

# Använd eget variabelnamn
python shellcrypt.py --in raw.bin --key beef --var payload --format c --out out.h


# Create a tiny test file
echo "test" > raw.bin

# Run
python shellcrypt.py --input raw.bin --key AA --format c --output test_payload.h
