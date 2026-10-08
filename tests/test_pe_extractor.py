"""Synthetic byte-level fixture tests. No real malware or code execution."""

import struct
import unittest

from pe_extractor import MAX_PE_BYTES, PEFormatError, extract_pe_features
from model import FEATURES

ADDRESS = b"1BoatSLRHtKNngkdXEeobR76b53LETtpyT"  # publicly known test address


def make_pe(pe64=False, wallet=False, dll=False):
    image = bytearray(1024)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<HHIIIHH", image, coff, 0x8664 if pe64 else 0x14C, 3, 0, 0, 0,
                     240 if pe64 else 224, 0x2000 if dll else 0x0002)
    opt = coff + 20
    struct.pack_into("<H", image, opt, 0x20B if pe64 else 0x10B)
    struct.pack_into("<BB", image, opt + 2, 14, 31)
    struct.pack_into("<H", image, opt + 40, 6)
    struct.pack_into("<H", image, opt + 44, 2)
    struct.pack_into("<H", image, opt + 70, 0x8140)
    struct.pack_into("<Q" if pe64 else "<I", image, opt + 72, 2**33 if pe64 else 2**20)
    struct.pack_into("<I", image, opt + (108 if pe64 else 92), 16)
    dd = opt + (112 if pe64 else 96)
    for index, va, size in [(0, 0x5000, 333), (2, 0x6000, 777), (6, 0x7000, 88), (12, 0x8000, 90)]:
        struct.pack_into("<II", image, dd + index * 8, va, size)
    if wallet:
        image[800:800 + len(ADDRESS)] = ADDRESS
    return bytes(image)


class PEExtractorTest(unittest.TestCase):
    def test_pe32_fields_and_saved_model_schema(self):
        parsed = extract_pe_features(make_pe())
        self.assertEqual(set(parsed.features), set(FEATURES))
        self.assertEqual(parsed.features['Machine'], 332)
        self.assertEqual(parsed.features['IatVRA'], 0x8000)
        self.assertEqual(parsed.features['DebugRVA'], 0x7000)
        self.assertEqual(parsed.features['DebugSize'], 88)
        self.assertEqual(parsed.features['ExportRVA'], 0x5000)
        self.assertEqual(parsed.features['ExportSize'], 333)
        self.assertEqual(parsed.features['ResourceSize'], 777)
        self.assertEqual(parsed.features['SizeOfStackReserve'], 2**20)
        self.assertEqual(parsed.features['MajorOSVersion'], 6)
        self.assertEqual(parsed.features['MajorImageVersion'], 2)
        self.assertEqual(parsed.features['MajorLinkerVersion'], 14)
        self.assertEqual(parsed.features['MinorLinkerVersion'], 31)
        self.assertEqual(parsed.features['NumberOfSections'], 3)
        self.assertEqual(parsed.features['DllCharacteristics'], 0x8140)
        self.assertEqual(parsed.features['BitcoinAddresses'], 0)
        self.assertFalse(parsed.is_dll)

    def test_pe32plus_and_dll(self):
        parsed = extract_pe_features(make_pe(pe64=True, dll=True))
        self.assertEqual(parsed.pe_kind, 'PE32+ (64-bit)')
        self.assertEqual(parsed.features['Machine'], 34404)
        self.assertEqual(parsed.features['SizeOfStackReserve'], 2**33)
        self.assertTrue(parsed.is_dll)

    def test_bitcoin_address_ascii_and_utf16le(self):
        self.assertEqual(extract_pe_features(make_pe(wallet=True)).features['BitcoinAddresses'], 1)
        b = bytearray(make_pe())
        encoded = ADDRESS.decode().encode('utf-16le')
        b[800:800 + len(encoded)] = encoded
        self.assertEqual(extract_pe_features(bytes(b)).features['BitcoinAddresses'], 1)

    def test_invalid_files_and_size_cap(self):
        for payload in [b'', b'not an executable', b'MZ' + bytes(62), b'MZ' + bytes(MAX_PE_BYTES)]:
            with self.subTest(size=len(payload)):
                with self.assertRaises(PEFormatError):
                    extract_pe_features(payload)
        b = bytearray(make_pe())
        struct.pack_into('<I', b, 0x3C, 0x7FFFFFFF)
        with self.assertRaises(PEFormatError):
            extract_pe_features(bytes(b))
        b = bytearray(make_pe())
        struct.pack_into('<H', b, 0x98, 0x107)
        with self.assertRaises(PEFormatError):
            extract_pe_features(bytes(b))


if __name__ == '__main__':
    unittest.main()
