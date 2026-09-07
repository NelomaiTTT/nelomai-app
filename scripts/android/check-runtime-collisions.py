#!/usr/bin/env python3
"""Inspect actual AAR/JAR/DEX/ELF payloads before combining runtime slots.

Common Android libraries belong to the container and must be excluded from both
runtime payloads. An allowlist must never conceal intersecting versioned code.
"""
from __future__ import annotations

import argparse
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import tempfile
import unicodedata
import xml.etree.ElementTree as ET
import zipfile

MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
CATEGORIES = ('classes', 'resources', 'components', 'jni_exports', 'sonames', 'native_libraries')
ANDROID = '{http://schemas.android.com/apk/res/android}'


def safe_path(value):
    path = PurePosixPath(value)
    if (not value or '\\' in value or ':' in value or '\x00' in value
            or path.is_absolute() or any(part in ('', '.', '..') for part in value.split('/'))
            or unicodedata.normalize('NFC', value) != value):
        raise ValueError('noncanonical archive path')
    return path


def archive_entries(data):
    seen, total = set(), 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for item in archive.infolist():
            name = item.filename.rstrip('/') if item.is_dir() else item.filename
            safe_path(name)
            folded = name.casefold()
            if folded in seen:
                raise ValueError('duplicate archive path')
            seen.add(folded)
            if stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError('symlink archive path')
            if item.flag_bits & 1:
                raise ValueError('encrypted runtime archive')
            total += item.file_size
            if item.file_size > MAX_FILE or total > MAX_TOTAL:
                raise ValueError('runtime archive exceeds size limit')
            if not item.is_dir():
                yield name, archive.read(item)


def class_name(data):
    """Read this_class from bytecode; archive filenames are not evidence."""
    if data[:4] != b'\xca\xfe\xba\xbe':
        raise ValueError('invalid class bytecode')
    count = struct.unpack_from('>H', data, 8)[0]
    pool, offset, index = {}, 10, 1
    sizes = {3: 4, 4: 4, 5: 8, 6: 8, 8: 2, 9: 4, 10: 4, 11: 4,
             12: 4, 15: 3, 16: 2, 17: 4, 18: 4, 19: 2, 20: 2}
    while index < count:
        tag = data[offset]
        offset += 1
        if tag == 1:
            length = struct.unpack_from('>H', data, offset)[0]
            offset += 2
            # Non-name strings use JVM modified UTF-8; only this_class is decoded.
            pool[index] = data[offset:offset + length]
            offset += length
        elif tag == 7:
            pool[index] = struct.unpack_from('>H', data, offset)[0]
            offset += 2
        elif tag in sizes:
            offset += sizes[tag]
            if tag in (5, 6):
                index += 1
        else:
            raise ValueError('unknown class constant')
        index += 1
    this_class = struct.unpack_from('>H', data, offset + 2)[0]
    return pool[pool[this_class]].decode('utf-8').replace('/', '.')


def dex_classes(data):
    if data[:4] != b'dex\n' or len(data) < 112 or struct.unpack_from('<I', data, 40)[0] != 0x12345678:
        raise ValueError('invalid DEX header')
    if struct.unpack_from('<I', data, 32)[0] != len(data):
        raise ValueError('invalid DEX size')
    string_count, strings = struct.unpack_from('<II', data, 56)
    type_count, types = struct.unpack_from('<II', data, 64)
    class_count, classes = struct.unpack_from('<II', data, 96)
    for index in range(class_count):
        type_index = struct.unpack_from('<I', data, classes + 32 * index)[0]
        if type_index >= type_count:
            raise ValueError('invalid DEX type')
        string_index = struct.unpack_from('<I', data, types + 4 * type_index)[0]
        if string_index >= string_count:
            raise ValueError('invalid DEX string')
        offset = struct.unpack_from('<I', data, strings + 4 * string_index)[0]
        for _ in range(5):
            byte = data[offset]
            offset += 1
            if not byte & 128:
                break
        else:
            raise ValueError('invalid DEX string length')
        end = data.index(0, offset)
        descriptor = data[offset:end].decode('utf-8')
        if not descriptor.startswith('L') or not descriptor.endswith(';'):
            raise ValueError('invalid DEX class descriptor')
        yield descriptor[1:-1].replace('/', '.')


def inspect_archive(data, *, readelf, depth=0):
    if depth > 4:
        raise ValueError('runtime archive nesting limit exceeded')
    result = {category: set() for category in CATEGORIES}
    for name, content in archive_entries(data):
        path = safe_path(name)
        suffix = path.suffix.lower()
        if suffix == '.apk':
            raise ValueError('nested APK is not a runtime artifact')
        if suffix in ('.aar', '.jar', '.zip'):
            nested = inspect_archive(content, readelf=readelf, depth=depth + 1)
            for category in CATEGORIES:
                overlap = result[category] & nested[category]
                # AAR and its compiled DEX may represent the same source. The
                # release payload chooses one representation, never both.
                if overlap and category == 'classes':
                    raise ValueError('duplicate class inside runtime payload')
                result[category].update(nested[category])
        elif suffix == '.class':
            value = class_name(content)
            if name != value.replace('.', '/') + '.class':
                raise ValueError('class bytecode identity differs from archive path')
            result['classes'].add(value)
        elif suffix == '.dex':
            for value in dex_classes(content):
                if value in result['classes']:
                    raise ValueError('duplicate class inside runtime payload')
                result['classes'].add(value)
        elif path.name == 'R.txt':
            for line in content.decode('utf-8').splitlines():
                fields = line.split()
                if len(fields) < 4 or fields[0] not in ('int', 'int[]'):
                    raise ValueError('invalid Android resource symbol table')
                result['resources'].add(fields[1] + '/' + fields[2])
        elif path.name == 'AndroidManifest.xml':
            root = ET.fromstring(content)
            package = root.get('package', '')
            for element in root.iter():
                if element.tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
                    value = element.get(ANDROID + 'name')
                    if not value:
                        raise ValueError('manifest component has no class name')
                    if value.startswith('.'):
                        value = package + value
                    elif '.' not in value:
                        value = package + '.' + value
                    result['components'].add(value)
                    if element.tag == 'provider':
                        for authority in element.get(ANDROID + 'authorities', '').split(';'):
                            if authority:
                                result['components'].add('authority:' + authority)
        elif suffix == '.so':
            if content[:4] != b'\x7fELF':
                raise ValueError('native runtime library is not ELF')
            abi = path.parent.name
            if abi not in ('arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'):
                raise ValueError('native library lacks Android ABI directory')
            result['native_libraries'].add(abi + '/' + path.name)
            with tempfile.TemporaryDirectory(prefix='nelomai-elf-') as temporary:
                binary = Path(temporary) / 'engine.so'
                binary.write_bytes(content)
                output = subprocess.run([str(readelf), '--dynamic', '--dyn-syms', '--wide', str(binary)], check=True, capture_output=True, text=True).stdout
            sonames = re.findall(r'\(SONAME\).*\[([^]]+)\]', output)
            if len(sonames) != 1:
                raise ValueError('native library must declare one ELF SONAME')
            result['sonames'].add(abi + '/' + sonames[0])
            for line in output.splitlines():
                fields = line.split()
                if len(fields) >= 8 and fields[4] in ('GLOBAL', 'WEAK') and fields[6] != 'UND':
                    symbol = fields[7].split('@')[0]
                    if symbol.startswith('Java_') or symbol in ('JNI_OnLoad', 'JNI_OnUnload'):
                        result['jni_exports'].add(symbol)
    return result


def collisions(latest, stable):
    return {name: sorted(latest[name] & stable[name]) for name in CATEGORIES if latest[name] & stable[name]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--latest', type=Path, required=True)
    parser.add_argument('--stable', type=Path, required=True)
    parser.add_argument('--readelf', type=Path, required=True)
    args = parser.parse_args()
    found = collisions(inspect_archive(args.latest.read_bytes(), readelf=args.readelf), inspect_archive(args.stable.read_bytes(), readelf=args.readelf))
    print(json.dumps(found, sort_keys=True, indent=2))
    raise SystemExit(1 if found else 0)


if __name__ == '__main__':
    main()
