"""Fetch immutable, checksum-verified Ghidra and public PE fixtures."""
import argparse
import hashlib
import json
import shutil
import time
import urllib.request
import zipfile
from pathlib import Path


def download(url, digest, target, limit):
    for attempt in range(3):
        try:
            total = 0
            checksum = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=60) as response, target.open('wb') as output:
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > limit:
                        raise ValueError('Download exceeds size limit')
                    checksum.update(chunk)
                    output.write(chunk)
            if checksum.hexdigest() != digest:
                raise ValueError(f'Checksum mismatch: {target.name}')
            return
        except (OSError, TimeoutError):
            target.unlink(missing_ok=True)
            if attempt == 2:
                raise
            time.sleep(2)


def extract_verified_archive(archive, destination):
    with zipfile.ZipFile(archive) as bundle:
        total = 0
        for info in bundle.infolist():
            path = (destination / info.filename).resolve()
            if not path.is_relative_to(destination.resolve()):
                raise ValueError('Archive path escapes destination')
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Archive contains a symlink')
            total += info.file_size
            if total > 3 * 1024**3:
                raise ValueError('Expanded archive exceeds size limit')
        bundle.extractall(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--sample', required=True)
    args = parser.parse_args()
    manifest = json.loads(Path(__file__).with_name('corpus.json').read_text())
    sample = manifest['samples'][args.sample]
    args.root.mkdir(parents=True, exist_ok=True)
    ghidra = manifest['ghidra']
    archive = args.root / 'ghidra.zip'
    download(ghidra['url'], ghidra['sha256'], archive, 2 * 1024**3)
    extract_verified_archive(archive, args.root)
    archive.unlink()
    source = args.root / 'sample.download'
    download(sample['source_url'], sample['source_sha256'], source, 128 * 1024**2)
    target = args.root / sample['name']
    if 'archive_member' in sample:
        with zipfile.ZipFile(source) as bundle, bundle.open(sample['archive_member']) as entry, target.open('wb') as output:
            info = bundle.getinfo(sample['archive_member'])
            if info.file_size != sample['size']:
                raise ValueError('Unexpected fixture size')
            shutil.copyfileobj(entry, output)
    else:
        source.replace(target)
    if target.stat().st_size != sample['size'] or hashlib.sha256(target.read_bytes()).hexdigest() != sample['sha256']:
        raise ValueError('Fixture checksum mismatch')
    source.unlink(missing_ok=True)
    print(f'Verified Ghidra 12.2 and {sample["name"]}', flush=True)


if __name__ == '__main__':
    main()
