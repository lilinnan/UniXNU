#!/usr/bin/env python3
"""Generate an owner key and the signed OS/SystemOS block-hash policies (build/verified-root-{os,systemos}).

Replaces the maintainer-local steps that are not in the repositories (owner key generation and the host C verifier of
scripts/build-owner-os-policy.py). Input: the unchanged OS and SystemOS disk images of the IPSW, as `unixnu ipsw fetch`
stores them. The OS policy covers the attached whole virtual disk (the bytes the userdata image holds), the SystemOS policy
the raw image file. Signatures are checked with openssl. Run from the build tree on macOS (hdiutil, diskutil, openssl).
"""
import hashlib
import json
from pathlib import Path
import plistlib
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'kits/VerifiedRoot/tools'))
import manifest  # noqa: E402

OS_UUID = '04769D26-2CA0-4825-B443-E2E5F88300F2'
VOLUMES = {
    'os': dict(dmg='044-76040-038.dmg', sha256='e5634d04a8ac35f024845f583394e0a35deb26a04cb0c00286a8674e25a9a4f2',
               blocks=1483785, bytes=6077580800, uuid=OS_UUID, whole_disk=True),
    'systemos': dict(dmg='044-76034-038.dmg', sha256='b4908cde41d23e6bc05e6af51a2c9eeb00cf0f863a6a18b1600c96a3fd70414f',
                     blocks=806400, bytes=3303014400, uuid=None, whole_disk=False),
}


def find_dmg(name):
    found = sorted((ROOT.parents[1] / 'ipsw').glob('*/' + name)) + sorted((ROOT / '.cache/firmware/target-volumes').glob(name))
    if not found:
        raise SystemExit(f'{name} not found: run ./unixnu ipsw fetch OS Cryptex1,SystemOS first')
    return found[0]


def keys():
    out = ROOT / 'build/verified-root-host/keys'
    out.mkdir(parents=True, exist_ok=True)
    private, public = out / 'owner.pem', out / 'owner-public.pem'
    if not private.is_file():
        subprocess.run(['openssl', 'genrsa', '-out', str(private), '3072'], check=True, capture_output=True)
        private.chmod(0o600)
    subprocess.run(['openssl', 'rsa', '-in', str(private), '-pubout', '-out', str(public)], check=True, capture_output=True)
    return private, public


def attach(dmg):
    out = subprocess.run(['hdiutil', 'attach', '-nomount', '-readonly', '-noverify', '-noautofsck', '-plist', str(dmg)],
                         capture_output=True, check=True).stdout
    devices = [e['dev-entry'] for e in plistlib.loads(out)['system-entities']]
    whole = min(devices, key=len)
    name = Path(whole).name
    # APFS volume UUIDs of the containers whose physical store is on this attached disk.
    uuids = []
    listing = plistlib.loads(subprocess.check_output(['diskutil', 'apfs', 'list', '-plist']))
    for container in listing.get('Containers', []):
        stores = [s.get('DeviceIdentifier', '') for s in container.get('PhysicalStores', [])]
        if any(store == name or store.startswith(name + 's') for store in stores):
            uuids += [v['APFSVolumeUUID'].upper() for v in container.get('Volumes', [])]
    total = plistlib.loads(subprocess.check_output(['diskutil', 'info', '-plist', whole]))['TotalSize']
    print(f'{dmg.name}: {whole}, {total} bytes, APFS volumes {uuids}')
    return whole, uuids, total


def build(component, private, public):
    spec = VOLUMES[component]
    dmg = find_dmg(spec['dmg'])
    whole, uuids, total = attach(dmg)
    try:
        if component == 'os':
            if spec['uuid'] not in uuids:
                raise SystemExit(f'OS volume UUID {spec["uuid"]} not found in {uuids}')
            volume_uuid = spec['uuid']
        else:
            if len(uuids) != 1:
                raise SystemExit(f'Expected one SystemOS volume UUID, found {uuids}')
            volume_uuid = uuids[0]
        source = Path('/dev/r' + Path(whole).name) if spec['whole_disk'] else dmg
        size = total if spec['whole_disk'] else dmg.stat().st_size
        if size != spec['bytes']:
            raise SystemExit(f'{component}: image is {size} bytes, expected {spec["bytes"]}')
        out = ROOT / ('build/verified-root-' + component)
        with source.open('rb', buffering=1024 * 1024) as stream:
            record = manifest.make(stream, size, private, public, volume_uuid, 1, out)
    finally:
        subprocess.run(['hdiutil', 'detach', whole], capture_output=True)
    if record['image_sha256'] != spec['sha256'] or record['block_count'] != spec['blocks']:
        raise SystemExit(f'{component}: image digest {record["image_sha256"]} / {record["block_count"]} blocks differ from the pin')
    count = record['block_count']
    indices = [0, 1, count // 2, count - 1]
    samples, lengths = [], []
    with source.open('rb', buffering=1024 * 1024) as stream:
        for index in indices:
            stream.seek(index * 4096)
            block = stream.read(min(4096, size - index * 4096))
            samples.append(block.ljust(4096, b'\0'))
            lengths.append(len(block))
    if component == 'os' and lengths != [4096, 4096, 4096, 1536]:
        raise SystemExit(f'Unexpected OS sample lengths {lengths}')
    (out / 'original-samples.bin').write_bytes(b''.join(samples))
    report = dict(image_bytes=size, blocks_verified=count, image_sha256=record['image_sha256'], volume_uuid=volume_uuid,
                  generation=1, trusted_key_sha256=record['trusted_key_sha256'], actual_sample_indices=indices,
                  actual_sample_lengths=lengths, real_c_signature_and_block_verification=True,
                  verification_note='signature checked by openssl and every block hashed by kits/VerifiedRoot/tools/manifest.py; '
                                    'the maintainer host C verifier is not in the repositories',
                  original_image_modified=False, host_only=True, boot_root_authenticated=False, hardware_tested=False)
    (out / 'verification.json').write_text(json.dumps(report, indent=2) + '\n')
    print(f'PASS: {component} volume {volume_uuid}: {count} blocks signed, image sha256 {record["image_sha256"]}')


if __name__ == '__main__':
    private, public = keys()
    for component in ('os', 'systemos'):
        build(component, private, public)
    if (ROOT / 'build/verified-root-os/trusted-key.bin').read_bytes() != (ROOT / 'build/verified-root-systemos/trusted-key.bin').read_bytes():
        raise SystemExit('Both policies must share one owner anchor')
