#!/usr/bin/env python3
"""Consistent PostgreSQL dump plus runtime configuration to a private bucket."""
import datetime
import fcntl
import hashlib
import http.client
import json
import os
import pathlib
import shutil
import subprocess
import tarfile
import urllib.parse
import urllib.request

os.umask(0o077)
root = pathlib.Path('/opt/new-api-dev')
lock = (root / 'backups/backup.lock').open('a')
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
if shutil.disk_usage(root).free < 1024 ** 3:
    raise RuntimeError('Insufficient free disk space for a backup')
stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
dump = root / 'backups' / f'{stamp}.sql'
archive = root / 'backups' / f'{stamp}.tar.gz'
try:
    with dump.open('xb') as stream:
        subprocess.run(['docker', 'compose', 'exec', '-T', 'postgres', 'pg_dump', '-U', 'newapi', '-d', 'newapi', '--no-owner', '--no-acl'], cwd=root, stdout=stream, check=True, timeout=600)
    with tarfile.open(archive, 'x:gz') as backup:
        backup.add(dump, arcname='database.sql')
        for name in ('compose.yaml', '.env', 'runtime.env', 'Caddyfile', 'secrets', 'data'):
            backup.add(root / name, arcname=name)
    metadata = urllib.request.Request('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', headers={'Metadata-Flavor': 'Google'})
    with urllib.request.urlopen(metadata, timeout=15) as response:
        token = json.load(response)['access_token']
    bucket = 'moztech-new-api-dev-backups-249593319772'
    name = 'daily/' + archive.name
    path = f'/upload/storage/v1/b/{bucket}/o?uploadType=media&ifGenerationMatch=0&name={urllib.parse.quote(name, safe="")}'
    # http.client streams the file; the archive never needs to fit in RAM.
    connection = http.client.HTTPSConnection('storage.googleapis.com', timeout=180)
    try:
        with archive.open('rb') as stream:
            connection.request('POST', path, body=stream, headers={
                'Authorization': 'Bearer ' + token,
                'Content-Type': 'application/gzip',
                'Content-Length': str(archive.stat().st_size),
            })
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError(f'Backup upload rejected (HTTP {response.status})')
            stored = json.load(response)
    finally:
        connection.close()
    if int(stored['size']) != archive.stat().st_size:
        raise RuntimeError('Backup size verification failed')
    with archive.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    print('Backup uploaded and size verified: ' + name + ' sha256=' + digest)
finally:
    dump.unlink(missing_ok=True)
    for old in sorted((root / 'backups').glob('*.tar.gz'))[:-3]:
        old.unlink()
