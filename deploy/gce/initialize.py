#!/usr/bin/env python3
"""Generate isolated deployment secrets without writing them to logs."""
import argparse
import os
import pathlib
import secrets
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--redis-uid', type=int, required=True)
parser.add_argument('--redis-gid', type=int, required=True)
args = parser.parse_args()
if args.redis_uid <= 0 or args.redis_gid <= 0:
    sys.exit('The Redis daemon must use a non-root UID/GID.')
root = pathlib.Path('/opt/new-api-dev')
root.mkdir(mode=0o700, parents=True, exist_ok=True)
os.umask(0o077)
if (root / 'runtime.env').exists():
    sys.exit('Already initialized; refusing to rotate persisted secrets.')
(root / 'secrets').mkdir(mode=0o700, exist_ok=True)
pg_password = secrets.token_hex(32)
redis_password = secrets.token_hex(32)
(root / 'secrets/postgres_password').write_text(pg_password)
(root / 'secrets/redis.conf').write_text(
    'bind 0.0.0.0\nprotected-mode yes\nappendonly yes\n'
    f'requirepass {redis_password}\nmaxmemory 192mb\nmaxmemory-policy noeviction\n'
)
os.chown(root / 'secrets/redis.conf', args.redis_uid, args.redis_gid)
os.chmod(root / 'secrets/redis.conf', 0o400)
values = {
    'SQL_DSN': f'postgresql://newapi:{pg_password}@postgres:5432/newapi',
    'REDIS_CONN_STRING': f'redis://:{redis_password}@redis:6379/0',
    'SESSION_SECRET': secrets.token_hex(32),
    'CRYPTO_SECRET': secrets.token_hex(32),
    'SESSION_COOKIE_SECURE': 'false',
    'TRUSTED_PROXIES': 'none',
    'TZ': 'Asia/Taipei',
    'DEFAULT_LANGUAGE': 'zh-TW',
    'NODE_NAME': 'new-api-dev-20261022',
    'GENERATE_DEFAULT_TOKEN': 'false',
    'DEBUG': 'false',
    'ENABLE_PPROF': 'false',
    'SQL_MAX_OPEN_CONNS': '20',
    'SQL_MAX_IDLE_CONNS': '5',
    'GOMEMLIMIT': '1200MiB',
}
(root / 'runtime.env').write_text(''.join(f'{key}={value}\n' for key, value in values.items()))
for name in ('data', 'logs', 'backups'):
    (root / name).mkdir(mode=0o700, exist_ok=True)
print('Isolated runtime initialized; secrets remain in the protected deployment directory.')
