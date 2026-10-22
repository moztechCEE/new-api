#!/usr/bin/env python3
"""Claim only a fresh private instance; never print credentials or responses."""
import http.cookiejar
import json
import os
import pathlib
import secrets
import sys
import urllib.error
import urllib.request

os.umask(0o077)
root = pathlib.Path('/opt/new-api-dev')
credential_file = root / 'bootstrap-admin.json'
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(path, payload=None, method=None, token=None):
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request('http://127.0.0.1:3000' + path, body, headers, method=method)
    try:
        with opener.open(req, timeout=30) as response:
            result = json.load(response)
    except (urllib.error.URLError, ValueError):
        sys.exit('Management request failed; no response body or credential was logged.')
    if not result.get('success'):
        sys.exit('Management operation rejected; inspect the private setup UI.')
    return result.get('data')


setup = request('/api/setup')
if setup.get('status') or setup.get('root_init'):
    sys.exit('Existing setup/root detected; refusing to create or replace an administrator.')
if credential_file.exists():
    credential = json.loads(credential_file.read_text())
else:
    credential = {'username': 'infoadmin', 'password': secrets.token_urlsafe(32)}
    credential_file.write_text(json.dumps(credential))
request('/api/setup', {
    'username': credential['username'],
    'password': credential['password'],
    'confirmPassword': credential['password'],
    'SelfUseModeEnabled': True,
    'DemoSiteEnabled': False,
})
login = request('/api/user/login', credential)
if not login or not login.get('access_token'):
    sys.exit('Administrator created, but login requires additional verification. Use the private UI.')
token = login['access_token']
try:
    keys = ('RegisterEnabled', 'PasswordRegisterEnabled')
    for key in keys:
        request('/api/option/', {'key': key, 'value': 'false'}, method='PUT', token=token)
    options = {item['key']: str(item['value']).lower() for item in request('/api/option/', token=token)}
    if any(options.get(key) != 'false' for key in keys):
        sys.exit('Registration settings were not confirmed; keep the instance private.')
finally:
    request('/api/user/auth/logout', {}, method='POST', token=token)
setup = request('/api/setup')
if not setup.get('status'):
    sys.exit('Setup completion was not confirmed.')
print('Administrator infoadmin created; normal login verified; public registration disabled; bootstrap session logged out.')
print('Credential saved in protected bootstrap-admin.json; it was not printed.')
