"""Individually encrypted GitHub update grants; never contains publisher secrets."""
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import zipfile

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

REPO = 'wenjiany312-hub/starsky-amazon-codex-releases'
BRANCH = 'codex/member-updates'
DOMAIN = b'starsky-member-updates-v1'


class GrantError(ValueError):
    pass


class NoGrant(GrantError):
    pass


def enc(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def dec(value):
    return base64.b64decode(value + '=' * (-len(value) % 4), altchars=b'-_', validate=True)


def recipient_id(anchor):
    return hashlib.sha256(DOMAIN + b'/recipient/' + anchor.strip().encode()).hexdigest()


def claims(code, public, device=None, today=None, allow_expired=False):
    from starsky_installer import verify_license
    try:
        raw = json.loads(dec(code.strip().split('.')[1]))
        return verify_license(code, public, device or raw['device'], today=today, allow_expired=allow_expired)
    except Exception as exc:
        raise GrantError('授权签名、机器或期限校验失败。') from exc


def binding(meta):
    from starsky_installer import version_order
    try:
        version_order(meta['version'])
        from starsky_installer import PRODUCT
        return {'product': PRODUCT, 'version': meta['version'],
                'key_id': meta['encryption']['key_id'], 'payload_sha256': meta['files']['payload.enc']}
    except Exception as exc:
        raise GrantError('更新包绑定信息缺失。') from exc


def aad(anchor, meta):
    return json.dumps(dict(binding(meta), recipient=recipient_id(anchor)), sort_keys=True, separators=(',', ':')).encode()


def derive(anchor, salt):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=DOMAIN).derive(anchor.strip().encode())


def seal_grant(anchor, grant_code, public, meta, today=None):
    old = claims(anchor, public, today=today, allow_expired=True)
    new = claims(grant_code, public, old['device'], today=today)
    if new['id'] != old['id'] or new.get('release') != meta['version'] or meta['encryption']['key_id'] not in new.get('content_keys', {}):
        raise GrantError('会员更新许可与原激活或目标发行不一致。')
    salt, nonce = os.urandom(16), os.urandom(12)
    plaintext = json.dumps({'schema': 1, 'binding': binding(meta), 'code': grant_code}, separators=(',', ':')).encode()
    encrypted = AESGCM(derive(anchor, salt)).encrypt(nonce, plaintext, aad(anchor, meta))
    return json.dumps({'schema': 1, 'salt': enc(salt), 'nonce': enc(nonce), 'ciphertext': enc(encrypted)}, separators=(',', ':')).encode()


def open_grant(anchor, sealed, public, meta, device, today=None):
    try:
        old = claims(anchor, public, device, today=today, allow_expired=True)
        envelope = json.loads(sealed)
        if envelope['schema'] != 1:
            raise GrantError('不支持的更新凭证格式。')
        salt, nonce = dec(envelope['salt']), dec(envelope['nonce'])
        if len(salt) != 16 or len(nonce) != 12 or len(sealed) > 100_000:
            raise GrantError('更新凭证布局不正确。')
        raw = AESGCM(derive(anchor, salt)).decrypt(nonce, dec(envelope['ciphertext']), aad(anchor, meta))
        grant = json.loads(raw)
        if grant['schema'] != 1 or grant['binding'] != binding(meta):
            raise GrantError('更新凭证绑定错误。')
        new = claims(grant['code'], public, device, today=today)
        if new['id'] != old['id'] or new.get('release') != meta['version'] or meta['encryption']['key_id'] not in new.get('content_keys', {}):
            raise GrantError('更新授权不匹配。')
        return grant['code']
    except GrantError:
        raise
    except Exception as exc:
        raise GrantError('更新凭证解密或完整性校验失败。') from exc


def feed_manifest(meta, archive):
    return {'schema': 1, **binding(meta), 'file': 'grants.zip',
            'sha256': hashlib.sha256(archive).hexdigest(), 'bytes': len(archive),
            'generated_at': datetime.now(timezone.utc).isoformat()}


def fetch_grant(anchor, bundle, meta, device, download, today=None):
    from starsky_installer import verify_signature
    target = binding(meta)
    import starsky_installer as host
    root = f'https://raw.githubusercontent.com/{host.REPO}/refs/heads/{host.MEMBER_BRANCH}/v1/{target["version"]}/'
    public = (Path(bundle) / 'license_public.pem').read_bytes()
    claims(anchor, public, device, today=today, allow_expired=True)
    try:
        raw = download(root + 'index.json', 100_000, timeout=20)
        signature = download(root + 'index.sig', 20_000, timeout=20)
        verify_signature(raw, base64.b64decode(signature.strip(), validate=True), public)
        index = json.loads(raw)
        if index.get('schema') != 1 or any(index.get(k) != v for k, v in target.items()) or index.get('file') != 'grants.zip':
            raise GrantError('会员更新清单与当前安装包不一致。')
        archive = download(root + 'grants.zip', 50_000_000, timeout=45)
        if len(archive) != index['bytes'] or hashlib.sha256(archive).hexdigest() != index['sha256']:
            raise GrantError('会员更新凭证文件摘要不符。')
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            entries = z.infolist()
            if len(entries) > 10000 or sum(i.file_size for i in entries) > 50_000_000:
                raise GrantError('会员凭证文件超出限制。')
            if len({i.filename for i in entries}) != len(entries) or any(not re.fullmatch(r'[0-9a-f]{64}\.json', i.filename) or i.file_size > 100_000 for i in entries):
                raise GrantError('会员凭证目录含重复或不安全条目。')
            name = recipient_id(anchor) + '.json'
            if name not in z.namelist():
                raise NoGrant('本次发行暂无本激活码的更新许可，请核对会员登记、期限或等待作者同步凭证。')
            return open_grant(anchor, z.read(name), public, meta, device, today=today)
    except GrantError:
        raise
    except Exception as exc:
        raise GrantError('会员更新服务暂不可用或凭证校验失败；旧版保留，不代表会员已过期。') from exc
