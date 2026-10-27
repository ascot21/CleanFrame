"""Build and sign with the official Tizen SDK (macOS).

The SDK is .local/tizen-sdk (a symlink is fine). The signing profile is read from
"profile" in .local/device.json, defaulting to the reference machine's FrameHome.
If .local/certificates/private holds the reference setup's profile and password
file, that profile is used and the password is supplied to the SDK. Otherwise the
SDK's own Certificate Manager profile is used with its stored passwords.
"""
from pathlib import Path
import json
import os
import pty
import select
import signal
import subprocess
import time
import xml.etree.ElementTree as XML
import zipfile
from font_assets import write_widget_archive

ROOT = Path(__file__).resolve().parents[1]
# Resolve the link: the SDK's own tools fail on paths containing spaces.
SDK = (ROOT / '.local/tizen-sdk').resolve()
PRIVATE = ROOT / '.local/certificates/private'
CLI = SDK / 'tools/ide/bin/tizen'
if not CLI.exists():
    raise SystemExit('Local SDK missing. See docs/development.md.')
config_file = ROOT / '.local/device.json'
config = json.loads(config_file.read_text()) if config_file.exists() else {}
profile_name = config.get('profile', 'FrameHome')
password_file = PRIVATE / 'certificate-password.txt'
password = password_file.read_bytes().strip() if password_file.exists() else None
if password_file.exists() and not password:
    raise SystemExit('Signing password is empty.')
dist = ROOT / 'dist'
dist.mkdir(exist_ok=True)
if password:
    data = SDK / 'data'
    data.mkdir(exist_ok=True)
    (SDK / 'sdk.info').write_text('TIZEN_SDK_INSTALLED_PATH=' + str(SDK) + '\nTIZEN_SDK_DATA_PATH=' + str(data) + '\nJDK_PATH=' + str(SDK / 'jdk') + '\n')
    profile = PRIVATE / 'profiles.xml'
    tree = XML.parse(profile)
    for item in tree.getroot().iter('profileitem'):
        for key in ['key', 'ca', 'rootca']:
            value = item.get(key)
            if value:
                folder = PRIVATE if key == 'key' else PRIVATE.parent / 'ca'
                item.set(key, str(folder / Path(value).name))
    tree.write(profile, encoding='UTF-8', xml_declaration=True)
    profile.chmod(0o600)
    result = subprocess.run([str(CLI), 'cli-config', 'default.profiles.path=' + str(profile)], capture_output=True, timeout=30)
    if result.returncode:
        raise SystemExit('SDK signing profile configuration failed.')
else:
    info = dict(line.split('=', 1) for line in (SDK / 'sdk.info').read_text().splitlines() if '=' in line)
    profile = Path(info.get('TIZEN_SDK_DATA_PATH', '')) / 'profile/profiles.xml'
    if not profile.exists():
        raise SystemExit('No signing profile found. Create one with Certificate Manager.')
    names = [item.get('name') for item in XML.parse(profile).getroot().iter('profile')]
    if profile_name not in names:
        raise SystemExit('Signing profile ' + profile_name + ' not found. Set "profile" in .local/device.json.')
unsigned = dist / 'CleanFrame-unsigned.wgt'
write_widget_archive(unsigned)
signed_dir = dist / 'signed'
signed_dir.mkdir(exist_ok=True)
command = [str(CLI), 'package', '-t', 'wgt', '-s', profile_name, '-o', str(signed_dir), '--', str(unsigned)]
pid, terminal = pty.fork()
if pid == 0:
    os.execv(command[0], command)
output = b''
passwords = saves = 0
deadline = time.monotonic() + 60
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([terminal], [], [], 1)
        if ready:
            try:
                chunk = os.read(terminal, 8192)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            count = output.lower().count(b'password:')
            if count > passwords:
                if not password:
                    os.kill(pid, signal.SIGTERM)
                    raise SystemExit('The SDK asked for a certificate password. Save it in Certificate Manager.')
                os.write(terminal, password + b'\n')
                passwords = count
            count = output.count(b'No: (N) ?')
            if count > saves:
                os.write(terminal, b'n\n')
                saves = count
    else:
        os.kill(pid, signal.SIGTERM)
        raise SystemExit('SDK signing timed out.')
finally:
    os.close(terminal)
os.waitpid(pid, 0)
redacted = output.replace(password, b'[redacted]').decode(errors='replace') if password else output.decode(errors='replace')
if 'is created successfully' not in redacted:
    print(redacted)
    raise SystemExit('SDK did not confirm a signed package.')
signed = signed_dir / unsigned.name
with zipfile.ZipFile(signed) as package:
    if not {'author-signature.xml', 'signature1.xml'}.issubset(package.namelist()):
        raise SystemExit('Package is missing its signing files.')
target = dist / 'CleanFrame.wgt'
target.write_bytes(signed.read_bytes())
print('Signed widget created: ' + str(target))
