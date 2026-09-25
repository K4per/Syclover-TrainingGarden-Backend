"""Run container checks with SYCL_TEST_DOCKER=1 pytest tests/test_hotfix009.py."""
import os
import subprocess
from dataclasses import replace
from zipfile import ZipFile

import pytest
from starlette.requests import Request

from app.api.routes.instances import _effective_public_host
from app.services.docker import ContainerError, DockerService


@pytest.mark.parametrize('bind', ['0.0.0.0', '::', '[::]'])
@pytest.mark.parametrize('public_host', ['', 'localhost', 'LOCALHOST', '127.0.0.1', '::1', '[::1]', 'challenge.sycsec.com'])
def test_wildcard_public_host(settings, bind, public_host):
    request = Request({'type': 'http', 'headers': [(b'host', b'traininggarden.sycsec.com')]})
    configured = replace(settings, instance_bind_address=bind, instance_public_host=public_host)
    expected = public_host if public_host == 'challenge.sycsec.com' else 'traininggarden.sycsec.com'
    assert _effective_public_host(request, configured) == expected


@pytest.mark.skipif(os.getenv('SYCL_TEST_DOCKER') != '1', reason='requires local Docker and alpine:latest')
@pytest.mark.parametrize('user', ['0:0', '10001:10001'])
@pytest.mark.parametrize('fails', [False, True])
def test_patch_as_container_user(tmp_path, user, fails):
    def docker(*args):
        return subprocess.check_output(['docker', *args], text=True).strip()

    container = docker('run', '-d', '--rm', '--network', 'none', '--user', user,
                       'alpine:latest', 'sleep', '120')
    try:
        docker('exec', '--user', '0', container, 'mkdir', '-p', '/app')
        docker('exec', '--user', '0', container, 'chown', user, '/app')
        archive = tmp_path / 'patch.zip'
        with ZipFile(archive, 'w') as bundle:
            bundle.writestr('fix.sh', 'set -eu\nid -u > /app/applied-user\n' + ('exit 1\n' if fails else 'echo patched\n'))
            bundle.writestr('service.txt', 'fixed')
        service = DockerService('docker')
        if fails:
            with pytest.raises(ContainerError):
                service.apply_asset(container, archive, 'patch', category='Web')
        else:
            assert service.apply_asset(container, archive, 'patch', category='Web') == 'patched'
        assert docker('exec', container, 'cat', '/app/applied-user') == user.split(':')[0]
        assert docker('exec', container, 'cat', '/app/service.txt') == 'fixed'
        assert docker('exec', container, 'sh', '-c', 'find /tmp -name "syclover-patch-*"') == ''
    finally:
        docker('rm', '-f', container)
