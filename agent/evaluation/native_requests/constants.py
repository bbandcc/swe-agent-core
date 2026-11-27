"""Fixed research profile identities and bounded Docker CLI transport."""
import subprocess

IMAGE = ('swebench/sweb.eval.x86_64.psf_1776_requests-3362@sha256:'
         'd1c8c15eeb5e12b7eb3815307d1131d68c72d53419fa2f8b89bc46bc0009a61b')
BASE = '36453b95b13079296776d11b09cab2567ea3e703'
SOURCE = '2005cc0a544f4de6962df341319dad5e70e91eab8ac2495f18f13b451dd1cd4e'
LABEL = 'swe.fixed-tls.owner'
IMAGE_LABELS = {'org.opencontainers.image.version': '22.04'}
PYTHON = '/opt/miniconda3/envs/testbed/bin/python'

def command(*args, timeout=15):
    return subprocess.run(['docker',*args],stdin=subprocess.DEVNULL,
        capture_output=True,timeout=timeout,shell=False)
