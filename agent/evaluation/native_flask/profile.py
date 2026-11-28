"""Portable fixed data and byte manifests; safe to import on host and in guest."""
import hashlib
import json
import os
from pathlib import Path
import stat

TASK='pallets__flask-4045'
BASE='d8c37f43724cd9fb0870f77877b7c4c7e38a19e0'
IMAGE='swebench/sweb.eval.x86_64.pallets_1776_flask-4045@sha256:431573fcf066022cec6e296bdb1105b5135283a3ebdf13b9ad1bd1859580a7c0'
SOURCE='36c6c15ddeacbde5fa9ceac60c343e59b8eda72965bc143b27b17956133def13'
BASELINE='badaa55c0f4f6a067db8f3427748ce2379cc2fad5367af9d7010b28c4872839a'
SPEC='092d5fc44b80f904bb8c3b62c8dd18db02bedb9a0f9ba0e75662269ea54cf78e'
TEST_PATCH='def1da53a3857f67b571f108abde6fcdac61da5c7820c0749fa7c487fe87a62a'
ARGV=['pytest','-rA','tests/test_basic.py','tests/test_blueprints.py']
POLICY={'editable_prefixes':['.'],'protected_paths':['.git','tests','build','dist',
    '.pytest_cache','__pycache__','src/flask.egg-info'],'max_entries':4096,
    'max_total_bytes':67108864,'max_changed_bytes':262144,'immutable_paths':[]}
PINS={'Werkzeug-2.0.3-py3-none-any.whl':(289232,
    '1421ebfc7648a39a5c58c601b154165d05cf47a3cd0ccb70857cbdacf6c8f2b8'),
    'setuptools-65.5.1-py3-none-any.whl':(1232712,
    'd0b9a8433464d5800cbe05094acf5c6d52a91bfac9b52bcfc4d41382be5d5d31')}


def sha(data):return hashlib.sha256(data).hexdigest()


def encoded(data):return json.dumps(data,sort_keys=True,separators=(',',':')).encode()


def hidden(name):
    parts=name.casefold().split('/');base=parts[-1]
    return (any(p in ('tests','.git','__pycache__','.pytest_cache','build','dist','.ssh','.aws','credentials')
        or p.endswith('.egg-info') for p in parts) or base in ('credentials.json','id_rsa','id_ed25519','.env')
        or base.startswith('.env.') or base.endswith(('.pyc','.pyo')))


def tree(root,*,model=False):
    """Bounded regular files, directories, portable snapshot and image-file digests."""
    root=Path(root);files={};directories=[];total=0;count=0;seen=set()
    for parent,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=sorted(d for d in dirs if d!='.git' and not (model and hidden((Path(parent)/d).relative_to(root).as_posix())))
        for name in dirs+sorted(names):
            path=Path(parent)/name;relative=path.relative_to(root).as_posix()
            if model and hidden(relative):continue
            count+=1
            if count>4096 or relative.casefold() in seen:raise ValueError('tree_entry_limit_or_alias')
            seen.add(relative.casefold());info=path.lstat()
            if stat.S_ISDIR(info.st_mode):directories.append(relative);continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise ValueError('tree_nonregular')
            total+=info.st_size
            if total>64*1024*1024:raise ValueError('tree_byte_limit')
            data=path.read_bytes()
            if len(data)!=info.st_size:raise ValueError('tree_changed')
            files[relative]=data
    if model:
        # Image export materializes file parents and deliberately omits empty image directories.
        directories=sorted({str(p) for n in files for p in Path(n).parents if str(p)!='.'})
        directories=[p.replace('\\','/') for p in directories]
    rows=[[name,sha(data),len(data)] for name,data in sorted(files.items())]
    manifest=json.dumps(rows+[(d,'directory') for d in sorted(directories)],separators=(',',':'),ensure_ascii=False).encode()
    image_rows=[[name,len(data),sha(data)] for name,data in sorted(files.items())]
    source=sha(json.dumps(image_rows,separators=(',',':')).encode())
    return files,tuple(sorted(directories)),sha(manifest),source
