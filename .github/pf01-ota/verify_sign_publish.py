#!/usr/bin/env python3
"""Fail-closed, user-confirmed OTA QA 16.0.3 signing from PRIVATE unsigned Action artifact.

This script is only for exactly pinned v13 .alpha.r2 / 16.0.3.
No private source is checked out in this PUBLIC repo; source code cannot be published here.
No existing manifest, zip, Canon, Source, Registry, Owner, M4 or Play status is modified.
"""
from __future__ import annotations
import argparse,base64,hashlib,json,os,re,sys,urllib.error,urllib.request,zipfile
from pathlib import Path
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding

VERSION='16.0.3'
PRIVATE_REPO='parksu9308/TaiRmasterPG'
PUBLIC_REPO='parksu9308/pf01-ota-qa'
APPID='app.tairmasterpg.pf01.qa.alpha.r2'
COMPAT='PF01_R16_CAPACITOR8_CAPGO8_SQLITE8_QA_R2_V1'
SCHEMA='PF01_R16_OTA_MANIFEST_V1'
PUBLIC_PIN_SHA='758bbe19e65688355491e0329ee23eea6d6fb8f64623d42b1ef1a4d6edf2b6c4'
BASE_SHA='11814c5f09b88fd099e530313f05a470da9f7f0639638fa14fd5dd359c4dfd32'
CAND_SHA='b05a643b623d66ce3c50c27fd382fe1b119297d6e1777516c4eef51854564914'
APK_SHA='092d5de6d93d7651d77e0466bfca8cd6bd582f3ed65718a0fa527a1e8634eb5e'
BUNDLE_URL='https://parksu9308.github.io/pf01-ota-qa/qa/16.0.3.zip'
MANIFEST_URL='https://parksu9308.github.io/pf01-ota-qa/qa/manifest-16.0.3.json'
ORDER=['schema','appId','nativeCompat','minNativeCode','version','bundleUrl','bundleSha256','publisher']
CHANGED={'src/pf01/main.ts','src/pf01/native-alpha.ts','src/pf01/m6-preissuer-native-review.ts','tests/m6-r2-preissuer-native-readonly.test.mjs'}


def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def assert_true(x:bool,code:str)->None:
    if not x:raise ValueError(code)
def hex64(s:str)->bool:return bool(re.fullmatch(r'[0-9a-f]{64}',s))
def load_json(p:Path)->dict:
    assert_true(p.is_file() and not p.is_symlink(),'HOLD_MISSING_PUBLIC_REVIEW_FILE:'+p.name)
    return json.loads(p.read_text(encoding='utf-8'))
def compact_body(body:dict)->bytes:
    return json.dumps({k:body[k] for k in ORDER},ensure_ascii=False,separators=(',',':')).encode('utf-8')

def request_api(url:str,token:str,*,method='GET',data:dict|None=None,expect:int=200):
    assert_true(url.startswith('https://api.github.com/'),'HOLD_UNAPPROVED_GITHUB_API_HOST')
    payload=None if data is None else json.dumps(data,separators=(',',':')).encode('utf-8')
    req=urllib.request.Request(url,data=payload,method=method,headers={
        'Accept':'application/vnd.github+json','Authorization':f'Bearer {token}',
        'X-GitHub-Api-Version':'2022-11-28',
        **({'Content-Type':'application/json'} if data is not None else {})})
    try:
        with urllib.request.urlopen(req,timeout=30) as r:
            assert_true(r.status==expect,'HOLD_UNEXPECTED_GITHUB_HTTP_STATUS')
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code==404 and expect==404:return None
        raise ValueError(f'HOLD_GITHUB_API_HTTP_{e.code} (no secret printed)') from None

def verify_release(artifact_dir:Path,run_id:int,approve_bundle:str,approve_source:str,repo_api:bool=True)->tuple[dict,dict,bytes]:
    assert_true(run_id>0 and hex64(approve_bundle) and hex64(approve_source),'HOLD_APPROVAL_INPUT_FORMAT')
    required={'CLOUD_PREPARE_PROOF.json','RELEASE_REVIEW.json','UNSIGNED_MANIFEST_REVIEW.json','pf01-ota-web.zip'}
    found={p.name for p in artifact_dir.iterdir() if p.is_file()}
    assert_true(found==required,'HOLD_ARTIFACT_MEMBER_SET_MISMATCH')
    proof=load_json(artifact_dir/'CLOUD_PREPARE_PROOF.json')
    report_bytes=(artifact_dir/'RELEASE_REVIEW.json').read_bytes()
    unsigned_bytes=(artifact_dir/'UNSIGNED_MANIFEST_REVIEW.json').read_bytes()
    r=load_json(artifact_dir/'RELEASE_REVIEW.json')
    body=load_json(artifact_dir/'UNSIGNED_MANIFEST_REVIEW.json')
    zip_bytes=(artifact_dir/'pf01-ota-web.zip').read_bytes()
    assert_true(proof.get('schema')=='PF01_CLOUD_PREPARE_PROOF_V1' and
                proof.get('repository')==PRIVATE_REPO and proof.get('workflowPath')=='.github/workflows/pf01-ota-cloud-prepare.yml' and
                proof.get('runId')==run_id and proof.get('headRef')=='refs/heads/main' and
                proof.get('actor')=='parksu9308' and proof.get('version')==VERSION and
                proof.get('releaseTag')=='pf01-ota-16.0.3-inputs' and
                bool(re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}',str(proof.get('headSha','')))) and
                proof.get('didSign') is False and proof.get('didDeploy') is False and proof.get('didIssue') is False,
                'HOLD_PRIVATE_PREPARE_PROOF_SCOPE')
    assert_true(proof.get('reviewSha256')==sha(report_bytes) and
                proof.get('unsignedManifestSha256')==sha(unsigned_bytes),
                'HOLD_PRIVATE_PROOF_FILE_SHA_MISMATCH')
    assert_true(r.get('status')=='PREPARED_REVIEW_ONLY_NOT_SIGNED_NOT_DEPLOYED' and
                r.get('didSign') is False and r.get('didDeploy') is False and r.get('didIssue') is False and
                r.get('canAutoStart') is False,'HOLD_PREPARE_STATUS_NOT_UNSIGNED')
    rv=r.get('review',{})
    assert_true(rv.get('baselineZipSha256')==BASE_SHA and rv.get('candidateZipSha256')==CAND_SHA and
                rv.get('changeCount')==4 and set(rv.get('changedPaths',[]))==CHANGED and
                rv.get('requiresExplicitHumanCodeReview') is True and
                rv.get('officialPlayIssuerAuthority') is False and
                rv.get('preIssuerNativeReadOnlyScope') is True,'HOLD_PREISSUER_CHANGE_SCOPE')
    assert_true(r.get('apkSha256')==APK_SHA and r.get('pinnedOtaPublicSha256')==PUBLIC_PIN_SHA and
                r.get('manifestUrl')==MANIFEST_URL,'HOLD_APK_PIN_OR_MANIFEST_URL')
    assert_true(r.get('web',{}).get('sourceDigest')==approve_source==proof.get('sourceDigest') and
                r.get('web',{}).get('sourceEntries',0)>=170 and
                r.get('web',{}).get('outputEntries',0)>=15,'HOLD_SOURCE_DIGEST_OR_PROVENANCE')
    assert_true(set(body)==set(ORDER) and body.get('schema')==SCHEMA and body.get('appId')==APPID and
                body.get('nativeCompat')==COMPAT and body.get('minNativeCode')==8 and
                body.get('version')==VERSION and body.get('bundleUrl')==BUNDLE_URL and
                body.get('publisher')=='PF01_OTA_QA','HOLD_UNSIGNED_MANIFEST_WRONG_SCOPE')
    assert_true(sha(zip_bytes)==approve_bundle==r.get('webBundleSha256')==body.get('bundleSha256')==proof.get('bundleSha256'),
                'HOLD_BUNDLE_SHA_APPROVAL_MISMATCH')
    with zipfile.ZipFile(artifact_dir/'pf01-ota-web.zip') as z:
        names=z.namelist()
        assert_true(len(names)==len(set(names)) and 'index.html' in names and 'pf01-build.json' in names and
                    z.testzip() is None,'HOLD_WEB_ZIP_INVALID')
        assert_true(not any(n.startswith('/') or '..' in n.split('/') or '\\' in n or n.startswith('.env') for n in names),'HOLD_WEB_ZIP_PATH')
    if repo_api:
        t=os.environ.get('PF01_PRIVATE_READ_PAT','')
        assert_true(bool(t),'HOLD_PRIVATE_ARTIFACT_READ_TOKEN_MISSING')
        run=request_api(f'https://api.github.com/repos/{PRIVATE_REPO}/actions/runs/{run_id}',t)
        assert_true(run.get('conclusion')=='success' and run.get('status')=='completed' and
                    run.get('event')=='workflow_dispatch' and run.get('head_branch')=='main' and
                    run.get('head_sha')==proof['headSha'] and
                    run.get('actor',{}).get('login')=='parksu9308' and
                    str(run.get('path','')).split('@')[0]==proof['workflowPath'],
                    'HOLD_PRIVATE_PREPARE_RUN_NOT_TRUSTED')
    return body, r, zip_bytes

def get_verified_public_key():
    p=Path(__file__).parent/'ota-public.spki.b64'
    raw=base64.b64decode(p.read_text(encoding='ascii').strip(),validate=True)
    assert_true(sha(raw)==PUBLIC_PIN_SHA,'HOLD_OTA_PUBLISHER_PUBLIC_KEY_CHANGED')
    k=serialization.load_der_public_key(raw)
    assert_true(isinstance(k,rsa.RSAPublicKey) and k.key_size==3072,'HOLD_OTA_PUBLIC_KEY_NOT_RSA3072')
    return k

def sign(body:dict,pub:rsa.RSAPublicKey)->bytes:
    pem=os.environ.get('PF01_OTA_ENCRYPTED_PEM','').encode('ascii')
    password=os.environ.get('PF01_OTA_PEM_PASSWORD','').encode('utf-8')
    assert_true(pem.startswith(b'-----BEGIN ENCRYPTED PRIVATE KEY-----') and password,
                'HOLD_ENCRYPTED_OTA_KEY_ENVIRONMENT_SECRET_MISSING')
    key=serialization.load_pem_private_key(pem,password=password)
    assert_true(isinstance(key,rsa.RSAPrivateKey) and key.key_size==3072 and
                key.public_key().public_numbers()==pub.public_numbers(),
                'HOLD_OTA_PRIVATE_KEY_NOT_MATCHING_V13_APK')
    msg=compact_body(body)
    signature=key.sign(msg,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    pub.verify(signature,msg,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    out=json.dumps({**body,'signature':base64.b64encode(signature).decode('ascii')},ensure_ascii=False,indent=2)+'\n'
    return out.encode('utf-8')

def publish_new_only(token:str,body:dict,manifest_bytes:bytes,bundle_bytes:bytes):
    assert_true(os.environ.get('GITHUB_REPOSITORY')==PUBLIC_REPO and os.environ.get('GITHUB_REF')=='refs/heads/main',
                'HOLD_PUBLIC_SIGNER_WRONG_REPOSITORY_OR_BRANCH')
    api=f'https://api.github.com/repos/{PUBLIC_REPO}/contents/'
    dest=[(f'docs/qa/{VERSION}.zip',bundle_bytes),(f'docs/qa/manifest-{VERSION}.json',manifest_bytes)]
    for name,_ in dest:
        request_api(api+name+'?ref=main',token,expect=404)
    for name,data in dest:
        request_api(api+name,token,method='PUT',data={
            'message':f'pf01 OTA QA {VERSION} immutable signed publication: {name.split("/")[-1]}',
            'content':base64.b64encode(data).decode('ascii'),
            'branch':'main'
        },expect=201)
    return {'status':'PUBLISHED_SIGNED_OTA_QA_WEB_ONLY','version':VERSION,'bundleSha256':sha(bundle_bytes),
            'manifestSha256':sha(manifest_bytes),'manifestUrl':MANIFEST_URL,'canIssueOfficialGameAuthority':False}

def main():
    p=argparse.ArgumentParser()
    p.add_argument('--unsigned-dir',type=Path,required=True)
    p.add_argument('--approve-run-id',type=int,required=True)
    p.add_argument('--approve-bundle-sha',required=True)
    p.add_argument('--approve-source-digest',required=True)
    a=p.parse_args()
    try:
        assert_true(os.environ.get('GITHUB_ACTOR')=='parksu9308','HOLD_DISPATCH_ACTOR_NOT_OWNER')
        body,report,zip_bytes=verify_release(a.unsigned_dir,a.approve_run_id,a.approve_bundle_sha,a.approve_source_digest)
        pub=get_verified_public_key()
        signed=sign(body,pub)
        token=os.environ.get('PF01_PUBLIC_REPO_TOKEN','')
        assert_true(bool(token),'HOLD_PUBLIC_REPO_WRITE_TOKEN_MISSING')
        result=publish_new_only(token,body,signed,zip_bytes)
        print(json.dumps(result,indent=2))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            with open(os.environ['GITHUB_STEP_SUMMARY'],'a') as f:
                f.write(f'## PF01 {VERSION}: SIGNED web QA published (NOT official GAME authority)\n')
                f.write(f"- Bundle SHA: `{result['bundleSha256']}`\n- Manifest SHA: `{result['manifestSha256']}`\n- {MANIFEST_URL}\n")
        return 0
    except Exception as e:
        # Never expose exception details from cryptography passwords/tokens to Actions log.
        typ = str(e) if isinstance(e,ValueError) and str(e).startswith('HOLD_') else 'HOLD_CLOUD_SIGN_OR_PUBLISH_UNVERIFIED'
        print(typ,file=sys.stderr)
        return 2
if __name__=='__main__':raise SystemExit(main())
