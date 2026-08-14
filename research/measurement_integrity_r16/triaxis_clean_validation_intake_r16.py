#!/usr/bin/env python3
"""
TRIAXIS R16 clean-validation return intake.

Validates an independently produced clean-suite ZIP without inferring production
qualification or model-level evidence.

GREEN requires all of:
- safe ZIP paths, no symlinks;
- exactly one SHA256SUMS;
- every returned regular file covered by SHA256SUMS and hash-valid;
- one summary JSON with exact expected git HEAD;
- dependency install terminal success;
- full unittest terminal success;
- tests_run > 0, failures=0, errors=0, timed_out=false;
- raw install and unittest logs present and hashed;
- exact declared test command present.

No network or remote writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

SCHEMA="triaxis.r16.clean_validation_intake/v1"
REQUIRED_COMMAND="PYTHONPATH=src:. python -m unittest discover -s tests -v"

def sha256_file(path:Path)->str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def safe_member(info:zipfile.ZipInfo)->tuple[bool,str|None]:
    raw=info.filename.replace("\\","/")
    p=PurePosixPath(raw)
    if not raw or raw.startswith("/") or p.is_absolute():
        return False,"ABSOLUTE_OR_EMPTY_PATH"
    if any(part in {"",".."} for part in p.parts):
        return False,"PATH_TRAVERSAL"
    mode=(info.external_attr>>16)&0xFFFF
    if stat.S_ISLNK(mode):
        return False,"SYMLINK_FORBIDDEN"
    return True,None

def parse_sums(path:Path)->tuple[dict[str,str],list[str]]:
    entries={}
    errors=[]
    for lineno,line in enumerate(path.read_text(encoding="utf-8",errors="strict").splitlines(),1):
        if not line.strip():
            continue
        m=re.fullmatch(r"([0-9a-fA-F]{64})[ \t]+[* ]?(.+)",line)
        if not m:
            errors.append(f"BAD_SHA256SUMS_LINE:{lineno}")
            continue
        digest,name=m.group(1).lower(),m.group(2).strip().replace("\\","/")
        if name=="SHA256SUMS":
            errors.append(f"SELF_HASH_FORBIDDEN:{lineno}")
            continue
        pp=PurePosixPath(name)
        if pp.is_absolute() or ".." in pp.parts:
            errors.append(f"UNSAFE_SUM_PATH:{lineno}")
            continue
        if name in entries:
            errors.append(f"DUPLICATE_SUM_ENTRY:{name}")
            continue
        entries[name]=digest
    return entries,errors

def _as_int(summary:dict,key:str,errors:list[str])->int|None:
    v=summary.get(key)
    if isinstance(v,bool) or not isinstance(v,int):
        errors.append(f"SUMMARY_{key.upper()}_NOT_INT")
        return None
    return v

def inspect(zip_path:Path, *, expected_head:str)->dict:
    errors=[]
    warnings=[]
    archive_sha=sha256_file(zip_path)

    try:
        zf=zipfile.ZipFile(zip_path)
    except Exception as e:
        return {
          "schema":SCHEMA,"status":"FAIL","green":False,
          "archive_sha256":archive_sha,
          "errors":[f"INVALID_ZIP:{type(e).__name__}:{e}"],
          "warnings":[]
        }

    with zf, tempfile.TemporaryDirectory(prefix="triaxis_clean_") as td:
        out=Path(td)
        infos=zf.infolist()

        for info in infos:
            ok,err=safe_member(info)
            if not ok:
                errors.append(f"{err}:{info.filename}")
        if errors:
            return {
              "schema":SCHEMA,"status":"FAIL","green":False,
              "archive_sha256":archive_sha,
              "errors":sorted(errors),"warnings":[]
            }

        files=[]
        for info in infos:
            if info.is_dir():
                continue
            rel=info.filename.replace("\\","/")
            dest=out/PurePosixPath(rel)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src,dst)
            files.append(rel)

        sums_files=[f for f in files if PurePosixPath(f).name=="SHA256SUMS"]
        if len(sums_files)!=1:
            errors.append(f"SHA256SUMS_COUNT:{len(sums_files)}")
            sums={}
            base=PurePosixPath(".")
        else:
            sf=sums_files[0]
            base=PurePosixPath(sf).parent
            sums,sum_errors=parse_sums(out/sf)
            errors.extend(sum_errors)

        rel_files={}
        for f in files:
            if PurePosixPath(f).name=="SHA256SUMS":
                continue
            pp=PurePosixPath(f)
            try:
                rel=str(pp.relative_to(base))
            except ValueError:
                errors.append(f"FILE_OUTSIDE_SUM_ROOT:{f}")
                continue
            rel_files[rel]=out/f

        for name,digest in sums.items():
            fp=rel_files.get(name)
            if fp is None:
                errors.append(f"SUM_TARGET_MISSING:{name}")
                continue
            got=sha256_file(fp)
            if got!=digest:
                errors.append(f"HASH_MISMATCH:{name}:{digest}:{got}")

        for name in sorted(set(rel_files)-set(sums)):
            errors.append(f"UNHASHED_RETURN_FILE:{name}")
        for name in sorted(set(sums)-set(rel_files)):
            errors.append(f"SUM_WITHOUT_FILE:{name}")

        summary_candidates=[
            name for name in rel_files
            if PurePosixPath(name).name in {"summary.json","clean_validation_summary.json"}
        ]
        if len(summary_candidates)!=1:
            errors.append(f"SUMMARY_JSON_COUNT:{len(summary_candidates)}")
            summary={}
        else:
            try:
                summary=json.loads(rel_files[summary_candidates[0]].read_text(encoding="utf-8"))
            except Exception as e:
                errors.append(f"SUMMARY_JSON_INVALID:{type(e).__name__}:{e}")
                summary={}

        # Required summary fields.
        git_head=summary.get("git_head")
        if git_head!=expected_head:
            errors.append(f"GIT_HEAD_MISMATCH:{git_head}:{expected_head}")

        command=summary.get("test_command")
        if command!=REQUIRED_COMMAND:
            errors.append("TEST_COMMAND_MISMATCH")

        install_exit=_as_int(summary,"install_exit_code",errors)
        test_exit=_as_int(summary,"test_exit_code",errors)
        tests_run=_as_int(summary,"tests_run",errors)
        failures=_as_int(summary,"failures",errors)
        test_errors=_as_int(summary,"errors",errors)
        skips=_as_int(summary,"skips",errors)

        timed_out=summary.get("timed_out")
        if not isinstance(timed_out,bool):
            errors.append("SUMMARY_TIMED_OUT_NOT_BOOL")
        elif timed_out:
            errors.append("TEST_TIMED_OUT")

        if install_exit is not None and install_exit!=0:
            errors.append(f"INSTALL_EXIT_NONZERO:{install_exit}")
        if test_exit is not None and test_exit!=0:
            errors.append(f"TEST_EXIT_NONZERO:{test_exit}")
        if tests_run is not None and tests_run<=0:
            errors.append(f"NO_TESTS_RUN:{tests_run}")
        if failures is not None and failures!=0:
            errors.append(f"TEST_FAILURES:{failures}")
        if test_errors is not None and test_errors!=0:
            errors.append(f"TEST_ERRORS:{test_errors}")
        if skips is not None and skips<0:
            errors.append(f"INVALID_SKIPS:{skips}")

        # Terminal-evidence fields.
        if not isinstance(summary.get("python_version"),str) or not summary.get("python_version","").strip():
            errors.append("PYTHON_VERSION_MISSING")
        if not isinstance(summary.get("pip_version"),str) or not summary.get("pip_version","").strip():
            errors.append("PIP_VERSION_MISSING")
        if not isinstance(summary.get("elapsed_seconds"),(int,float)) or isinstance(summary.get("elapsed_seconds"),bool):
            errors.append("ELAPSED_SECONDS_INVALID")
        elif summary["elapsed_seconds"]<0:
            errors.append("ELAPSED_SECONDS_NEGATIVE")

        required_logs={
            "install_log":summary.get("install_log"),
            "test_log":summary.get("test_log"),
            "freeze_log":summary.get("freeze_log"),
        }
        for key,name in required_logs.items():
            if not isinstance(name,str) or not name:
                errors.append(f"{key.upper()}_MISSING")
                continue
            if name not in rel_files:
                errors.append(f"{key.upper()}_FILE_MISSING:{name}")
            elif name not in sums:
                errors.append(f"{key.upper()}_NOT_HASHED:{name}")

        # Optional explicit loader/discovery flag: if present it must be false.
        loader_errors=summary.get("loader_errors")
        if loader_errors is not None:
            if not isinstance(loader_errors,int) or isinstance(loader_errors,bool):
                errors.append("LOADER_ERRORS_NOT_INT")
            elif loader_errors!=0:
                errors.append(f"LOADER_ERRORS:{loader_errors}")

        green=not errors
        return {
          "schema":SCHEMA,
          "status":"PASS" if green else "FAIL",
          "green":green,
          "archive":{
            "path":str(zip_path),
            "sha256":archive_sha,
            "files_total":len(rel_files),
            "sha256sums_entries":len(sums)
          },
          "expected_git_head":expected_head,
          "reported_git_head":git_head,
          "summary":summary,
          "errors":sorted(errors),
          "warnings":sorted(warnings),
          "claim_boundary":{
            "clean_suite_reproducible_at_exact_commit":green,
            "production_qualified":False,
            "physical_authority_independence":False,
            "physical_worm":False,
            "trading_safety_proven":False,
            "broad_intelligence_lift":False
          }
        }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("zip",type=Path)
    ap.add_argument("--expected-head",required=True)
    ap.add_argument("-o","--output",type=Path)
    a=ap.parse_args()
    out=inspect(a.zip,expected_head=a.expected_head)
    text=json.dumps(out,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    if a.output:
        a.output.write_text(text,encoding="utf-8")
        print(a.output)
    else:
        print(text,end="")
    return 0 if out["green"] else 2

if __name__=="__main__":
    raise SystemExit(main())
