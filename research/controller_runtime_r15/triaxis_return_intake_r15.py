#!/usr/bin/env python3
"""
TRIAXIS R15 return-intake verifier.

Purpose:
- preserve a provider return ZIP as raw evidence;
- reject unsafe archive paths/symlinks;
- verify SHA256SUMS;
- verify that every returned regular file is covered by SHA256SUMS;
- bind scientific-model vs execution-backend identity;
- report expected R9-C artifacts without inferring a scientific verdict.

No network or remote writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

R9C_EXPECTED = (
    "r9c_w0_native_result.json",
    "r9c_failure_queue.json",
    "r9c_v1_outputs.json",
    "r9c_final_result.json",
    "r9c_r10o_receipt.json",
)

def sha256_file(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda:f.read(1024*1024),b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_member(info: zipfile.ZipInfo) -> tuple[bool,str|None]:
    name=info.filename.replace("\\","/")
    p=PurePosixPath(name)
    if not name or name.startswith("/") or p.is_absolute():
        return False,"ABSOLUTE_OR_EMPTY_PATH"
    if any(part in {"..",""} for part in p.parts):
        return False,"PATH_TRAVERSAL"
    mode=(info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        return False,"SYMLINK_FORBIDDEN"
    return True,None

def parse_sha256sums(path: Path) -> tuple[dict[str,str],list[str]]:
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
        p=PurePosixPath(name)
        if p.is_absolute() or ".." in p.parts:
            errors.append(f"UNSAFE_SUM_PATH:{lineno}")
            continue
        if name in entries:
            errors.append(f"DUPLICATE_SUM_ENTRY:{name}")
            continue
        entries[name]=digest
    return entries,errors

def inspect_return(zip_path: Path, *, scientific_model: str, execution_backend: str) -> dict:
    errors=[]
    warnings=[]
    files=[]
    archive_sha=sha256_file(zip_path)

    with tempfile.TemporaryDirectory(prefix="triaxis_return_") as td:
        out=Path(td)
        try:
            zf=zipfile.ZipFile(zip_path)
        except Exception as e:
            return {
                "schema":"triaxis.r15.return_intake/v1",
                "status":"FAIL",
                "archive_sha256":archive_sha,
                "identity":{"scientific_model":scientific_model,"execution_backend":execution_backend},
                "errors":[f"INVALID_ZIP:{type(e).__name__}:{e}"],
            }

        infos=zf.infolist()
        for info in infos:
            ok,err=_safe_member(info)
            if not ok:
                errors.append(f"{err}:{info.filename}")

        if errors:
            return {
                "schema":"triaxis.r15.return_intake/v1",
                "status":"FAIL",
                "archive_sha256":archive_sha,
                "identity":{"scientific_model":scientific_model,"execution_backend":execution_backend},
                "errors":sorted(errors),
            }

        for info in infos:
            if info.is_dir():
                continue
            dest=out/PurePosixPath(info.filename)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src,dst)
            files.append(info.filename.replace("\\","/"))

        sums_candidates=[f for f in files if PurePosixPath(f).name=="SHA256SUMS"]
        if len(sums_candidates)!=1:
            errors.append(f"SHA256SUMS_COUNT:{len(sums_candidates)}")
            sums={}
        else:
            sums_path=out/sums_candidates[0]
            sums,sum_errors=parse_sha256sums(sums_path)
            errors.extend(sum_errors)

        base_dir=PurePosixPath(sums_candidates[0]).parent if sums_candidates else PurePosixPath(".")
        regular=[f for f in files if PurePosixPath(f).name!="SHA256SUMS"]

        # Normalize returned files relative to SHA256SUMS directory.
        rel_files={}
        for f in regular:
            pp=PurePosixPath(f)
            try:
                rel=str(pp.relative_to(base_dir))
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

        uncovered=sorted(set(rel_files)-set(sums))
        if uncovered:
            errors.extend(f"UNHASHED_RETURN_FILE:{x}" for x in uncovered)

        extra_sums=sorted(set(sums)-set(rel_files))
        if extra_sums:
            errors.extend(f"SUM_WITHOUT_FILE:{x}" for x in extra_sums)

        basename_map={}
        for rel in rel_files:
            basename_map.setdefault(PurePosixPath(rel).name,[]).append(rel)

        present={}
        for expected in R9C_EXPECTED:
            matches=basename_map.get(expected,[])
            present[expected]=matches
            if len(matches)>1:
                warnings.append(f"DUPLICATE_EXPECTED_BASENAME:{expected}")

        has_final=bool(present["r9c_final_result.json"])
        has_failure_receipt=any(
            "failure" in PurePosixPath(x).name.lower() and PurePosixPath(x).suffix.lower()==".json"
            for x in rel_files
        )
        execution_shape=(
            "NORMAL_OUTPUT_SET_PRESENT" if has_final
            else "FAILURE_RETURN_PRESENT" if has_failure_receipt
            else "INCOMPLETE_OR_UNKNOWN_RETURN_SHAPE"
        )

        return {
            "schema":"triaxis.r15.return_intake/v1",
            "status":"PASS" if not errors else "FAIL",
            "archive":{
                "path":str(zip_path),
                "sha256":archive_sha,
                "files_total":len(regular),
                "sha256sums_entries":len(sums),
            },
            "identity":{
                "scientific_model":scientific_model,
                "execution_backend":execution_backend,
                "backend_is_scientific_model":False,
            },
            "evidence_class":{
                "backend_execution_evidence":"ELIGIBLE_IF_RAW_EXECUTION_LOGS_PRESENT",
                "scientific_model_evidence":"REQUIRES_VALID_NATIVE_SCORE_AND_CONTRACT_ADMISSION",
                "scientific_verdict":"NOT_ADJUDICATED_BY_INTAKE",
            },
            "r9c_expected_artifacts":present,
            "execution_shape":execution_shape,
            "errors":sorted(errors),
            "warnings":sorted(warnings),
            "governance":{
                "W0_REGENERATION":False,
                "MERGE_PERMISSION":"DENY",
                "deploy_permission":"DENY",
                "can_trade":False,
                "capital_permission":"DENY",
            },
        }

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("zip",type=Path)
    ap.add_argument("-o","--output",type=Path)
    ap.add_argument("--scientific-model",default="Qwen/Qwen3.5-0.8B pinned R9-C revision")
    ap.add_argument("--execution-backend",default="Manus Agent")
    args=ap.parse_args()
    out=inspect_return(args.zip,scientific_model=args.scientific_model,execution_backend=args.execution_backend)
    text=json.dumps(out,ensure_ascii=False,indent=2,sort_keys=True)+"\n"
    if args.output:
        args.output.write_text(text,encoding="utf-8")
        print(args.output)
    else:
        print(text,end="")
    return 0 if out["status"]=="PASS" else 2

if __name__=="__main__":
    raise SystemExit(main())
