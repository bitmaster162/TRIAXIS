#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional
import argparse, json

class AuthorityState(str,Enum):
    AUTHORITY_FRESH="AUTHORITY_FRESH"
    HELPER_STALE_DIRECT_AUTHORITY_FRESH="HELPER_STALE_DIRECT_AUTHORITY_FRESH"
    HOLD_AUTHORITY_CONFLICT="HOLD_AUTHORITY_CONFLICT"
    HOLD_REF_UNAVAILABLE="HOLD_REF_UNAVAILABLE"

@dataclass(frozen=True)
class AuthorityEvidence:
    helper_head:Optional[str]=None
    direct_ref_head:Optional[str]=None
    direct_pr_head:Optional[str]=None

@dataclass(frozen=True)
class Resolution:
    state:AuthorityState
    authority_head:Optional[str]
    consequential_write_allowed:bool
    stale_helper:bool
    reasons:tuple[str,...]

def resolve(e:AuthorityEvidence)->Resolution:
    if not e.direct_ref_head:
        return Resolution(
            AuthorityState.HOLD_REF_UNAVAILABLE,None,False,False,
            ("DIRECT_REF_REQUIRED",)
        )
    if e.direct_pr_head and e.direct_pr_head != e.direct_ref_head:
        return Resolution(
            AuthorityState.HOLD_AUTHORITY_CONFLICT,None,False,False,
            ("DIRECT_REF_PR_HEAD_MISMATCH",)
        )
    if e.helper_head and e.helper_head != e.direct_ref_head:
        return Resolution(
            AuthorityState.HELPER_STALE_DIRECT_AUTHORITY_FRESH,
            e.direct_ref_head,True,True,
            ("NORMALIZED_HELPER_STALE","DIRECT_REF_PRECEDENCE")
        )
    reasons=["DIRECT_REF_CONFIRMED"]
    if e.direct_pr_head:
        reasons.append("DIRECT_PR_CORROBORATED")
    if e.helper_head:
        reasons.append("HELPER_AGREES")
    return Resolution(
        AuthorityState.AUTHORITY_FRESH,e.direct_ref_head,True,False,tuple(reasons)
    )

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--helper-head")
    ap.add_argument("--direct-ref-head")
    ap.add_argument("--direct-pr-head")
    a=ap.parse_args()
    r=resolve(AuthorityEvidence(a.helper_head,a.direct_ref_head,a.direct_pr_head))
    print(json.dumps({
      "state":r.state.value,
      "authority_head":r.authority_head,
      "consequential_write_allowed":r.consequential_write_allowed,
      "stale_helper":r.stale_helper,
      "reasons":list(r.reasons),
    },sort_keys=True))
    return 0 if r.consequential_write_allowed else 2

if __name__=="__main__": raise SystemExit(main())
