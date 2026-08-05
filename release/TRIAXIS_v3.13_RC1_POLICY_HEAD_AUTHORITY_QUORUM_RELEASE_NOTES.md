# TRIAXIS v3.13-RC1 Release Notes

Added operator-pinned Policy Head Authority quorum:

- sealed quorum configuration;
- exact config digest pin;
- threshold agreement by distinct authority, signer, key and trust domain;
- split-view and signer-equivocation detection;
- operator minimum policy floor embedded in the pinned config;
- closure trigger and schema validation.

One rolled-back or compromised authority can no longer determine the accepted policy head when the remaining threshold is current.
