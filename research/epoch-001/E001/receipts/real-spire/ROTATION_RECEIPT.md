# SVID Rotation Evidence — E001-R1

* **Configured Experimental TTL**: `120s` (research-only, NOT a production policy threshold)
* **Wait Period**: `135s`
* **Application Restart Required**: `false`

## First SVID
* **serial=428499DEDF000EF0648432B85308D440**
* **notAfter=Aug  7 18:15:44 2026 GMT**
* **sha256 Fingerprint=90:4F:44:43:A8:DF:E1:C5:ED:A8:09:F5:92:04:20:AC:75:22:B5:3A:E0:96:B0:2B:0D:79:82:A0:3D:C2:0E:00**

## Second SVID (post-rotation)
* **serial=A5B646754181E5B2420BEDFADFB6EE07**
* **notAfter=Aug  7 18:17:41 2026 GMT**
* **sha256 Fingerprint=DC:31:54:9A:F3:88:88:B6:CD:76:19:09:F9:15:DF:1A:6C:5E:4B:D5:27:33:0A:34:E5:39:B5:A1:E7:75:54:2B**

## Rotation Observed: `true`
* **Evidence Classification**: `EXECUTED_RESULT`

> **NOTE**: The 120s experimental TTL is NOT a proposed production threshold. Production SVID lifetime must be bounded by policy derived from threat model, workload characteristics, failure recovery requirements, and measured rotation behavior.
