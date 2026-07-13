# Protocol Reference — every protocol in the catalog, explained

The function catalog (`../catalog/02_FUNCTION_CATALOG_HUAWEI.md`) and the findings talk about MAC, RLC, RRC,
NAS, PDCP, RTP, and dozens of other acronyms. **This folder defines each one** so you never hit a term
you don't understand. For every protocol you get: **meaning, purpose, the exact 3GPP TS / IETF RFC that
defines it (with a link), how its packet looks on the wire (ASCII field diagram), the key fields, beginner
gotchas, and its security relevance** (which layer, pre-/post-auth, and which findings live in it).

Read `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` first for the big picture, and keep `../fundamentals/03_GLOSSARY_AND_NAMING.md`
open for acronyms.

## Files (bottom of the stack → top)

| File | Layer | Protocols |
|---|---|---|
| `01_physical_layer.md` | **L1** | GSM / WCDMA / LTE / NR PHY + logical↔transport↔physical channel mapping |
| `02_layer2_mac_rlc_pdcp_sdap.md` | **L2** | MAC · RLC · PDCP · SDAP · LLC · SNDCP (with PDU/header diagrams) |
| `03_layer3_as_rrc_rr.md` | **L3 (Access Stratum)** | GSM RR · UMTS/LTE/NR RRC (SIB/MIB, paging, connection, security-mode) |
| `04_layer3_nas.md` | **L3 (NAS)** | MM · CC · GMM · SM · EMM · ESM · 5GMM · 5GSM + NAS header & IE (TLV) formats |
| `05_encodings.md` | (cross-cutting) | ASN.1/PER/UPER · TLV family · CSN.1 · BCD — *how bytes become structs* |
| `06_sms_cb_etws.md` | services | SMS (CP/RP/TP, TPDU, UDH, 7-bit packing) · Cell Broadcast · ETWS/CMAS |
| `07_ims_media.md` | IMS/media | SIP · SDP · RTP · RTCP · RTT redundancy (RFC 4103) · EVS/AMR codec framing |
| `08_security.md` | cross-cutting | AKA · key hierarchy · NAS security · AS security · EIA/EEA algorithms · the 32-bit MAC |

## The one thing to carry through all of it
At every layer, a **decoder** turns attacker-controlled **bytes** into a **structure**. The packet-format
diagrams here show you exactly what those bytes are. **Wherever a decoder reads a length / count / index
from the packet and uses it in a copy or array write without checking it fits, that's a bug** — and that
single pattern is behind almost every finding in this project (see `../../../CONSOLIDATED_FINDINGS.md`).

## Which protocol each finding lives in
| Finding | Protocol (file) |
|---|---|
| F1 (MT-SMS) | SMS — `06_sms_cb_etws.md` |
| F2 (VoLTE RTT) | RTP redundancy — `07_ims_media.md` |
| F3, F12 (ESM PCO) | ESM / TLV — `04_layer3_nas.md`, `05_encodings.md` |
| F4, F5, F11 (5GMM IEs) | 5GMM / TLV — `04_layer3_nas.md` |
| F6, F9 (NR SI) | NR RRC + L1 handoff — `03_layer3_as_rrc_rr.md`, `01_physical_layer.md` |
| F7 (EVS) | EVS codec framing — `07_ims_media.md` |
| F8 (GSM CB) | Cell Broadcast + 7-bit packing — `06_sms_cb_etws.md`, `05_encodings.md` |
| F10 (GSM neighbour list) | GSM RR + CSN.1 — `03_layer3_as_rrc_rr.md`, `05_encodings.md` |
| F13 (integrity underflow) | NAS security / the crypto MAC — `08_security.md`, `04_layer3_nas.md` |

> **Note on accuracy:** these diagrams are written to be spec-faithful, but a few bit-widths are marked
> "(verify)" where they vary by release/option — always confirm against the cited TS/RFC before relying
> on an exact width for exploit development.
