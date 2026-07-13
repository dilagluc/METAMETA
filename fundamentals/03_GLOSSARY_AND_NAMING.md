# Glossary + "How to read baseband function names" (beginner cheat-sheet)

Two things beginners struggle with most: the **acronym soup** and **decoding the `SomeFunc_Prefix_Name`
convention** in the firmware. Keep this open while reading the catalog and the findings.

---

## A. Acronym glossary

### Entities & network
| Term | Meaning |
|---|---|
| UE | User Equipment = the phone (specifically its baseband/modem here) |
| AP | Application Processor = the Android SoC (separate from the modem) |
| RAT | Radio Access Technology (GSM/UMTS/LTE/NR) |
| BTS / NodeB / eNB / gNB | Base station for 2G / 3G / 4G / 5G |
| RNC | Radio Network Controller (3G) |
| MSC / SGSN | 2G/3G core: circuit-switched / packet-switched serving nodes |
| MME / SGW / PGW | 4G core (EPC): mobility mgmt / serving & packet gateways |
| AMF / SMF / UPF | 5G core (5GC): access-mobility / session mgmt / user-plane function |
| PLMN | Public Land Mobile Network = a specific operator's network (MCC+MNC) |
| IMSI / SUPI | Permanent subscriber identity (2G-4G / 5G) |
| GUTI / 5G-GUTI | Temporary subscriber identity |

### Layers & sublayers
| Term | Layer | Job |
|---|---|---|
| PHY | L1 | Physical radio (modulation/coding); much runs on the DSP |
| MAC | L2 | Medium Access Control: scheduling, HARQ, MAC PDUs/CEs |
| RLC | L2 | Radio Link Control: **segmentation & reassembly**, ARQ |
| PDCP | L2 (4G/5G) | **Ciphering & integrity**, header compression, reorder |
| SDAP | L2 (5G) | QoS flow → radio bearer mapping |
| LLC / SNDCP | L2 (2G GPRS) | Logical Link Control / packet convergence |
| RRC / RR | L3 (AS) | Radio Resource Control (3G/4G/5G) / Radio Resource (2G): SIB, paging, connection |
| NAS | L3 | Non-Access Stratum: signalling to the CORE (through the base station) |

### NAS protocols (L3, per generation & domain)
| Term | Gen / domain | Job |
|---|---|---|
| MM / CC | 2G/3G circuit-switched | Mobility Mgmt / Call Control (voice) |
| GMM / SM | 2G/3G packet-switched | GPRS Mobility Mgmt / Session Mgmt (data) |
| EMM / ESM | 4G LTE | EPS Mobility Mgmt / EPS Session Mgmt |
| 5GMM / 5GSM | 5G NR | 5G Mobility Mgmt / 5G Session Mgmt |
| SMS (CP/RP/TP) | all | Short Message Service transport sublayers; **TPDU** = the message PDU you decode |
| CB / ETWS / CMAS | all | Cell Broadcast / Earthquake-Tsunami & Commercial Mobile alerts (broadcast) |

### Messages / structures
| Term | Meaning |
|---|---|
| MIB / SIB | Master / System Information Block — **broadcast** cell parameters (pre-auth) |
| PCCH / BCCH / CCCH / DCCH | Paging / Broadcast / Common / Dedicated control channels |
| IE | Information Element — one field inside a message (Type-Length-Value or ASN.1) |
| PDU / SDU | Protocol / Service Data Unit — a packet at a given layer |
| RTP / RTCP | Real-time Transport Protocol / its Control Protocol — **voice/video media** |
| SIP / SDP | Session Initiation Protocol / Session Description Protocol — IMS call signalling (often AP-side) |
| EVS / AMR | Enhanced Voice Services / Adaptive Multi-Rate — voice **codecs** |
| RTT (T.140) | Real-Time Text — text sent live during a call (RFC 4103) |

### Encodings
| Term | Used by | Note |
|---|---|---|
| TLV | NAS | Type-Length-Value; a length byte drives a copy — overflow-prone |
| ASN.1 / PER / UPER | RRC (3G/4G/5G) | Formal schema, bit-packed; huge auto-generated decoders |
| CSN.1 | GSM RR / GPRS | Bit-oriented description |
| BCD | phone numbers | Binary-Coded Decimal digits |

### Security
| Term | Meaning |
|---|---|
| AS / NAS security | Radio-link (PDCP) / core-signalling (NAS) protection |
| AKA | Authentication and Key Agreement (proves the SIM key K) |
| EIA / EEA | EPS Integrity / Encryption Algorithm (LTE); NIA/NEA in 5G |
| MAC (crypto) | Message Authentication Code = the integrity signature (≠ the MAC layer!) |
| pre-auth / post-auth | Before / after the security context (integrity) is established — see the tier model |

> ⚠️ **"MAC" is two different things:** the **L2 Medium Access Control** layer, and the **cryptographic
> Message Authentication Code** (integrity signature). Context tells you which.

---

## B. How to read a baseband function name

MediaTek's symbolized names (Huawei build) follow patterns. Once you know the prefixes you can guess a
function's RAT, layer, and job before you even open it. General shape:

```
[RAT/tech prefix]_[subsystem]_[action]_[object]
   e.g.  vgmm_decode_ladn_info      → 5G(v=5G) MM, decode, LADN Information IE
         AsnDecode_RRC_SysInfoType3 → ASN.1 decoder, UMTS RRC, System Info Block 3
         FDD_rr_decode_..._cells    → GSM (FDD) Radio Resource, decode, ... cells
         esm_event_decode_pco_ie    → LTE ESM, event handler, decode PCO IE
         ltecsr_tty_dl_count_blocks → VoLTE CS-over-RTP, real-time text, downlink, count blocks
```

### Prefix decoder (this firmware)
| Prefix / token | RAT | Layer / subsystem |
|---|---|---|
| `FDD_` / `TDD_` | 2G/3G | Frequency/Time-Division Duplex variant (mostly 2G RR & 3G here) |
| `FDD_rr_`, `_rr_` | 2G | Radio Resource (RR, L3 AS) |
| `FDD_rmc_` | 2G | RLC/MAC control (L2) |
| `FDD_reasm_` | 2G | RLC→LLC reassembly (L2) |
| `llc_` | 2G GPRS | Logical Link Control (L2) |
| `csn_` | 2G | CSN.1 codec |
| `RRC_`, `AsnDecode_RRC_` | 3G | UMTS RRC (L3 AS) + its ASN.1 decoders |
| `mm_`, `_cc_`, `gmm`, `sm_` | 2G/3G | CS/PS NAS (shared) |
| `smsal_` | all | SMS Abstraction Layer (TPDU/UDH/CB) |
| `errc_` | 4G | LTE RRC (L3 AS) — `errc_lsys_*` = system info, `errc_lcel_*` = cell/paging, `errc_cel_pwsrcv_*` = ETWS/CMAS |
| `erlc`, `epdcp`, `emac` | 4G | LTE RLC / PDCP / MAC (L2) |
| `emm_`, `CEmm...` | 4G | LTE EMM NAS (L3) — C++ classes like `CEmmSec` = EMM security |
| `esm_` | 4G | LTE ESM NAS (L3) |
| `AsnDecode_SystemInformationBlockType*` | 4G | LTE RRC SIB ASN.1 decoders |
| `nrrc`, `Nrrc`, `NL1_CTRL_Nrrc` | 5G | NR RRC (L3) + its L1-control glue |
| `AsnDecode_NR_*` | 5G | NR RRC ASN.1 decoders |
| `vgmm_` | 5G | 5GMM NAS (the `v` = 5G/NR here) |
| `vgsm_` | 5G | 5GSM NAS |
| `ltecsr_` | IMS | VoLTE "CS-over-RTP" (voice/RTT media on the modem) |
| `VOLTE_FM_`, `evs`, `amr` | IMS | VoLTE Frame Manager / codec depacketizers |

### Action verbs you'll see
`decode`/`unpack` (parse incoming bytes — **where bugs are**), `encode`/`pack`/`construct` (build
outgoing — re-serialization bugs possible, cf. F12), `handler`/`hdlr`/`ind`/`cnf`/`req` (message
handlers: indication/confirm/request), `set`/`get`, `reasm`/`reconstruct` (reassembly — buffers!),
`chk`/`validate` (checks — sometimes the *missing* check is the bug).

### Beginner tip: from a function name to "is this interesting?"
1. Prefix → RAT + layer (above).
2. Contains `decode`/`unpack`/`reasm` → it parses attacker bytes → **candidate**.
3. Handles a **broadcast/pre-auth** message (SIB, paging, CB, attach/identity) → **high value** (T0/T1).
4. Open it, look for a **length/count/index** read from the input used in a **copy/store** with **no
   bound** → that's the bug pattern behind almost every finding in this project.
