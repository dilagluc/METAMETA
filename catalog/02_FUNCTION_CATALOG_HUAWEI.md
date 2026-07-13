# Function Catalog & Identification Method — Huawei MediaTek modem (symbolized)

This file explains **how to identify which function belongs to which RAT (2G/3G/4G/5G) and which layer**,
and gives the **master command/regex cheat-sheet**. The full per-layer function tables live in the
companion files `catalog_2G.md`, `catalog_3G.md`, `catalog_4G.md`, `catalog_5G.md`, `catalog_cross.md`
(each: `function | addr | layer | protocol | what it does`). Read `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` first for
the concepts and `../fundamentals/03_GLOSSARY_AND_NAMING.md` for the naming conventions.

Target: `MD1IMG_22.img` → `000_md1rom`, **debug-symbolized** (this is why name-based search works; the
Samsung build is stripped, so it needs string-anchoring instead).

---

## 1. The method — how these functions were identified

Everything runs against a persistent IDA query server over the symbolized DB:
```bash
source /workspace/.venv-ida/bin/activate
python /workspace/idaq search   "<python-regex>" <limit>   # find functions by NAME (case-insensitive)
python /workspace/idaq decompile "<name|0xaddr>"           # read what a function actually does
python /workspace/idaq disasm    "<name|0xaddr>"           # nanoMIPS assembly
python /workspace/idaq xrefs     "<name|0xaddr>"           # callers / callees (trace up/down a layer)
python /workspace/idaq strxref   "<regex>"                 # (fallback) find funcs via a source-path string
```
Three-step identification:
1. **Anchor on the name prefix** (RAT+layer) — the tables below. `idaq search "^errc_" 5000` etc.
2. **Verify with a decompile** of a few samples — never trust the name alone; confirm it parses OTA bytes.
3. **Trace with xrefs** — follow callers to find the message entry point, callees to find the sink.

Fallbacks when a name is ambiguous:
- **Source-path strings** (`strxref`): MediaTek keeps `.c` paths, e.g. `protocol/lte_sec/enas/esm/…`,
  `l1/nl1/…`, `protocol/2g/gas/…` — anchor on those to disambiguate a subsystem.
- **Read the MIDDLE token, not just `FDD_`:** `FDD_rr_*` = **GSM (2G)** RR, but `FDD_Urlc_*`/`FDD_UMAC_*` =
  **WCDMA (3G)** L2. The `FDD/TDD` token is a duplex mode, not a RAT.

Caveats the cataloguers verified (don't get fooled):
- `FDD_rmc_` is **RR mobility/measurement (L3)**, NOT MAC/RLC. Real GPRS L2 = `FDD_mac_`/`FDD_rlc_`/`FDD_rmpc_`.
- `eia`/`eea` mostly match unrelated **AT-command** handlers, not crypto — the real integrity/ciphering is
  under `CEmmSec::`, `l2_cp_int_nas`, `CHE_AES_*`.
- Bare substrings over-match across RATs (`rlc`=2012, `psi`=242, `pdcp`=734 span multiple generations) —
  use the anchored prefix (`^erlc`, `^nrlc`, `FDD_psi`) instead.
- `search` is **case-insensitive**.

---

## 2. Master cheat-sheet: regex → RAT / layer (with live counts)

Copy-paste these. Counts are the number of matching functions in this firmware (shows you the scale).

### 2G — GSM (CS) + GPRS/EGPRS (PS)   → detail in `catalog_2G.md`
| Layer | Regex (`idaq search "…"`) | ~Count | What it is |
|---|---|---|---|
| L1 PHY | `l1a_gsm`, `^L1[DIT]_`, `cbch` | 81 / — / 94 | GSM physical-layer control; CBCH scheduling |
| L2 MAC | `^FDD_mac_` | 380 | GPRS MAC |
| L2 RLC | `^FDD_rlc_`, `^FDD_reasm_` | 234 / 17 | GPRS RLC + RLC→LLC reassembly |
| L2 pkt-ctrl | `^FDD_rmpc_` | 343 | Packet radio control |
| L2 LLC | `^llc_` | 168 | Logical Link Control (GPRS) |
| L2 SNDCP | `sndcp`, `ratdm_sndcp` | 18 | Packet convergence |
| codec | `^[Cc]sn` | 14 | CSN.1 bit codec |
| L3 RR | `^FDD_rr_`, `^TDD_rr_`, `^FDD_acs_` | 510 / 469 / 49 | Radio Resource (SI, paging, immediate assign) |
| L3 RR SI | `^FDD_si`, `^FDD_psi` | 231 / 20 | System / Packet-System Information decoders |
| L3 NAS (shared 2G/3G) | `^mm_`, `^cc_`, `^gmm_`, `^sm_` | 748 / 501 / 433 / 556 | MM, CC, GMM, SM |
| SMS | `^smsal_`, `smsal_cb_` | 592 / 37 | SMS abstraction + Cell Broadcast |

### 3G — UMTS/WCDMA   → detail in `catalog_3G.md`
| Layer | Regex | ~Count | What it is |
|---|---|---|---|
| L1 PHY | `^UL1`, `wcdma` | 6260 / 39 | WCDMA physical layer |
| L2 MAC | `umac` | 107 | UMTS MAC |
| L2 RLC | `urlc`, `FDD_Urlc_UPlane` | 213 | UMTS RLC (incl. user-plane PDU parsers) |
| **L3 RRC** | `^RRC_` | **2161** | UMTS Radio Resource Control |
| **L3 RRC decoders** | `^AsnDecode_RRC_` | **1316** | **ASN.1/PER message decoders — #1 attack surface** |
| ↳ SIB | `AsnDecode_RRC_Sys`, `CompleteSIB` | 63+ | System Information decoders (broadcast, T0) |
| ↳ meas/handover | `AsnDecode_RRC_Meas`, `InterRAT`, `Handover` | 298 / 424 | Measurement / handover |
| ↳ capability | `UE_RadioAccess`, `UECapability` | 75 | UE capability |
| ↳ paging | `AsnDecode_RRC_Paging`, `PCCH` | 5 | Paging (broadcast) |
| PER runtime | `getShortBits`, `getBits`, `GetUperLength`, `AsnDecodeAlloc` | 86 / 8 / 5 / 29 | The shared bit-reader/allocator every decoder uses |
| security | `SecurityMode`, `IntegrityProtection` | 12 / 42 | AS security mode |

### 4G — LTE   → detail in `catalog_4G.md`
| Layer | Regex | ~Count | What it is |
|---|---|---|---|
| L1 PHY | `^el1_` (`el1_meas`,`el1_irt`,`el1_csr`) | 1799 | LTE physical-layer control |
| L2 MAC | `^emac` | 586 | LTE MAC |
| L2 RLC | `^erlcdl`, `^erlcul` | 86 / 85 | LTE RLC downlink/uplink (reassembly) |
| L2 PDCP | `^epdcp` | 60 | LTE PDCP (ciphering/integrity/ROHC) |
| **L3 RRC** | `^errc_` | **5719** | LTE RRC (`errc_cel` 1729, `errc_mob` 1427, `errc_conn` 435) |
| ↳ dispatch | `errc_asn1_decoder` | — | ASN.1 message dispatcher |
| ↳ SIB | `AsnDecode_SystemInformationBlockType` | 15 | LTE SIB decoders (broadcast, T0) |
| ↳ ETWS/CMAS | `errc_cel_pwsrcv_` | 40 | Public Warning System receiver (broadcast) |
| **L3 NAS EMM** | `CEmm`, `^emm_` | 3004 / 81 | EPS Mobility Mgmt (C++ classes: `CEmmReg/Conn/Sec/…`) |
| **L3 NAS ESM** | `^esm_` | 618 | EPS Session Mgmt (bearer/PCO/TFT/QoS) |
| NAS codec | `mcd_unpack` | 51 | Table-driven NAS IE unpack engine |

### 5G — NR   → detail in `catalog_5G.md`
| Layer | Regex | ~Count | What it is |
|---|---|---|---|
| L1 control | `^nl1`, `^nl1_ctrl` (`NL1_CTRL`) | 5920 / 852 | NR L1 control; SI/BCCH/paging glue `NL1_CTRL_Nrrc_*` |
| L2 MAC | `^nmac` | 384 | NR MAC |
| L2 RLC | `^nrlc` | 381 | NR RLC |
| L2 PDCP | `^npdcp` | 388 | NR PDCP |
| L2 SDAP | `sdap` | 27 | QoS-flow mapping (5G-only) |
| **L3 RRC** | `[Nn]rrc`, `nrrc_asn1_decode` | 2664 | NR Radio Resource Control |
| **L3 RRC decoders** | `^AsnDecode_NR_` | 108 | NR ASN.1 decoders (SIB1/MIB/PCCH/BCCH) |
| **L3 NAS 5GMM** | `^vgmm_` | 765 | 5G Mobility Mgmt |
| **L3 NAS 5GSM** | `^vgsm_` | 591 | 5G Session Mgmt |

### Cross-cutting (IMS / SMS / security)   → detail in `catalog_cross.md`
| Subsystem | Regex | ~Count | What it is |
|---|---|---|---|
| IMS/VoLTE media | `^ltecsr_`, `rtp`, `rtcp`, `evs`, `amr`, `VOLTE_FM` | 319 / 439 / 124 / 295 / 155 / 32 | RTP/RTCP + codec depacketizers (modem side) |
| IMS signalling | `sip`, `sdp`, `atp_imc` | 701 / 247 / 91 | SIP/SDP shuttling (**text parsing is AP-side**) |
| SMS | `^smsal_`, `tpdu` | 592 / 21 | SMS transport + CB |
| Security (crypto) | `CEmmSec`, `chkIntegrity`, `aka`, `milenage`, `kdf`, `CHE_AES` | 171 / 1 / 116 / 6 / 37 / — | NAS integrity/ciphering, authentication |

---

## 3. The findings, mapped to RAT / layer / function

This connects the catalog to the actual vulnerabilities (see `/workspace/CONSOLIDATED_FINDINGS.md`):

| # | RAT | Layer | Subsystem | Vulnerable function (Huawei) |
|---|---|---|---|---|
| F1 | 2G (C2K) | L3 NAS | SMS (CDMA2000) | `ValSmsProcessDeliverParaMsg` |
| F2 | IMS/4G | media | VoLTE Real-Time Text | `ltecsr_tty_dl_count_blocks` |
| F3 | 4G | L3 NAS | ESM PCO | `esm_event_decode_pco_ie` |
| F4 | 5G | L3 NAS | 5GMM LADN | `vgmm_decode_ladn_info` |
| F5 | 5G | L3 NAS | 5GMM Emergency# | `vgmm_decode_emergency_number_list` |
| F6/F9 | 5G | L1→RRC | NR SI reassembly | `NL1_CTRL_Nrrc_Reconstruct_Raw_Data` |
| F7 | IMS/4G | media | EVS voice codec | `VOLTE_FM_EVS_HF_CountFrames` |
| F8 | 2G | cross | GSM Cell Broadcast | `smsal_decode_cb_page` |
| F10 | 2G | L3 RR | GSM SI neighbour list | `FDD_rr_decode_eutran_pcid_group_ie` |
| F11 | 5G | L3 NAS | 5GMM Access Category | `vgmm_set_op_def_access_category_definitions` |
| F12 | 4G | L3 NAS | ESM PCO re-serialization | `esm_cmn_copy_esm_pco_to_pco` |
| F13 | 4G | L3 NAS | EMM security (integrity) | `CEmmSec::chkIntegrity` |

Pattern to notice: bugs cluster in **NAS IE decoders (L3)**, **RRC/SI reassembly (L3/L1 broadcast)**, and
**IMS media depacketizers** — exactly the layers that parse attacker-controlled variable-length data.

---

## 4. Explore it yourself (beginner exercise)
```bash
source /workspace/.venv-ida/bin/activate
# 1. list all 5G session-management functions:
python /workspace/idaq search "^vgsm_" 800
# 2. find the ones that DECODE (parse attacker input):
python /workspace/idaq search "vgsm_decode" 200
# 3. open one and look for a length/count used without a bound:
python /workspace/idaq both "vgmm_decode_ladn_info"
# 4. see who calls it (trace to the message entry point):
python /workspace/idaq xrefs "vgmm_decode_ladn_info"
```
Rule of thumb: **prefix → RAT+layer** (§2) · **`decode`/`unpack`/`reasm` → parses attacker bytes** ·
**broadcast/pre-auth message → high value** · **length/count/index without a bound → the bug**.
