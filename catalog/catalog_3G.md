# Catalog — 3G (UMTS / WCDMA) function inventory

Target binary: Huawei `MD1IMG_22.img` → `000_md1rom`, symbolized, loaded in the IDA query
server (port 8799). Every command below is:

```
source /workspace/.venv-ida/bin/activate
python /workspace/idaq search   "<python-regex>" <limit>   # find functions by name
python /workspace/idaq decompile "<name|0xaddr>"           # sample behaviour
python /workspace/idaq xrefs     "<name|0xaddr>"           # callers/callees
```

> **Note on the search engine:** name matching is **case-insensitive** (`^rlc`, `^Rlc`
> and `^RLC` all return the same set). Counts below were obtained with
> `python /workspace/idaq search "<re>" 100000 | grep -c '"ea"'`.

---

## 0. What "3G" is, and how it is laid out in this firmware

3G = **UMTS** (Universal Mobile Telecommunications System), whose radio interface is
**WCDMA** (Wideband Code Division Multiple Access). It sits between 2G (GSM/GPRS) and 4G
(LTE) and reuses the same **NAS** core-network signalling as 2G (MM/GMM/CC/SM). The radio
stack follows the classic layering:

| OSI-style layer | 3GPP name | Job |
|---|---|---|
| **L1 / PHY** | WCDMA physical layer | Spreading/despreading, power control, channel coding, transport over the air. |
| **L2 — MAC** | Medium Access Control | Maps logical channels to transport channels, scheduling, HARQ (HS/E-DCH). |
| **L2 — RLC** | Radio Link Control | Segmentation/reassembly, ARQ retransmission (TM / UM / AM modes), ciphering. |
| **L2 — PDCP** | Packet Data Convergence Protocol | Header compression (ROHC) for PS data. |
| **L3 — RRC** | Radio Resource Control | The signalling brain: system info, connection setup, measurement, handover. **RRC messages are ASN.1/PER encoded.** |
| **L3 — NAS** | MM/GMM/CC/SM | Mobility, session and call-control — **shared with 2G** (see `catalog_2G.md`). |

### Naming conventions discovered in this DB

| Prefix / pattern | Meaning |
|---|---|
| `UL1*` / `ul1*` (`UL1I_`, `UL1T_`, `UL1D_`, `ul1a_`, `ul1d_`, `UL1SISR_`) | **UMTS L1** (WCDMA physical layer) driver/ISR code. |
| `UMAC*` / `umac_` / `lumac_` | **UMTS MAC** (L2). `lumac` = LTE-context/low MAC helpers, `TDD_lumac`/`FDD_UMAC` = mode-specific. |
| `URLC*` / `Urlc` / `urlc_` / `FDD_Urlc_*` | **UMTS RLC** (L2). `FDD_Urlc_UPlane_*` = user-plane AM/UM PDU processing. |
| `Pdcp*`, `RRC_PDCP_*`, `AsnDecode_RRC_PDCP_*` | **UMTS PDCP** (small) + PDCP-config IEs inside RRC. |
| `RRC_*` (~2161) | **UMTS RRC** layer — state machine, databases (`RRC_FDD_DB_*`), validators (`*_isValid`). |
| `AsnDecode_RRC_*` (~1316) / `AsnEncode_RRC_*` (~1346) | **UMTS RRC ASN.1/PER decoders / encoders** — the message parsers. |
| `getShortBits` / `getBits` / `GetUperLengthDeterminant` / `AsnDecodeAlloc` / `AsnError` | **PER runtime** — the shared bit-level engine the RRC decoders call. |
| `mm_ / gmm_ / cc_ / sm_` | **NAS**, shared 2G/3G — documented in `catalog_2G.md`. |
| `FDD_*` / `TDD_*` | Duplex-mode variants. ⚠️ In this Huawei DB `FDD_rr_*` / `FDD_acs_*` are actually **GSM RR/access** (see `catalog_2G.md`), while `FDD_Urlc_*`/`FDD_UMAC_*` are genuine WCDMA-FDD L2. Read the *middle* token, not just `FDD`. |

---

## 1. What ASN.1 / PER decoding is (beginner primer)

The most important attack surface in 3G is the **RRC message decoder**, so it helps to
understand the encoding.

- **ASN.1** (Abstract Syntax Notation One) is the language 3GPP uses to *describe* the
  shape of every RRC message: which fields exist, their types, ranges, whether they are
  optional, and how they nest. A `SysInfoType3` message, a `MeasurementReport`, a
  `RRCConnectionSetup` — each is one ASN.1 type.
- **PER** (Packed Encoding Rules) is how those messages are turned into bytes on the air.
  Unlike a C struct, PER is **bit-packed**: an optional field costs *1 bit* (a "presence
  bit"), an integer constrained to 0..7 costs *3 bits*, and lengths are stored as compact
  "length determinants". Nothing is byte-aligned, so you cannot just cast a pointer — you
  must walk the bitstream field by field.
- The **decoder** reverses this: it reads bits in the exact order the ASN.1 spec dictates,
  reconstructing the message into a C structure in RAM. In this firmware that job is done
  by the ~1316 `AsnDecode_RRC_*` functions, each one hand-generated for one ASN.1 type,
  all calling a shared bit-reading runtime (`getShortBits`, `getBits`, …).

**Why it matters for security:** the decoder parses *attacker-controlled* radio bytes
(a fake base station can send any RRC message). A length field read wrong, a missing
bounds check on an array count, or a presence-bit mishandled can corrupt the reconstructed
struct — classic memory-corruption territory. This is why the decoders are the primary
hunting ground.

### PER runtime (the shared engine)

Regexes: `getShortBits` → **86**, `getBits` → **8**, `GetUperLength` → **5**,
`AsnDecode.*Alloc` → **29** (includes `AsnDecodeAlloc`, `AsnRootDecodeAlloc`).

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `getShortBits` | 0x900901c0 | PER runtime | bit reader | Reads **≤24 bits** from the bitstream FIFO, refilling a byte at a time; calls `AsnError` on underflow. The core primitive. |
| `getBits` | 0x9009025a | PER runtime | bit reader | Reads **up to 32 bits** by splitting into two `getShortBits(…,24)` + remainder calls; `AsnError(…,7)` if >32 requested. |
| `GetUperLengthDeterminant` | (see search) | PER runtime | length | Decodes a PER **length determinant** (the compact 7-bit / 15-bit / fragmented length prefix) for SEQUENCE-OF / OCTET STRING sizes. |
| `AsnRootDecodeAlloc` / `AsnDecodeAlloc` | (see search) | PER runtime | memory | Allocates the output struct for a decode and registers it so a decode error can free it (`AsnDecodeFree`) via `setjmp`/`longjmp`. |
| `AsnError` | (called by above) | PER runtime | error | Central error path; `longjmp`s back to the top-level decoder's `setjmp` frame, unwinding a failed decode. |
| `initFifo` | (called by decoders) | PER runtime | setup | Points the bit-FIFO at the raw message buffer + length before decoding starts. |

Sample — the bit reader and a top-level SIB decoder (abridged), showing the pattern:

```c
// getBits @ 0x9009025a
unsigned int getBits(int *a1, unsigned int a2) {
  if (a2 >= 0x21) a1 = AsnError(a1, 7);           // > 32 bits => error
  else if (a2 < 0x19) return getShortBits(a1, a2); // <= 24 bits: one shot
  ShortBits = getShortBits(a1, 0x18u);             // else 24 + remainder
  return getShortBits(a1, a2 - 24) | (ShortBits << (a2 - 24));
}

// AsnDecode_RRC_SysInfoType3 @ 0x90041986  (abridged)
  if (setjmp(v12)) { AsnDecodeFree(...); ... }     // error-unwind frame
  else {
    AsnRootDecodeAlloc(v11, a1, 812);              // alloc 812-byte struct
    initFifo(v11, a2, (*a3 + 7) >> 3);             // aim FIFO at msg bytes
    *v6      = getShortBits(v11, 1u);              // read 1 presence bit
    v6[1]    = getShortBits(v11, 1u);              // read 1 presence bit
    AsnDecode_RRC_CellIdentity(v6 + 2, v11);       // nested IE decode
    AsnDecode_RRC_CellSelectReselectInfoSIB_3_4(v6 + 7, v11);
    if ((*v6 & 1) != 0) { ... v4b0ext ... }        // optional extension chains
```

This `setjmp` + `Alloc` + `initFifo` + per-field `getShortBits`/nested-`AsnDecode`
skeleton is repeated across **all ~1316 decoders**.

---

## 2. L1 — WCDMA physical layer

Handles the WCDMA air interface (spreading codes, power control, transport-channel
coding, measurement gaps, cell/RAT switching). This is driver-level DSP/ISR code, not a
message parser, so it is a smaller review priority than RRC — but it is where inter-RAT
gap and measurement resources are managed.

Regexes: `^UL1` → **6260** (the umbrella count; includes ISR, timing, RF, CCM),
`l1.*umts` → **29**, `wcdma` → **39**, `uphy` → **0** (no `uphy` prefix in this build).

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `UL1I_GetLatestTiming` | (search) | L1 | WCDMA timing | Returns current cell timing snapshot for the L1 scheduler. |
| `UL1I_Send_IntraFreqChangeRpt` | (search) | L1 | measurement | Reports intra-frequency cell changes up to higher layers. |
| `UL1I_ChannelPriorityAdjust` | (search) | L1 | scheduling | Adjusts physical-channel priority (multi-SIM arbitration, `CCM`). |
| `ul1d_query_is_umts_in_dch_state` | (search) | L1 | state query | Tells upper layers whether L1 is in dedicated-channel (DCH) mode. |
| `UL1D_UMTS_Is_In_Dedi_Mode` | (search) | L1 | state query | Dedicated-mode check used for gap/handover decisions. |
| `UL1T_LidToUmtsBand` / `UL1D_RF_UMTSBandToHLB` | (search) | L1 | RF band map | Maps logical-channel/UMTS band id to RF hardware band. |
| `UL1I_UpdateInterSIMUMTSResource` | (search) | L1 | inter-SIM | Reserves/updates UMTS L1 resources shared between SIMs. |
| `l1a_handover_from_umts_active_gap_req` | (search) | L1 | inter-RAT gap | Requests measurement gaps when handing **out of** UMTS. |
| `mll1_umts_fdd_handler` / `mll1_umts_tdd_handler` | (search) | L1 | mode dispatch | Top dispatch for FDD vs TDD UMTS L1 events. |
| `ul1a_cm_utility_GetCurrentUMTSInterFreqNum` | (search) | L1 | compressed mode | Counts inter-frequency neighbours for compressed-mode measurement. |
| `ul1d_nvram_read_umts_category` | (search) | L1 | config | Reads UE UMTS category from NVRAM (caps HS/DCH rates). |

*(The `^UL1` 6260 total is dominated by ISR/timing/RF plumbing; the rows above are chosen
to show the functional groups — timing, state, RF band, inter-SIM, inter-RAT gaps.)*

---

## 3. L2 — MAC (Medium Access Control)

Maps logical channels onto WCDMA transport channels (RACH/FACH/DCH/HS-DSCH/E-DCH),
handles HARQ for HSPA, and moves PDUs to/from RLC.

Regexes: `umac` → **107**, `^umac` (prefix, incl. `UMAC`) → **16**, `umac_` → **94**,
`^mac_` → **9** (mostly generic, not UMTS).

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `UMAC_ReCalActCFN` | (search) | L2-MAC | timing | Recomputes the Activation Connection Frame Number for reconfig. |
| `UMAC_QP_3G_DL_MAC_COPY` | (search) | L2-MAC | DL path | Copies a downlink MAC PDU from HW queue into SW buffers. |
| `UMAC_CP_VB_RELEASE` | (search) | L2-MAC | buffers | Releases a virtual-buffer (VB) MAC PDU descriptor. |
| `umac_dch_lisr_entry` | (search) | L2-MAC | DCH ISR | Low-ISR entry for dedicated-channel MAC ticks. |
| `umac_csr_lisr_entry` | (search) | L2-MAC | common ISR | Low-ISR for common (RACH/FACH) scheduling. |
| `umac_dch_csr_edch_hisr_entry` | (search) | L2-MAC | E-DCH ISR | High-ISR combining DCH/CSR/E-DCH (HSUPA) handling. |
| `umac_r99_get_tx_data_buffer` | (search) | L2-MAC | R99 UL | Gets a TX buffer for Release-99 uplink data. |
| `lumac_pch_get_variable_pdu_buffer` | (search) | L2-MAC | PCH | Allocates a paging-channel PDU buffer. |
| `lumac_to_lurlc_data_ind` | (search) | L2-MAC↔RLC | data ind | Delivers a received MAC SDU up to RLC. |
| `FDD_Urlc_Umac_Deliver_R99_Pdu` | (search) | L2-MAC↔RLC | DL delivery | Hands a decoded R99 PDU from MAC to RLC (FDD). |
| `FDD_Send_EM_UMAC_CONFIG_INFO_HSDSCH_IND` | (search) | L2-MAC | HS-DSCH cfg | Sends HS-DSCH (HSDPA) config indication for engineering-mode/telemetry. |
| `FTA_UMAC_UL_DCH_Tick_Low_Lisr` | (search) | L2-MAC | UL tick | Per-TTI uplink DCH tick handler. |

---

## 4. L2 — RLC (Radio Link Control)

Segments/reassembles RLC SDUs into PDUs, runs ARQ retransmission in AM (Acknowledged
Mode), and applies ciphering. The **user-plane AM/UM PDU processing** path
(`FDD_Urlc_UPlane_*`) parses PDU headers and sequence numbers from received data — a
notable non-RRC attack surface.

Regexes: `urlc` → **213**, `FDD_Urlc` (case-insensitive, catches `FDD_Urlc_*`,
`FDD_urlc_*`, `FDD_URLC*`) → dozens. Note `rlc`/`RLC` → **2012** and `_rlc` → **871**
mostly hit **LTE (`erlc`) and NR (`nrlc`) RLC** — filter to the `urlc`/`Urlc` family for
3G.

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `FDD_Urlc_UPlane_ProcessAMPDU` | (search) | L2-RLC | AM RX | Parses/processes a received Acknowledged-Mode PDU (SN, polling, data). |
| `FDD_Urlc_UPlane_ExtractAM_RX_PULength` | (search) | L2-RLC | AM RX | Extracts payload-unit length fields from an AM PDU header. |
| `FDD_Urlc_UPlane_Find1stMissingSN` | (search) | L2-RLC | AM ARQ | Finds first missing sequence number → drives status/retransmit. |
| `FDD_Urlc_UPlane_AMReestablish` | (search) | L2-RLC | AM reset | Re-establishes an AM entity (reset SN state, buffers). |
| `FDD_Urlc_UPlane_GetNewVRR_After_SN_MRW` | (search) | L2-RLC | AM window | Recomputes receive window after a Move-Receiving-Window (MRW). |
| `FDD_urlc_fill_am_dsc` | (search) | L2-RLC | AM TX | Fills an AM PDU descriptor for transmission. |
| `FDD_urlc_alloc_rx_ciphering_into_rb` | (search) | L2-RLC | ciphering | Binds an RX ciphering context to a radio bearer. |
| `FDD_Urlc_UPlane_GetDecipherKeyIdx` | (search) | L2-RLC | ciphering | Selects the decipher key index for an incoming PDU. |
| `FDD_URLCDeleteAmPdu` / `FDD_URLCDeleteTmPdu` | (search) | L2-RLC | buffers | Frees AM / Transparent-Mode PDU buffers. |
| `FDD_URLCCompareRBID` | (search) | L2-RLC | routing | Matches a PDU to its radio-bearer id. |
| `FDD_urlc_tx_cb_edch_tick1_LISR` | (search) | L2-RLC | E-DCH TX | Per-tick TX callback for E-DCH (HSUPA). |
| `lumac_to_lurlc_data_ind` | (search) | MAC→RLC | data ind | (Cross-ref) MAC delivering an SDU into RLC. |

---

## 5. L2 — PDCP (Packet Data Convergence Protocol)

Small in UMTS (mainly ROHC header compression for PS bearers). Most `PDCP` hits are
either **RRC IEs describing PDCP config** (`AsnDecode_RRC_PDCP_*`) or **LTE PDCP**
(`epdcp`). The genuine UMTS PDCP runtime is just a handful of `Pdcp*` functions.

Regex: `PDCP` → **734** (mostly RRC-IE + LTE); UMTS-specific `Pdcp*` runtime ≈ a few.

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `PdcpCheckShaqStatus` | 0x9008feee | L2-PDCP | status | Checks PDCP queue ("shaq") status; dispatches to `FDD_PdcpCheckShaqStatus`. |
| `PdcpUpdateSendSN` | (search) | L2-PDCP | sequencing | Updates the PDCP send sequence number. |
| `AsnDecode_RRC_PDCP_Info` | (search) | L3-RRC (PDCP cfg) | IE decoder | Decodes the PDCP-Info IE (RB-level PDCP/ROHC config) from RRC. |
| `AsnDecode_RRC_PDCP_ROHC_TargetMode` | (search) | L3-RRC (PDCP cfg) | IE decoder | Decodes ROHC target-mode IE. |
| `AsnDecode_RRC_RB_WithPDCP_InfoList` | (search) | L3-RRC (PDCP cfg) | IE decoder | Decodes the list of radio bearers that carry PDCP. |
| `RRC_PDCP_Info_headerCompressionInfoList_isValid` | (search) | L3-RRC | validator | Sanity-checks the decoded header-compression list. |

---

## 6. L3 — RRC (Radio Resource Control): the main attack surface

RRC is the largest and most security-relevant 3G component. It has two halves:

1. **State machine / databases / validators** — `RRC_*`, total **`^RRC_` → 2161**. These
   hold the decoded system-information databases (`RRC_FDD_DB_*`), per-field validators
   (`*_isValid`), and procedure logic.
2. **ASN.1/PER message codecs** — **`AsnDecode_RRC_*` → 1316** decoders (+ `AsnEncode_RRC_*`
   → **1346** encoders). The decoders parse attacker-reachable radio bytes; this is the
   #1 hunting ground (see §1 for why).

Below the decoders are broken out by functional group.

### 6a. System Information / SIB decoders

Broadcast messages every UE reads from *any* cell it camps on (including a rogue cell) —
so these run on unauthenticated, attacker-controlled input very early.

Regexes: `AsnDecode_RRC_Sys` → **63**, `AsnDecode_RRC_.*SIB` → **20**,
`CompleteSIB` → **3**.

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `AsnDecode_RRC_SysInfoType1` | (search) | L3-RRC | SIB1 | Decodes SIB1 (NAS/timers). |
| `AsnDecode_RRC_SysInfoType3` | 0x90041986 | L3-RRC | SIB3 | Decodes SIB3 (cell selection/reselection + `_v4b0`/`_v590`/`_v5c0` extension chains). |
| `AsnDecode_RRC_SysInfoType5` | (search) | L3-RRC | SIB5 | Decodes SIB5 (common physical-channel config) — many version ext variants. |
| `AsnDecode_RRC_SysInfoType11` / `..Type12` | (search) | L3-RRC | SIB11/12 | Measurement control system info (neighbour lists). |
| `AsnDecode_RRC_SysInfoType18` | (search) | L3-RRC | SIB18 | PLMN identities for cell reselection. |
| `AsnDecode_RRC_SysInfoTypeSB1` / `..SB2` | (search) | L3-RRC | SB1/SB2 | Scheduling blocks (which SIBs are scheduled when). |
| `AsnDecode_RRC_System_Information_Container` | (search) | L3-RRC | container | Top-level SI container that dispatches to per-type decoders. |
| `AsnDecode_RRC_CompleteSIB_List` | (search) | L3-RRC | SIB assembly | Reassembles segmented SIBs into complete blocks before decode. |
| `AsnDecode_RRC_SIB_TypeAndTag` | (search) | L3-RRC | SIB header | Reads SIB type + value tag. |
| `AsnDecode_RRC_CellSelectReselectInfoSIB_3_4` | (search) | L3-RRC | SIB3/4 IE | Cell (re)selection thresholds (Qrxlevmin, etc.). |
| `AsnDecode_RRC_CellSelectReselectInfoSIB_11_12_RSCP` | (search) | L3-RRC | SIB11/12 IE | Reselection info keyed on RSCP measurement quantity. |
| `AsnDecode_RRC_SIB_Data_variable` | (search) | L3-RRC | SIB body | Decodes the variable-length raw SIB payload. |

### 6b. Connection management

Regex: `AsnDecode_RRC_RRCConnection` → **17**.

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `AsnDecode_RRC_RRCConnectionSetup_v590ext_IEs` | (search) | L3-RRC | conn setup | Decodes RRCConnectionSetup (network grants RRC connection) extension IEs. |
| `AsnDecode_RRC_RRCConnectionSetupComplete_v380ext_IEs` | (search) | L3-RRC | conn setup | SetupComplete extension IEs (many version variants v3a0/v3g0/v590/…). |
| `AsnDecode_RRC_RRCConnectionRelease_r3_IEs` | (search) | L3-RRC | conn release | Decodes RRCConnectionRelease (network tears down connection). |
| `AsnDecode_RRC_RRCConnectionRelease_v690ext_IEs` | (search) | L3-RRC | conn release | Release extension IEs (redirect info etc.). |
| `AsnDecode_RRC_RRCConnectionSetupCompleteBand_va40ext_IEs` | (search) | L3-RRC | conn setup | Supported-band info inside SetupComplete. |

*(`RRCConnectionRequest` and other UL messages appear on the **encode** side
`AsnEncode_RRC_*`; the decoders here are the DL messages the UE parses.)*

### 6c. Measurement & handover / inter-RAT

Measurement control tells the UE what/when to measure; handover and inter-RAT messages
move the UE between cells/RATs — all parsed from network input during an active
connection.

Regexes: `AsnDecode_RRC_Meas` → **30**, `InterRAT` → **298** (all layers),
`Handover` → **424** (all layers). The RRC-decoder slice is `AsnDecode_RRC_.*InterRAT` /
`AsnDecode_RRC_.*Handover`.

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `AsnDecode_RRC_MeasurementControl` | (search) | L3-RRC | meas | Decodes MeasurementControl (adds/modifies/removes measurements). |
| `AsnDecode_RRC_MeasurementControl_v590ext_IEs` | (search) | L3-RRC | meas | Version-extension IEs of MeasurementControl. |
| `AsnDecode_RRC_MeasuredResults` | (search) | L3-RRC | meas | Decodes measured-results structure (also used in reports). |
| `AsnDecode_RRC_MeasurementReport` | (search) | L3-RRC | meas | Decodes a MeasurementReport message. |
| `AsnDecode_RRC_MeasurementQuantityEUTRA` / `..GSM` | (search) | L3-RRC | inter-RAT meas | Decodes measurement-quantity IEs for LTE/GSM neighbours. |
| `AsnDecode_RRC_CellsForInterRATMeasList` | (search) | L3-RRC | inter-RAT | Neighbour-cell list for inter-RAT measurement. |
| `AsnDecode_RRC_InterRATHandoverInfo_v3a0ext_IEs` | (search) | L3-RRC | inter-RAT HO | Decodes InterRATHandoverInfo (handover to/from GSM/LTE) — 15+ version variants. |
| `AsnDecode_RRC_InterRATReportCriteria` | (search) | L3-RRC | inter-RAT | Reporting criteria (events/thresholds) for inter-RAT. |
| `AsnDecode_RRC_MeasurementValidity_ue_State` | (search) | L3-RRC | meas | UE-state condition under which a measurement stays valid. |

### 6d. UE capability

Regexes: `UE_RadioAccess` → **75**, `UECapability` → **47** (both decode + encode halves).

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `AsnDecode_RRC_UE_RadioAccessCapability` | (search) | L3-RRC | UE cap | Decodes the UE radio-access capability structure. |
| `AsnDecode_RRC_UE_RadioAccessCapabBandFDDList` | (search) | L3-RRC | UE cap | Decodes supported FDD-band list (variants List3/4/6/7 + version exts). |
| `AsnDecode_RRC_UE_RadioAccessCapability_v590ext` | (search) | L3-RRC | UE cap | HSPA-era capability extensions. |
| `AsnDecode_RRC_UECapabilityInformation_v380ext_IEs` | (search) | L3-RRC | UE cap msg | Decodes UECapabilityInformation message extensions. |
| `AsnDecode_RRC_UECapabilityInformation_TDD128ext_IEs` | (search) | L3-RRC | UE cap msg | TD-SCDMA (LCR TDD) capability extensions. |

*(UE capability is mostly UE→network — many of these have `AsnEncode_RRC_*` twins the UE
uses to build its own report; the decoders exist because capability info is also relayed
in InterRATHandoverInfo.)*

### 6e. Paging

Regexes: `AsnDecode_RRC_Paging` → **5**, `PCCH` → **92** (all layers).

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `AsnDecode_RRC_PagingCause` | (search) | L3-RRC | paging | Decodes the paging cause enum. |
| `AsnDecode_RRC_PagingRecordTypeID` | (search) | L3-RRC | paging | Decodes the paged-identity type (IMSI/TMSI/etc.). |
| `AsnDecode_RRC_PagingIndicatorLength` | (search) | L3-RRC | paging | Decodes the paging-indicator length parameter. |
| `AsnDecode_RRC_PagingPermissionWithAccessControlParameters` | (search) | L3-RRC | paging | PPAC parameters (access-control gating during paging). |

Paging is delivered on **PCCH** (broadcast, unauthenticated) — like SIBs, it runs on
attacker-reachable input, so despite being only 5 decoders it is high-value.

### 6f. RRC state machine / databases (non-ASN.1)

Not message parsers, but the logic that *consumes* decoded messages. Representative from
`^RRC_` (2161 total, minus the ~1316 `AsnDecode_` + encode twins):

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `RRC_FDD_DB_Cell_Unsuitable_cell_barred_isValid` | 0x9008c144 | L3-RRC | cell selection | Validator: is the "cell barred" DB field valid/set. |
| `RRC_FDD_DB_Scheduling_Flag_sib3_scheduled_isValid` | (search) | L3-RRC | SI scheduling | Tracks whether SIB3 is scheduled in the current cell. |
| `RRC_FDD_DB_HS_PDSCH_selected_common_h_rnti_Index_isValid` | (search) | L3-RRC | HSDPA | Validates the selected common H-RNTI index. |
| `RRC_FDD_DB_InterRAT_CellReselection_Info_ncMode_isValid` | (search) | L3-RRC | inter-RAT | Validates network-controlled reselection mode field. |
| `RRC_PDCP_Info_losslessSRNS_RelocSupport_isValid` | (search) | L3-RRC | PDCP cfg | Validates lossless SRNS-relocation support flag. |

---

## 7. Security (AS-layer)

3G integrity/ciphering setup (RRC SecurityModeCommand → RLC/MAC ciphering).

Regexes: `SecurityMode` → **12**, `IntegrityProtection` → **42**.

| function | addr | layer | sublayer | what it does |
|---|---|---|---|---|
| `AsnDecode_RRC_SecurityModeCommand*` | (search `SecurityMode`) | L3-RRC | AS security | Decodes SecurityModeCommand (network selects ciphering/integrity algos). |
| `*IntegrityProtection*` IEs | (search `IntegrityProtection`) | L3-RRC | AS security | Integrity-protection mode/config IEs carried in RRC. |
| `FDD_urlc_alloc_rx_ciphering_into_rb` | (search) | L2-RLC | ciphering | (Cross-ref §4) actual RLC-layer decipher context. |

---

## 8. NAS (MM / GMM / CC / SM) — shared with 2G

3G reuses the **same** Non-Access-Stratum core-network signalling as 2G/GPRS; there is no
separate 3G NAS in this build. These are documented in **`catalog_2G.md`** — the
3G-relevant ones are:

| prefix | count (`^prefix`) | protocol | relevance to 3G |
|---|---|---|---|
| `mm_` | 748 | **MM** (Mobility Management, CS) | Location update / authentication / TMSI over UMTS CS. |
| `gmm_` | 433 | **GMM** (GPRS MM, PS) | Attach / RAU / P-TMSI over UMTS PS. |
| `cc_` | 501 | **CC** (Call Control) | CS voice/video call setup over UMTS. |
| `sm_` | 556 | **SM** (Session Management) | PDP-context (PS data bearer) activation over UMTS. |

These NAS messages are carried **inside** RRC (Direct Transfer procedures) but are
encoded with the 2G-style TLV NAS encoding, **not** ASN.1/PER — so the decode path is
`RRC_* → NAS L3` and reviewing them belongs with the 2G catalog. See `catalog_2G.md` for
the per-function tables.

---

## 9. Summary — regex → count cheat-sheet

| regex | count | layer / group |
|---|---:|---|
| `^UL1` | 6260 | L1 WCDMA PHY (umbrella) |
| `l1.*umts` | 29 | L1 UMTS helpers |
| `wcdma` | 39 | multi-RAT WCDMA refs |
| `umac` | 107 | L2 MAC |
| `umac_` | 94 | L2 MAC (funcs) |
| `urlc` | 213 | L2 RLC |
| `PDCP` | 734 | L2 PDCP + RRC PDCP IEs (mostly LTE/RRC) |
| `^RRC_` | 2161 | L3 RRC (all) |
| `AsnDecode_RRC_` | 1316 | **L3 RRC ASN.1/PER decoders** |
| `AsnEncode_RRC_` | 1346 | L3 RRC ASN.1/PER encoders |
| `AsnDecode_RRC_Sys` | 63 | SIB / system-info decoders |
| `AsnDecode_RRC_.*SIB` | 20 | SIB IE decoders |
| `CompleteSIB` | 3 | SIB reassembly |
| `AsnDecode_RRC_RRCConnection` | 17 | connection-management decoders |
| `AsnDecode_RRC_Meas` | 30 | measurement decoders |
| `InterRAT` | 298 | inter-RAT (all layers) |
| `Handover` | 424 | handover (all layers) |
| `UE_RadioAccess` | 75 | UE capability |
| `UECapability` | 47 | UE capability messages |
| `AsnDecode_RRC_Paging` | 5 | paging decoders |
| `PCCH` | 92 | paging channel (all layers) |
| `getShortBits` | 86 | PER runtime bit reader |
| `getBits` | 8 | PER runtime bit reader |
| `GetUperLength` | 5 | PER length determinant |
| `AsnDecode.*Alloc` | 29 | PER decode allocator |
| `SecurityMode` | 12 | AS security |
| `IntegrityProtection` | 42 | AS security |
| `^mm_` / `^gmm_` / `^cc_` / `^sm_` | 748 / 433 / 501 / 556 | NAS (shared 2G — see `catalog_2G.md`) |

**Top attack surface for 3G:** the **`AsnDecode_RRC_*` (1316)** PER decoders — especially
the broadcast/unauthenticated ones (SIB §6a, Paging §6e) that parse rogue-cell input
before any security is established — all riding on the shared bit-reader runtime
(`getShortBits`/`getBits`, §1).
