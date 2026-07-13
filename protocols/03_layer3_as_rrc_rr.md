# L3 Access-Stratum control: GSM RR, UMTS/LTE/NR RRC

This file covers the **Access-Stratum (AS) Layer-3** control protocol — the one that decides *which cell
you camp on, how you get a radio channel, and how the radio connection is configured*. Every generation
has one: **2G calls it RR** (Radio Resource), **3G/4G/5G all call it RRC** (Radio Resource Control). It
sits on **L3**, directly above L2 (RLC/MAC — see `02_layer2_*`) and below the **NAS** (core-network
signalling, TS 24.xxx — see the NAS file). For the big picture and the L1/L2/L3 model, read
`../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` (§1–§3). Bit-level encoding rules (ASN.1/UPER packing, CSN.1 bit-readers)
live in the **encodings reference** — here we show the *logical* message structure and cite where the
bit-level detail is.

## Table of contents
- [Shared intro — what RRC/RR does, and the message categories](#shared-intro)
- [GSM RR — 2G Radio Resource](#gsm-rr)
- [UMTS RRC — 3G Radio Resource Control](#umts-rrc)
- [LTE RRC — 4G Radio Resource Control](#lte-rrc)
- [NR RRC — 5G Radio Resource Control](#nr-rrc)

---

<a name="shared-intro"></a>
## Shared intro — what RRC/RR does and its message categories

**What it is.** RRC (Radio Resource Control) / RR (Radio Resource) is the *control brain of the radio
side*. When your phone is switched on it has no channel and no keys; RRC/RR is what listens to the
tower's broadcasts, picks a cell, requests a channel, sets up the encrypted radio link, and keeps you
connected as you move. NAS messages (registration, calls, SMS) ride *inside* RRC once a connection
exists, but RRC itself runs first and runs unauthenticated at the start.

**The job, in four verbs:** *acquire* (read broadcasts, camp on a cell), *connect* (random access →
connection setup), *configure/secure* (radio bearers, ciphering/integrity), *move* (measurements,
reselection, handover).

**The six message categories every RAT has** (same skeleton, different names/encodings):

| Category | What it does | Security state when received |
| --- | --- | --- |
| **MIB / SIB (System Information)** | Broadcast cell parameters. **MIB** = the tiniest set needed to even decode the rest; **SIBs** = fuller config (cell selection, neighbour lists, timers, access control). | **Broadcast, no security** → pre-auth (T0) |
| **Paging** | "Wake up, there is a call/SMS/registration for you" (or "SI changed", or emergency alert). Broadcast to idle UEs. | **Broadcast, no security** → pre-auth (T0) |
| **RRC Connection (Setup / Reconfiguration / Release)** | Establish, modify, and tear down the dedicated radio connection and its bearers. | Setup begins pre-security; Reconfiguration usually post-security |
| **Measurement / Handover** | Configure what neighbours to measure; command a handover to another cell/RAT. | Post-connection (mostly post-security) |
| **Security Mode Command** | Turn on AS ciphering + integrity, selecting the algorithms. | The transition point: this message *starts* AS security |
| **UE Capability (Enquiry / Information)** | Network asks what bands/features the UE supports; UE answers. | Post-connection |

**Encoding split.** **2G RR** messages are **octet-oriented with a message-type octet**, and their
variable "rest octets" use **CSN.1** (a bespoke bit-field grammar). **3G/4G/5G RRC** messages are
**ASN.1, packed with UPER** (Unaligned Packed Encoding Rules) — a tightly bit-packed, deeply nested
format. That is why every 3G/4G/5G modem carries **thousands of hand-generated `AsnDecode_*` functions**
(one per IE/message type) — and why those decoders are the single largest baseband attack surface. The
bit-level packing rules are in the encodings reference; below we show only the **logical** structure.

**The beginner takeaway that drives the security section:** *MIB/SIB and Paging are broadcast with no
authentication and no integrity.* Any device that can transmit a stronger signal (a cheap fake base
station / rogue gNB) can feed a victim malformed System Information or Paging, and the victim's RRC
decoder will parse it *before any keys exist*. That is the **T0 pre-auth** surface, and it is exactly
where this project's headline findings live (F6/F9 on NR SI, F10 on GSM neighbour lists).

---

<a name="gsm-rr"></a>
## GSM RR — 2G Radio Resource

- **What it is / meaning:** **RR = Radio Resource management**, the L3 access-stratum protocol of GSM
  (2G). It runs on the modem above L2 (LAPDm on dedicated channels; raw blocks on BCCH/CCCH) and below
  the CS NAS (MM/CC/SMS). In this image its functions are the `FDD_rr_*` / `FDD_rmc_*` (measurement/
  reselection) / `FDD_acs_*` (access) / `FDD_si_*` / `FDD_psi_*` (System Information) families. GPRS
  packet resource control is the sibling in TS 44.060 (`FDD_psi_*`, PSI messages).
- **Purpose:**
  - Read BCCH **System Information (SI Type 1..13)** to camp on a cell and learn neighbours.
  - Run **RACH → Immediate Assignment** to get a dedicated or packet (TBF) channel.
  - Manage dedicated channels, ciphering mode, and handovers; run **cell reselection** (C1/C2).
  - Deliver **Paging Request** to idle mobiles.
- **Specification:** TS 44.018 (RR protocol) — https://www.3gpp.org/dynareport?code=44.018.htm ;
  packet/GPRS RR in TS 44.060 — https://www.3gpp.org/dynareport?code=44.060.htm ; CSN.1 rest-octets are
  described inline in those specs. ShareTechnote GSM index: https://www.sharetechnote.com/ .
- **Packet / PDU disposition (how it looks on the wire):** GSM RR is **octet-based** with a fixed 2-byte
  L3 header (skip indicator + protocol discriminator, then a **message-type octet**), followed by
  fixed IEs and finally variable **CSN.1 "rest octets"**. On BCCH/CCCH an extra L2 pseudo-length octet
  precedes it. Example — **System Information Type 3** (TS 44.018 §9.1.35):
  ```
   octet 1   [ L2 Pseudo Length (6b value) | 0 | 1 ]         (BCCH/CCCH framing)
   octet 2   [ Skip Indicator (4b) | Protocol Discriminator=0110b RR (4b) ]
   octet 3   [ Message Type = 0x1B  (System Information Type 3) ]
   octet 4-5 [ Cell Identity (16b) ]
   octet 6-10[ Location Area Identification (MCC/MNC/LAC, 40b) ]
   octet 11-13[ Control Channel Description (24b) ]
   octet 14  [ Cell Options (BCCH) ]
   octet 15-16[ Cell Selection Parameters ]
   octet 17-19[ RACH Control Parameters ]
   octet 20+ [ SI 3 Rest Octets  ---- CSN.1, variable ---- ]   (GPRS ind., SI2q ptr, ...)
  ```
  (message-type value per TS 44.018 Table 10.4.1 — verify.) The fixed part is plain octets; the *rest
  octets* need the CSN.1 bit-reader (`Csn*` functions) — that is where variable-length parsing bugs hide.
- **Key fields explained:**

  | Field | Meaning |
  | --- | --- |
  | Protocol Discriminator | `0110b` = RR (distinguishes RR from MM/CC/SMS in the same L3 stream) |
  | Message Type | 1 octet selecting the message (e.g. SI3=0x1B, Immediate Assignment=0x3F, Paging Request Type 1=0x21 — *verify*) |
  | Rest Octets | CSN.1-encoded optional/variable extensions appended after the fixed IEs |
  | (Paging) Page Mode / Channels Needed | 4-bit + 2×2-bit fields selecting paging behaviour and channel type |
  | (Paging) Mobile Identity 1/2 | TMSI or IMSI of the paged subscriber(s) |
- **Beginner notes / gotchas:** *"Rest octets" are not padding* — they carry real optional data in CSN.1
  and must be bit-decoded. There is no length field on many fixed IEs; sizes are implied by the message
  type. The same `FDD_rr_*`/`FDD_rmc_*` code is *reused* for TD-SCDMA (`TDD_rr_*`), so a "GSM" bug can
  also live in the 3G TDD sibling. Packet-domain SI is **PSI** (TS 44.060), decoded by `FDD_psi_*`.
- **Security relevance:** **System Information and Paging Request are broadcast, unauthenticated,
  pre-auth (T0).** A fake BTS can transmit arbitrary SI/paging and the `FDD_si_*`/CSN.1 decoders parse it
  with no keys. **Finding F10 lives here:** `FDD_rr_decode_eutran_pcid_group_ie` (@ `0x9080b0e0`), reached
  from the **SI2quater** E-UTRAN neighbour parameters, indexes a 9-bit PCID (0..511) as `value>>3` into a
  **63-byte** bitmap — PCID 504..511 write one attacker-chosen bit **1 byte past** the buffer (a single-bit
  heap OOB, DoS-class, but genuine and pre-auth broadcast). The neighbour-list / SI2q decode path is the
  attacker-controlled entry.

---

<a name="umts-rrc"></a>
## UMTS RRC — 3G Radio Resource Control

- **What it is / meaning:** **RRC = Radio Resource Control**, the L3 access-stratum protocol of UMTS
  (3G / WCDMA). It runs above L2 (RLC/MAC/PDCP) and below the CS+PS NAS (MM/CC/GMM/SM). In this image its
  message parsers are the **`AsnDecode_RRC_*` (~1316) / `AsnEncode_RRC_*` (~1346)** families, driven by a
  shared PER runtime (`getBits`/`getShortBits`/`AsnDecodeAlloc`/`AsnError`).
- **Purpose:**
  - Broadcast **Master Information Block (MIB) + System Information Blocks (SIB1..SIB18…)** on BCH/FACH.
  - **RRC Connection Setup / Reconfiguration / Release**; radio-bearer setup.
  - **Paging Type 1** (idle) / **Paging Type 2** (connected); **Security Mode Command**; measurement &
    handover control; UE capability.
- **Specification:** TS 25.331 (UMTS RRC) — https://www.3gpp.org/dynareport?code=25.331.htm ;
  ShareTechnote: https://www.sharetechnote.com/ .
- **Packet / PDU disposition (how it looks on the wire):** UMTS RRC is **ASN.1, PER-encoded** — there is
  no plain message-type octet; the message is a nested `CHOICE`. Each logical channel maps to a top-level
  PDU that is a `SEQUENCE`-wrapped `CHOICE` of message types, e.g.:
  ```
  BCCH-BCH-Message      ::= SEQUENCE { message MasterInformationBlock }   -- MIB
  BCCH-FACH-Message     ::= SEQUENCE { message CHOICE { systemInformation, systemInformationChangeIndication } }
  PCCH-Message          ::= SEQUENCE { message PagingType1 }              -- paging
  DL-DCCH-Message       ::= SEQUENCE { message CHOICE {                   -- dedicated downlink
                              rrcConnectionSetup, rrcConnectionRelease,
                              radioBearerReconfiguration, securityModeCommand,
                              measurementControl, ueCapabilityEnquiry, ... } }
  ```
  The bit-level UPER/PER packing (choice index bits, length determinants) is in the encodings reference;
  the decoder walks this tree with `getBits`/nested `AsnDecode_RRC_*` calls, allocating with
  `AsnDecodeAlloc` under a `setjmp`/`longjmp` error-unwind frame.
- **Key fields explained:**

  | Element | Meaning |
  | --- | --- |
  | top-level `CHOICE` index | selects the concrete message (the PER equivalent of a message-type octet) |
  | MIB `plmn-Identity` + `sib-ReferenceList` | which PLMN this cell is, and where/when each SIB is scheduled |
  | `schedulingInfo` (in SIB) | tells the UE which SIBs exist and their repetition period |
  | `paging-Record` (PagingType1) | list of paged UE identities (TMSI/IMSI/P-TMSI) |
- **Beginner notes / gotchas:** UMTS RRC has *many extension chains* — a base IE plus `_v4b0`/`_v590`/
  `_v5c0`… version-suffixed extensions (visible on `AsnDecode_RRC_SysInfoType3` and friends). Each is a
  separately generated decoder, which is why the count is >1300. "SysInfoType*N*" here is a UMTS SIB, not
  a GSM SI. The PER runtime is shared, so a bug in `getBits`/length-determinant handling affects *every*
  message.
- **Security relevance:** MIB/SIB and PagingType1 are **broadcast, pre-auth (T0)**; RRC Connection Setup
  is also reachable before AS security. The **~1316 `AsnDecode_RRC_*` decoders are a headline attack
  surface** — thousands of hand-generated bit-parsers reachable from broadcast (`AsnDecode_RRC_SysInfoType*`,
  ~63 of them) and from pre-security dedicated messages. This is the 3G analogue of the NR SI decoder
  family; no single confirmed finding is pinned here in this report set, but it is the archetype the F6/F9
  NR work generalises from.

---

<a name="lte-rrc"></a>
## LTE RRC — 4G Radio Resource Control

- **What it is / meaning:** **RRC** for LTE (4G / E-UTRA). L3 access stratum, above L2 (PDCP/RLC/MAC) and
  below the EPS NAS (EMM/ESM, TS 24.301). In this image the whole family is **`errc_*` (~5719
  functions)** — `errc_cel_*` (cell/entity + SIB + paging), `errc_mob_*` (mobility), `errc_conn_*`
  (connection), `errc_lsys_*` (SI dispatch), `errc_asn1_*` (ASN.1 codec) — plus **~15
  `AsnDecode_SystemInformationBlockType*`** per-SIB decoders.
- **Purpose:**
  - Broadcast **MIB** (on PBCH/BCH) + **SIB1..SIB19** (on DL-SCH, scheduled by SIB1).
  - **RRC Connection Establishment / Reconfiguration / Release**; DRB/SRB setup; **Security Mode Command**.
  - **Paging** (on PCCH); measurement config & **handover** (`rrcConnectionReconfiguration` with
    `mobilityControlInfo`); **UE Capability**; ETWS/CMAS public-warning delivery (`errc_cel_pwsrcv_*`).
- **Specification:** TS 36.331 (LTE RRC) — https://www.3gpp.org/dynareport?code=36.331.htm ;
  ShareTechnote LTE: https://www.sharetechnote.com/ .
- **Packet / PDU disposition (how it looks on the wire):** ASN.1 / **UPER**. Each logical channel is a
  `SEQUENCE` wrapping a two-level `CHOICE` (`c1` for the common set, then the message). Concrete **SIB
  example — SystemInformationBlockType1 (SIB1)**, the scheduler for all other SIBs:
  ```
  BCCH-DL-SCH-Message ::= SEQUENCE { message CHOICE { c1 CHOICE {
                            systemInformationBlockType1,   -- SIB1
                            systemInformation } } }        -- container of other SIBs
  SystemInformationBlockType1 ::= SEQUENCE {
    cellAccessRelatedInfo  SEQUENCE { plmn-IdentityList, trackingAreaCode(16b),
                                      cellIdentity(28b), cellBarred, ... },
    cellSelectionInfo      SEQUENCE { q-RxLevMin, q-RxLevMinOffset OPTIONAL },
    p-Max                  INTEGER OPTIONAL,
    freqBandIndicator      INTEGER (1..64),
    schedulingInfoList     SchedulingInfoList,   -- << maps each SI message to its SIB list + periodicity
    tdd-Config             OPTIONAL,
    si-WindowLength        ENUMERATED { ms1, ms2, ... },
    systemInfoValueTag     INTEGER (0..31),
    ... (version extensions) }
  ```
  **schedulingInfoList is the key idea:** SIB1 is fixed-scheduled; it then *tells the UE which SI
  messages carry which SIBs and how often*. The UPER bit layout (choice bits, `SEQUENCE OF` count
  determinants, OPTIONAL presence bits) is in the encodings reference.
- **Key fields explained:**

  | Element | Meaning |
  | --- | --- |
  | `c1` CHOICE | selects the message type on that channel (the ASN.1 "message-type") |
  | `schedulingInfoList` | SIB1's map of SI-messages → SIB types + periodicity (drives what the UE decodes next) |
  | `systemInfoValueTag` | changes when SI content changes → UE knows to re-read |
  | `mobilityControlInfo` (in Reconfiguration) | the actual **handover** command (target cell/RAT) |
- **Beginner notes / gotchas:** MIB (PBCH) carries only the *bare minimum* (bandwidth, PHICH, SFN);
  everything else is SIBs on DL-SCH. "SIB" numbers here are LTE-specific and do **not** match GSM SI
  numbers or UMTS SysInfoType numbers. Handover is not its own message — it is a field inside
  `rrcConnectionReconfiguration`.
- **Security relevance:** MIB/SIB and Paging are **broadcast, pre-auth (T0)**; RRC Connection Setup and
  early Reconfiguration are pre-security. The `errc_lsys_*`/`errc_asn1_*` SI-decode path and the ~15
  `AsnDecode_SystemInformationBlockType*` decoders are the broadcast attack surface. (This report's LTE
  findings F3/F13 are in the **NAS** layer carried *inside* RRC, not in RRC itself — see the NAS file —
  but they are reached via a rogue eNB precisely because early RRC accepts an unauthenticated connection.)

---

<a name="nr-rrc"></a>
## NR RRC — 5G Radio Resource Control

- **What it is / meaning:** **RRC** for 5G NR (New Radio). L3 access stratum, above L2 (SDAP/PDCP/RLC/MAC)
  and below the 5GS NAS (5GMM/5GSM, TS 24.501). In this image: the RRC body is **`nrrc_*` (~2664
  functions)**, the message parsers are **~108 `AsnDecode_NR_*`** UPER decoders, dispatched by
  `nrrc_asn1_decode`; the L1→RRC glue that reassembles broadcast SI before decode is the small
  **`NL1_CTRL_Nrrc_*`** family.
- **Purpose:**
  - Broadcast **MIB** (on BCH/PBCH) + **SIB1** (on DL-SCH) + other SIBs in **SI messages** (scheduled by
    SIB1's `si-SchedulingInfo`).
  - **RRC Setup / Reconfiguration / Resume / Reestablishment / Release**; **Security Mode Command**;
    measurement & handover; **UE Capability**; paging on PCCH.
- **Specification:** TS 38.331 (NR RRC) — https://www.3gpp.org/dynareport?code=38.331.htm ;
  ShareTechnote 5G: https://www.sharetechnote.com/ .
- **Packet / PDU disposition (how it looks on the wire):** ASN.1 / **UPER**, same `SEQUENCE{ CHOICE c1 }`
  skeleton as LTE. Two concrete examples at the field level:

  **MIB (BCCH-BCH-Message)** — the most basic cell params, ~23 bits total:
  ```
  BCCH-BCH-Message ::= SEQUENCE { message CHOICE { mib MIB, messageClassExtension } }
  MIB ::= SEQUENCE {
    systemFrameNumber        BIT STRING (SIZE(6)),
    subCarrierSpacingCommon  ENUMERATED { scs15or60, scs30or120 },
    ssb-SubcarrierOffset     INTEGER (0..15),
    dmrs-TypeA-Position      ENUMERATED { pos2, pos3 },
    pdcch-ConfigSIB1         PDCCH-ConfigSIB1,          -- where to find SIB1
    cellBarred               ENUMERATED { barred, notBarred },
    intraFreqReselection     ENUMERATED { allowed, notAllowed },
    spare                    BIT STRING (SIZE(1)) }
  ```
  **Paging (PCCH-Message)** — the concrete paging message:
  ```
  PCCH-Message ::= SEQUENCE { message CHOICE { c1 CHOICE { paging Paging }, ... } }
  Paging ::= SEQUENCE {
    pagingRecordList  SEQUENCE (SIZE(1..32)) OF PagingRecord  OPTIONAL,
    ... }
  PagingRecord ::= SEQUENCE {
    ue-Identity   CHOICE { ng-5G-S-TMSI BIT STRING(48), fullI-RNTI BIT STRING(40) },
    accessType    ENUMERATED { non3GPP }  OPTIONAL }
  ```
  DL-CCCH/DL-DCCH follow the same pattern: `DL-DCCH-Message` is a `CHOICE` of `rrcReconfiguration,
  rrcResume, rrcRelease, rrcReestablishment, securityModeCommand, dlInformationTransfer,
  ueCapabilityEnquiry, …`. UPER bit-packing detail is in the encodings reference.
- **Key fields explained:**

  | Element | Meaning |
  | --- | --- |
  | `pdcch-ConfigSIB1` (MIB) | tells the UE where SIB1 (and thus all SI) is scheduled |
  | `si-SchedulingInfo` (SIB1) | the NR equivalent of LTE `schedulingInfoList` — maps SI messages → SIBs |
  | `pagingRecordList` | up to 32 paged UE identities (5G-S-TMSI / I-RNTI) |
  | `c1` CHOICE index | selects the concrete DL-CCCH/DL-DCCH message |
- **Beginner notes / gotchas:** NR splits SI into MIB (PBCH) + SIB1 (a.k.a. "RMSI", remaining minimum SI)
  + other SIBs in SI messages; a UE must decode MIB→SIB1 *before* it can even do random access. Because
  an SI/paging transport block can exceed one PHY block, the L1 delivers it in **segments** that the
  `NL1_CTRL_Nrrc_*` glue must reassemble into one buffer *before* the `AsnDecode_NR_BCCH_DL_SCH_Message` /
  `AsnDecode_NR_PCCH_Message` decoder runs.
- **Security relevance:** MIB/SIB1/SI and Paging are **broadcast, unauthenticated, pre-auth (T0)** — the
  worst tier. **This is where F6/F9 live.** `NL1_CTRL_Nrrc_Reconstruct_Raw_Data` (@ `0x90ee9e26`)
  reassembles SI/paging segments by copying `nseg × segLen` bytes (both read verbatim from an L1
  descriptor) into a **380-byte stack buffer** and into message-pool buffers, with the loop's *only* exit
  being `nseg==0` and the one length check testing the **wrong field, after the copy** — a classic
  copy-before-check overflow, reachable pre-auth from a rogue gNB's SI/paging broadcast. On Samsung's
  build the copier was split into a fixed primary and an **unclamped sibling (F9, `sub_90CC90C8`)**, so
  the overflow survives the incomplete patch. See `../../F6.md` and `/workspace/CONSOLIDATED_FINDINGS.md`.
  The ~108 `AsnDecode_NR_*` decoders that run *after* reassembly are the same class of broadcast-reachable
  bit-parser as the 3G `AsnDecode_RRC_*` family — this is why RRC ASN.1 decoders are the #1 target.
