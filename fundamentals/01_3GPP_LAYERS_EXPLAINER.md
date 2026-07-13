# A Beginner's Guide to 3GPP Cellular Protocols, Layers, and Baseband Security

This is a from-scratch primer for someone new to cellular baseband. It explains **who 3GPP is**, how
the cellular stack is **divided into layers and sublayers**, how each generation (**2G / 3G / 4G / 5G**)
maps onto those layers, and — throughout — **why each layer matters for security analysis and
exploitation**. It ends with a curated link list. Companion file: `02_FUNCTION_CATALOG_*` maps these
concepts to the actual functions in this firmware.

---

## 0. Vocabulary you need first

- **UE** (User Equipment) — your phone. Specifically its **baseband / modem** (here, a MediaTek chip
  running nanoMIPS), which is a separate computer from the Android "application processor" (AP).
- **Network side names:** **BTS/NodeB/eNB/gNB** = the base station (2G/3G/4G/5G respectively).
  **Core network** = the operator's back-end (MSC/SGSN → MME/SGW/PGW → AMF/SMF/UPF across generations).
- **RAT** — Radio Access Technology (GSM, UMTS, LTE, NR). One phone supports several and hands over
  between them ("inter-RAT").
- **3GPP** — the **3rd Generation Partnership Project**, the standards body that writes the specs for
  2G(GSM/GPRS), 3G(UMTS), 4G(LTE), and 5G(NR). Specs are called **Technical Specifications (TS)**, each
  with a number like **TS 24.301**. They're grouped in **Series** (e.g. the 24-series = NAS signalling,
  the 36-series = LTE radio, the 38-series = 5G NR radio). This numbering is your map to the whole system.

### The one mental model: a protocol *stack*
Two peers (your phone and the network) talk through **layers**. Each layer on your phone has a logical
"conversation" with the same layer on the network, but physically the data travels **down** your phone's
stack (L3→L2→L1), across the radio, and **up** the network's stack. Each layer adds/removes its own
header and does one job. A message you care about (say, a 5G "Registration Accept") is an **L3** message
that was carried inside L2 frames inside an L1 transmission. **Attackers craft malformed content at some
layer; the bug is in the code that parses that layer.**

---

## 1. The layered architecture (the heart of it)

Cellular reuses the OSI idea but with 3GPP-specific names. Across all generations the shape is:

```
        ┌─────────────────────────────────────────────────────────────┐
  L3    │  NAS  (Non-Access Stratum): talks to the CORE network        │  ← "what", end-to-end signalling
        │        MM/GMM/CC/SM (2G/3G) · EMM/ESM (4G) · 5GMM/5GSM (5G)   │
        │  ───────────────────────────────────────────────────────────│
        │  RRC / RR  (Access Stratum L3): talks to the BASE STATION     │  ← radio connection control
        ├─────────────────────────────────────────────────────────────┤
  L2    │  PDCP (4G/5G) · RLC · MAC   [2G adds LLC/SNDCP for GPRS]      │  ← framing, reliability, ciphering
        ├─────────────────────────────────────────────────────────────┤
  L1    │  PHY (Physical layer): modulation, coding, radio             │  ← bits over the air
        └─────────────────────────────────────────────────────────────┘
```

Two big vertical splits you must internalize:

- **Access Stratum (AS)** = everything about the *radio link* to the base station: **RRC + L2 + L1**.
- **Non-Access Stratum (NAS)** = signalling that passes *through* the base station to the *core network*
  (registration, authentication, session/bearer setup, SMS). NAS rides on top of RRC.

Why this split matters for security: a **fake base station** controls the AS (it *is* the radio peer),
so **AS/RRC and L2 bugs are reachable pre-authentication**. NAS messages that set up security are also
processed pre-auth (they have to be), which is why **NAS attach/identity/reject** handlers are prime
pre-auth targets too. See the tier model in §6.

### L1 — Physical layer (PHY)
Turns bits into radio waveforms and back: modulation, channel coding, timing, power. On this modem much
of L1 runs on a **separate DSP** (Coresonic), not the nanoMIPS core. **Security relevance:** usually not
directly attacker-parseable memory-wise, BUT L1 hands *descriptors* (lengths, segment counts) up to L2/L3
— and if those are attacker-influenced and unchecked, an L1→L3 boundary bug results (this is exactly the
shape of the NR "SI reassembly" finding in this project).

### L2 — Data-link layer (the framing/reliability sublayers)
Splits into sublayers that differ slightly per generation:
- **MAC** (Medium Access Control): maps logical channels to transport channels, scheduling, HARQ, builds/parses
  MAC PDUs and control elements. Runs **before ciphering** on the downlink → a rich pre-auth parser surface.
- **RLC** (Radio Link Control): segmentation & **reassembly** of upper-layer packets, ARQ retransmission,
  duplicate detection. **Reassembly = buffers + length fields = classic overflow territory.**
- **PDCP** (Packet Data Convergence Protocol, **4G/5G only**): header compression (ROHC), **ciphering &
  integrity** of user/þcontrol data, reordering.
- **2G extras for GPRS:** **LLC** (Logical Link Control) and **SNDCP** (Subnetwork Dependent Convergence)
  sit above RLC/MAC for packet data.
- **5G extra:** **SDAP** (Service Data Adaptation Protocol) for QoS-flow→bearer mapping.

**Security relevance:** RLC/PDCP reassembly and MAC PDU parsing handle attacker-controlled lengths and run
early (often pre-security). Historically fewer public bugs than L3, but high value because pre-auth.

### L3 — Network layer (two very different halves)
**(a) RRC / RR — the Access-Stratum L3 (radio connection control).**
- 2G calls it **RR** (Radio Resource); 3G/4G/5G call it **RRC** (Radio Resource Control).
- Manages the radio connection: broadcast **System Information (SIB/MIB)**, **paging**, connection
  setup/reconfiguration/release, measurements, handovers, security-mode activation on the radio.
- 3G/4G/5G RRC messages are encoded with **ASN.1** (see §3) — a formal, nested, variable-length format.
  Parsing ASN.1 correctly is hard → the **RRC ASN.1 decoders are the single largest attack surface** and
  the most numerous functions in the firmware.
- **Security relevance:** **SIB and paging are broadcast with no security → pre-auth, zero-interaction,
  everyone in range (tier T0).** This is the crown-jewel attack surface.

**(b) NAS — the Non-Access-Stratum L3 (core-network signalling).**
- Handles **registration/attach**, **authentication (AKA)**, **security mode**, **mobility**, **session /
  bearer setup**, and **SMS transport**. It's split by generation and by CS/PS domain:

| Generation | Mobility mgmt | Session/call mgmt |
|---|---|---|
| 2G/3G CS (voice) | **MM** (Mobility Management) | **CC** (Call Control) |
| 2G/3G PS (data)  | **GMM** (GPRS MM) | **SM** (Session Management) |
| 4G LTE | **EMM** (EPS MM) | **ESM** (EPS SM) |
| 5G NR | **5GMM** | **5GSM** |

- NAS IEs are mostly **TLV** (Type-Length-Value) rather than ASN.1 — a length byte drives a copy into a
  struct field. **A missing "length ≤ buffer" check is the classic NAS overflow** (several findings here
  are exactly this: LADN, Emergency-Number-List, Access-Category).
- **Security relevance:** NAS messages processed *before* the security context (Identity Request,
  Authentication Request, Attach/Registration Reject, some Information messages) are **pre-auth via a rogue
  base station (T1)**. After security, they need a valid signature (T4). The single most important question
  for a NAS bug is *"is this message parsed before or after integrity verification?"*

---

## 2. How each generation maps onto the layers

Same skeleton, different names/encodings. (Frequencies/PHY differ hugely but that's the DSP's problem.)

| Layer | 2G (GSM/GPRS) | 3G (UMTS/WCDMA) | 4G (LTE) | 5G (NR) |
|---|---|---|---|---|
| **L3 NAS** | MM, CC (CS); GMM, SM (PS); SMS | MM, CC; GMM, SM; SMS | **EMM, ESM**; SMS-over-NAS | **5GMM, 5GSM**; SMS-over-NAS |
| **L3 AS** | **RR** (+ CSN.1 messages) | **RRC** (ASN.1) | **RRC** (ASN.1) | **RRC** (ASN.1) |
| **L2** | LLC, SNDCP (GPRS) / RLC, MAC | RLC, MAC (+PDCP hdr comp) | **PDCP, RLC, MAC** | **SDAP, PDCP, RLC, MAC** |
| **L1** | GSM PHY (TDMA/GMSK) | WCDMA PHY (CDMA) | LTE PHY (OFDMA) | NR PHY (OFDMA, mmWave) |
| Core | MSC/SGSN | MSC/SGSN | **MME/SGW/PGW (EPC)** | **AMF/SMF/UPF (5GC)** |
| Base station | BTS | NodeB (+RNC) | **eNB** | **gNB** |

Notes a beginner trips on:
- **CS NAS (MM/CC/SMS) is largely shared between 2G and 3G** in real modems (one code module serves both).
- **2G message encoding** uses **CSN.1** (a bit-oriented format) for RR + a lot of hand-rolled TLV; 3G/4G/5G
  RRC use **ASN.1/PER**. NAS across all uses **TLV/hand-coded IEs**.
- **SMS** is a cross-cutting service: it rides on NAS (CP/RP/TP sublayers → the "TPDU" you decode), and in
  4G/5G rides over EMM/5GMM. **Cell Broadcast (CB)** and **ETWS/CMAS emergency alerts** are broadcast
  (pre-auth) cousins of SMS.
- **IMS / VoLTE / VoWiFi** (voice-over-LTE/5G) is *above* NAS: SIP/SDP signalling + **RTP/RTCP** media.
  On many modems the SIP/SDP text parsing is on the Android side; the **modem handles the RTP media plane**
  (which is where the VoLTE-RTT and EVS-codec findings here live — tier T3, in-call).

---

## 3. ASN.1, TLV, CSN.1 — the encodings you'll fight

Attackers control **bytes**; the firmware **decodes** them into structures. The decoder is where bugs live.
- **TLV (Type-Length-Value)** — each field is a type tag, a length, then that many bytes. Used by NAS.
  The danger: code reads the length byte and copies that many bytes into a fixed struct field **without
  checking it fits**. → buffer overflow.
- **ASN.1 + PER/UPER (Packed Encoding Rules)** — a formal schema language; messages are tightly bit-packed.
  Used by RRC (3G/4G/5G). Decoders are auto-generated and huge (`AsnDecode_*` here). The danger: a
  **length determinant** or **SEQUENCE-OF count** that isn't clamped to the destination; bit-reader
  over-reads. PER is compact so a few bytes can expand into large structures.
- **CSN.1** — a bit-field description used by GSM RR / GPRS. Similar risks in a bespoke bit-reader.

For a beginner: think of the decoder as `parse(attacker_bytes) → struct`. Every place it uses an
attacker number as a **length, count, or index** without a bound is a candidate bug.

---

## 4. The call lifecycle (when is each layer active?)

Rough downlink-attacker timeline for a phone joining a network:
1. **Cell search / broadcast (L1+RRC):** phone reads **MIB/SIB** (broadcast, no security). ← **T0 pre-auth**
2. **RRC connection setup (RRC/L2):** radio connection established. ← pre-auth
3. **NAS Attach/Registration Request →** network sends **Identity/Authentication Request** ← **T1 pre-auth**
4. **Authentication (AKA)** — SIM proves the key K; only now do phone & *real* network share secrets.
5. **Security Mode Command** — integrity + ciphering turned on. **After this, unsigned messages are rejected.**
6. **Registration/Attach Accept, bearer/PDU setup** ← integrity-protected → **T4 post-auth (or MITM)**
7. **Services:** SMS (T2), VoLTE call → RTP media (T3), handovers, paging (broadcast, pre-auth).

**Everything before step 5 is a pre-auth attack surface reachable by a fake base station.** That single
timeline explains most of the severity ranking in the findings.

---

## 5. What lives on the modem vs the Android side

Beginners often mis-scope. On a MediaTek phone:
- **On the modem (this firmware):** L1(partly, + DSP), L2, RRC/RR, NAS (MM/GMM/CC/SM/EMM/ESM/5GMM/5GSM),
  SMS transport, **RTP/RTCP media** for VoLTE, security (EIA/EEA integrity/ciphering).
- **On Android (AP):** the IMS **SIP/SDP** stack is often here, the dialer/UI, RIL. So a "SIP bug" may not
  be in the modem at all — always confirm which processor parses the bytes.
- **Baseband→AP pivot:** the modem and AP share memory (CCIF/CLDMA). A modem RCE can attack the AP across
  that interface — which is why baseband bugs are so serious.

---

## 6. Reachability tiers (the security bottom line)

The whole point of the layer/lifecycle analysis is to answer: **what does the attacker need?**

| Tier | Where it's reached | Attacker capability | Example layers |
|---|---|---|---|
| **T0** | Broadcast (SIB/MIB/paging, Cell Broadcast) | Fake base station; **no interaction, everyone in range** | RRC SIB, NR SI, SMS-CB/ETWS |
| **T1** | Pre-security unicast (attach/identity/auth/reject) | Fake base station (rogue eNB/gNB), no keys | RRC setup, NAS pre-auth IEs |
| **T2** | Network service to the subscriber | Send an SMS / use a service (no radio gear) | SMS transport |
| **T3** | In-call media | Be the call peer / inject RTP into a call | IMS RTP/RTCP media |
| **T4** | Post-security signalling | Be the real network, or MITM with valid keys | integrity-protected NAS |

(There is a fuller treatment with per-finding reasoning in `/workspace/report/PREAUTH_POSTAUTH_EXPLAINER.md`.)

---

## 7. Curated links (learn more — chosen for a security-analysis angle)

**Best starting points (baseband security specifically):**
- Quarkslab, "A review of Ziggy… / Baseband security" & general baseband intros — https://blog.quarkslab.com/
- TASZK Labs baseband research (MediaTek nanoMIPS, the closest to this project) —
  https://labs.taszk.io/articles/ (see the "Basebanheimer" / full-chain baseband posts)
- NCC Group, "Ghidra nanoMIPS ISA module" & MediaTek baseband tooling —
  https://www.nccgroup.com/research/ghidra-nanomips-isa-module/
- Comsecuris / "Breaking Band" (Shannon baseband RE, foundational methodology) —
  https://github.com/Comsecuris/shannonRE  and the OffensiveCon/REcon talks by Nico Golde & Daniel Komaromy
- Google Project Zero on baseband (Exynos, methodology transferable) —
  https://googleprojectzero.blogspot.com/ (search "baseband", "Exynos", "CVE-2023-24033")
- FirmWire (academic baseband emulation/fuzzing framework) — https://github.com/FirmWire/FirmWire and
  the NDSS 2022 paper https://www.ndss-symposium.org/wp-content/uploads/2022-136-paper.pdf

**Learning the protocol stack (structured):**
- ShareTechnote — the single best free, diagram-heavy reference for LTE/NR/UMTS/GSM layers —
  https://www.sharetechnote.com/
- Grandmetric protocol tutorials (clear layer diagrams) — https://www.grandmetric.com/knowledge-base/
- EventHelix "3GPP call flows" (message sequence charts across layers) — https://www.eventhelix.com/
- 3GPP itself — spec numbering & downloads — https://www.3gpp.org/specifications  and the
  human-readable spec browser https://portal.3gpp.org/

**The specs that matter most for parsing bugs (read the IE tables):**
- **NAS:** TS 24.008 (2G/3G MM/CC/GMM/SM + the IE encoding everyone reuses), TS 24.301 (LTE EMM/ESM),
  **TS 24.501 (5G 5GMM/5GSM)** — the 24-series defines the TLV IEs you decode.
- **RRC:** TS 25.331 (UMTS RRC ASN.1), TS 36.331 (LTE RRC ASN.1), **TS 38.331 (NR RRC ASN.1)**.
- **L2:** TS 36.321/322/323 (LTE MAC/RLC/PDCP), TS 38.321/322/323 (+324 SDAP) for NR.
- **SMS / CB:** TS 23.040 (SMS), TS 23.041 (Cell Broadcast / ETWS-CMAS).
- **IMS/media:** TS 26.114 (IMS multimedia telephony, incl. RTP/codec), RFC 4103 (RTP for Real-Time Text),
  RFC 3550 (RTP), the EVS codec spec TS 26.445.
- **Security:** TS 33.401 (LTE security / EIA-EEA), TS 33.501 (5G security).

**ASN.1 / encoding background:**
- "A Layman's Guide to a Subset of ASN.1, BER, and DER" (Kaliski) — classic —
  http://luca.ntop.org/Teaching/Appunti/asn1.html
- OSS Nokalva ASN.1 intro — https://www.oss.com/asn1/resources/asn1-made-simple/introduction.html

**Tooling used in this project (see also the repo's own READMEs):**
- QEMU nanoMIPS `-cpu I7200`; IDA Pro; the `idaq` query server here; the dynamic PoC harness under
  `/workspace/poc/` and `/workspace/samsung/poc/`.

---

## 8. How to read the rest of this project (beginner path)
1. This file — the concepts.
2. `02_FUNCTION_CATALOG_HUAWEI.md` — the actual functions in this modem, per RAT & layer, with the exact
   search commands (so you can explore the DB yourself).
3. `/workspace/report/PREAUTH_POSTAUTH_EXPLAINER.md` — pre-auth vs post-auth in depth.
4. `/workspace/report/triggering/` — how each real vulnerability is triggered (SMS, call, fake tower…).
5. `/workspace/report/F1.md … F6.md` and `/workspace/samsung/new_findings/deep_dive/` — the deep-dives.
6. `/workspace/CONSOLIDATED_FINDINGS.md` — all 13 findings, categorized, Huawei vs Samsung.
