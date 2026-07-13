# Layer 2 — the data-link sublayers (MAC · RLC · PDCP · SDAP, plus 2G LLC/SNDCP)

**Layer 2 (L2)** sits between the radio physical layer (**L1/PHY**, bits over the air) and the L3
signalling/user data (**RRC/NAS**, and IP packets). Its job is *framing*: taking a stream of bytes and
turning it into addressed, sized, ordered, reliable, and (in 4G/5G) ciphered units — and doing the
reverse on receive. In 4G/5G the L2 stack is a clean pipe of **SDAP → PDCP → RLC → MAC** (top to bottom);
2G GPRS instead uses **SNDCP → LLC → RLC/MAC**. Because these sublayers *reassemble and parse
attacker-supplied radio bytes*, they are **pre-security parsers** — code that runs on data a fake base
station controls, often before any key is verified. See `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` for the big
picture and the reachability-tier model (T0–T4) referenced below.

**Contents:** [MAC](#mac--medium-access-control) · [RLC](#rlc--radio-link-control) ·
[PDCP](#pdcp--packet-data-convergence-protocol) · [SDAP](#sdap--service-data-adaptation-protocol) ·
[LLC](#llc--logical-link-control-2g-gprs) · [SNDCP](#sndcp--subnetwork-dependent-convergence-protocol-2g-gprs)

> **Read this first — the two meanings of "MAC".** In this document "MAC" appears with **two completely
> different meanings**: (1) **Medium Access Control**, the L2 sublayer below RLC (this section); and (2)
> **Message Authentication Code** (also written **MAC-I** / **NAS-MAC**), a cryptographic *integrity tag*
> appended by PDCP or NAS. They are unrelated. When we mean the crypto tag we say **MAC-I**; a bare "MAC"
> in an L2 context means the sublayer.

---

## MAC — Medium Access Control
- **What it is / meaning:** **MAC** = *Medium Access Control*, the **lowest L2 sublayer**, sitting directly
  on top of the PHY and below RLC. Used by **LTE (4G)** and **NR (5G)** (2G/3G have their own RLC/MAC). It
  multiplexes several **logical channels** (control + data) onto **transport channels** the PHY can carry,
  handles HARQ retransmission, scheduling/random-access, and buffer-status/power-headroom reporting.
- **Purpose:**
  - Multiplex/demultiplex RLC data of different **logical channels** into one **MAC PDU** (transport block).
  - Carry in-band control via **MAC Control Elements (CEs)** (e.g. timing advance, DRX, buffer status).
  - Identify each piece with a **Logical Channel ID (LCID)** in a per-piece subheader.
  - Drive HARQ and random access (RACH) — the fast, per-transmission reliability layer.
- **Specification:** LTE **TS 36.321** (`https://www.3gpp.org/dynareport?code=36.321.htm`), NR **TS 38.321**
  (`https://www.3gpp.org/dynareport?code=38.321.htm`). Tutorial:
  `https://www.sharetechnote.com/html/5G/5G_MAC.html`.
- **Packet / PDU disposition (how it looks on the wire):** a MAC PDU is **one or more** `{subheader + payload}`
  pairs concatenated (all subheaders can come first in NR), where payload is a MAC SDU (RLC data) or a MAC CE.
  ```
  LTE subheader — fixed (last SDU / CE, no length):
   0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |R|R|E|  LCID   |     R=reserved, E=more-subheaders-follow, LCID=5 bits
  +-+-+-+-+-+-+-+-+

  LTE subheader — variable (SDU whose length must be signalled):
   0 1 2 3 4 5 6 7  0 1 2 3 4 5 6 7 (...8 more if F=1)
  +-+-+-+-+-+-+-+-+ +-+-------------+
  |R|R|E|  LCID   | |F|   L ...     |   F=length-field-size flag (0→7-bit L, 1→15-bit L)
  +-+-+-+-+-+-+-+-+ +-+-------------+   L=length of this SDU in bytes
  (two R bits and the F/L split vary by release — widths per TS 36.321 §6.2.1, verify)

  NR subheader (TS 38.321 §6.1.2):
   0 1 2 3 4 5 6 7  0 ....... 7 (+8 if F=1)
  +-+-+-----------+ +---------+
  |R|F|   LCID    | |    L    |   R=reserved, F=1→16-bit L else 8-bit L, LCID=6 bits
  +-+-+-----------+ +---------+   (fixed-size CEs omit L entirely)

  Full PDU:  [subhdr][subhdr]...[SDU/CE][SDU/CE]... (+ optional padding, LCID=padding)
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | **LCID** | Logical Channel ID. Selects which logical channel the payload belongs to, **or** flags the payload as a specific **MAC CE** or padding (reserved LCID values). 5 bits LTE / 6 bits NR. |
  | **L** | Length of the associated MAC SDU in bytes (only in variable subheaders). |
  | **F** | Format flag: how many bits the following **L** field uses. |
  | **E** (LTE) | Extension: 1 = another subheader follows, 0 = last. |
  | **R** | Reserved (must be 0). |
- **Beginner notes / gotchas:** LCID is a small integer that behaves like a *type tag* — the receiver
  switches on it to route the payload, so an unexpected/reserved LCID is a classic parser edge case.
  Fixed-size MAC CEs carry **no length field**, so the decoder must know each CE's size from the LCID
  alone. Don't confuse this "MAC" with the crypto **MAC-I** tag (see the boxed note above).
- **Security relevance:** MAC parsing is an **AS L2** surface driven entirely by the radio peer, and on the
  **downlink MAC runs *before* PDCP deciphering** — i.e. the subheader walk (E/LCID/F/L loop) executes on
  bytes that are not yet decrypted/authenticated, making it **pre-security**. Attacker-controlled `L`
  values and subheader chaining are the length surface to watch. In this project the LTE/NR MAC PDU
  demux and the 2G RLC/MAC unpackers were **audited to their sinks and found correctly bounded**
  (see Appendix A negatives, `../../99_APPENDIX.md`) — no finding lives here, but it remains a priority
  re-audit target because of the pre-cipher position.

---

## RLC — Radio Link Control
- **What it is / meaning:** **RLC** = *Radio Link Control*, the L2 sublayer **between PDCP (above) and MAC
  (below)** in LTE/NR (2G/3G have their own RLC). Its central job is **segmentation and reassembly**:
  breaking large PDCP packets into radio-sized pieces on transmit, and stitching them back together on
  receive, optionally with retransmission-based reliability.
- **Purpose:**
  - **Segmentation & reassembly (SAR)** of upper-layer PDUs to fit the MAC transport block size.
  - Three service modes: **TM** (Transparent — no header, no SAR), **UM** (Unacknowledged — SAR + ordering,
    no retransmission), **AM** (Acknowledged — SAR + **ARQ** retransmission for lossless delivery).
  - Duplicate detection and in-order (or, in NR, out-of-order-then-reorder) delivery.
- **Specification:** LTE **TS 36.322** (`https://www.3gpp.org/dynareport?code=36.322.htm`), NR **TS 38.322**
  (`https://www.3gpp.org/dynareport?code=38.322.htm`). Tutorial:
  `https://www.sharetechnote.com/html/5G/5G_RLC.html`.
- **Packet / PDU disposition:**
  ```
  NR UMD PDU (TS 38.322 §6.2.2.3) — 6-bit SN shown:
   0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |SI |    SN     |   SI = 2-bit Segmentation Info (00=complete,01=first,10=last,11=middle)
  +-+-+-+-+-+-+-+-+   SN = sequence number (6 or 12 bits; 12-bit spills into a 2nd octet)
  |     SO (16 bits)  |   SO = Segment Offset, PRESENT ONLY when SI = last/middle segment
  +-------------------+
  |   Data field ...  |

  LTE UMD PDU (TS 36.322) — 5-bit SN shown:
   0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |FI |E|   SN    |   FI = 2-bit Framing Info (is first/last byte a segment boundary?)
  +-+-+-+-+-+-+-+-+   E  = extension: a Length-Indicator (LI) list follows
  | E | LI(11 bits)..|   (LI/E pairs describe multiple packed SDUs; SN also comes in 10-bit)
  +------------------+

  AM adds ARQ on top of the same idea (TS 38.322 §6.2.2.4):
   +-+-+-+-+-...
   |D/C|P|SI| SN ...   D/C=data/control, P=POLL bit (ask peer for a status report)
   +-+-+-+-+-...        + SO(16) for segments, same as UM
   AM STATUS PDU (D/C=0): D/C|CPT|ACK_SN|E1|NACK_SN|... → per-SN ACK/NACK for retransmission
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | **SN** | Sequence Number — orders PDUs and keys reassembly/reordering. NR UM 6/12-bit, AM 12/18-bit; LTE UM 5/10-bit, AM 10/16-bit. |
  | **SI** (NR) / **FI** (LTE) | Marks whether this PDU is a whole SDU or a first/middle/last **segment**. Drives the reassembly buffer. |
  | **SO** | Segment Offset — byte position of this segment within the original SDU. The **length/offset surface** for reassembly bugs. |
  | **LI/E** (LTE) | Length Indicators + extension bits packing multiple SDUs into one PDU. |
  | **P** (AM) | Poll bit — sender requests a STATUS PDU. |
  | **ACK_SN / NACK_SN** (AM STATUS) | Which SNs the receiver got / is missing → triggers ARQ retransmission. |
- **Beginner notes / gotchas:** **TM** has literally no header (used for broadcast/paging/RACH msg-carrying
  where framing is fixed). The single biggest confusion is that RLC, PDCP, and even NAS/RRC *all* have their
  own **sequence number** — an "SN" is meaningless without saying which layer. Reassembly holds partial data
  in a per-bearer buffer keyed by SN/SO; mismatches between the *claimed* segment length/offset and the
  *actual* bytes are exactly where memory-safety bugs hide.
- **Security relevance:** RLC reassembly is a **pre-security parser** (runs below PDCP ciphering on the
  downlink) and is driven by the radio peer — the SN/SO/LI fields decide how much is copied where. This is
  structurally the same class of bug as this project's headline finding **F6** (NR *SI* segment reassembly,
  an unbounded copy-before-check at `NL1_CTRL_Nrrc_Reconstruct_Raw_Data`, T0 broadcast). The LTE/NR **RLC
  SAR path itself was audited and found bounded**, and the 2G **RLC→LLC reassembly** was confirmed clean
  (LI/E scan pre-validated, destination sized to `pdulen`) — see Appendix A. Treat the length/offset arithmetic
  as the first thing to check on any RLC handler.

---

## PDCP — Packet Data Convergence Protocol
- **What it is / meaning:** **PDCP** = *Packet Data Convergence Protocol*, the **top L2 sublayer** in
  LTE/NR, sitting **above RLC** and just below RRC/SDAP/IP. It is where the **radio-link cryptography
  lives**: ciphering and, for signalling, integrity protection. It also compresses IP headers (**ROHC**)
  and handles reordering/duplicate discard during handovers.
- **Purpose:**
  - **Ciphering** (confidentiality) of both user data (DRBs) and signalling (SRBs).
  - **Integrity protection** — appends a 32-bit **MAC-I** tag to SRB PDUs (and optionally DRBs in NR).
  - **ROHC** header compression to shrink IP/UDP/RTP headers over the air.
  - Reordering, duplicate detection, and in-order delivery across handover.
- **Specification:** LTE **TS 36.323** (`https://www.3gpp.org/dynareport?code=36.323.htm`), NR **TS 38.323**
  (`https://www.3gpp.org/dynareport?code=38.323.htm`). Tutorial:
  `https://www.sharetechnote.com/html/5G/5G_PDCP.html`.
- **Packet / PDU disposition:**
  ```
  NR PDCP Data PDU, 12-bit SN (TS 38.323 §6.2.2.1):
   0 1 2 3 4 5 6 7  0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+
  |D|R R R| SN(hi)| |     SN(lo)    |   D/C=1 data / 0 control, R=reserved
  +-+-+-+-+-+-+-+-+ +-+-+-+-+-+-+-+-+   SN = 12 bits (or 18-bit variant → 3-octet header)
  |          Data (ciphered) ...      |
  +-----------------------------------+
  |   MAC-I (32 bits)  — SRBs only    |   integrity tag, at the END of the PDU
  +-----------------------------------+
  ```
  LTE uses SN sizes **7 / 12 / 15 / 18** bits; NR uses **12 / 18**. The header byte layout follows the same
  `D/C · R… · SN` shape (exact reserved-bit counts per TS — verify per SN size).
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | **D/C** | Data/Control bit. 1 = Data PDU (carries SDU), 0 = Control PDU (ROHC feedback, status report). |
  | **SN** | PDCP Sequence Number — feeds the deciphering **COUNT** and reordering. |
  | **Data** | The (ciphered) payload — an SDAP PDU / IP packet (DRB) or an RRC/NAS message (SRB). |
  | **MAC-I** | 32-bit **Message Authentication Code for Integrity** — the crypto tag, present on SRBs. **This is the crypto "MAC", not the MAC sublayer.** |
- **Beginner notes / gotchas:** PDCP is the crypto boundary: below it (RLC/MAC/PHY) everything is on
  ciphertext; above it RRC/NAS see plaintext. The **MAC-I** at the tail is the second meaning of "MAC"
  from the boxed note — a phone verifies MAC-I to know a message really came from the network. **ROHC**
  decompression is itself a non-trivial parser (state machine over compressed headers) and a classic
  attack surface distinct from the header above.
- **Security relevance:** PDCP is the layer that *decides* whether data is authentic, so ordering bugs
  matter enormously: if an SRB message is **unpacked/acted on before its MAC-I is verified**
  ("unpack-then-verify"), an attacker without keys can reach L3 parsers pre-auth — this is precisely the
  T1-vs-T4 question raised across findings **F3/F4/F5** (`../../F3.md`, `../../F5.md`). ROHC decompression
  and the SN/reordering buffer are additional pre-plaintext surfaces. Note: for 5GMM this project resolved
  the order as **verify-before-unpack** for the Registration-Accept class (Appendix C item 3), i.e. those
  specific paths are T4.

---

## SDAP — Service Data Adaptation Protocol
- **What it is / meaning:** **SDAP** = *Service Data Adaptation Protocol*, the **top of the 5G NR L2 stack**,
  above PDCP. It is **NR-only** (introduced in 5G; LTE has no SDAP). It maps **QoS flows** (how 5G describes
  per-application quality of service) onto **Data Radio Bearers (DRBs)**.
- **Purpose:**
  - Map each **QoS flow** (identified by a **QFI**) to the correct DRB, in both directions.
  - Optionally mark packets so the peer can (re)learn the flow↔bearer mapping (reflective QoS).
  - Carry the QoS Flow ID inline so the receiver can reconstruct QoS treatment.
- **Specification:** NR **TS 37.324** (`https://www.3gpp.org/dynareport?code=37.324.htm`). Tutorial:
  `https://www.sharetechnote.com/html/5G/5G_SDAP.html`.
- **Packet / PDU disposition:**
  ```
  SDAP Data PDU header — 1 byte (TS 37.324 §6.2):
   0 1 2 3 4 5 6 7
  +-+-+-----------+
  |D|R|    QFI    |   D/C = data/control (UL); R = reserved
  +-+-+-----------+   QFI = 6-bit QoS Flow Identifier
  |   SDU (IP pkt)|   (DL header uses RDI/RQI in place of D/C·R — same 6-bit QFI)
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | **QFI** | 6-bit **QoS Flow ID** — which of up to 64 QoS flows this packet belongs to. The core field. |
  | **D/C** | Data/Control indicator (uplink header). |
  | **R** | Reserved bit. |
  | **(RDI/RQI)** | On the downlink header: Reflective-QoS-flow-to-DRB Indication / Reflective-QoS Indication — tell the UE to update mappings. |
- **Beginner notes / gotchas:** SDAP is **tiny** (a single byte) and can even be *absent* — it is configured
  per-DRB by RRC, so a bearer may run PDCP directly over IP with no SDAP header at all. It only exists on
  **DRBs (user data)**, never on SRBs (signalling). "QoS flow" (NR) is the successor to the LTE "EPS bearer"
  QoS model — don't confuse the flow (QFI) with the radio bearer (DRB) it maps to.
- **Security relevance:** SDAP sits **above PDCP**, so by the time bytes reach it they are already
  deciphered and (if configured) integrity-checked — it is therefore **post-security** on protected
  bearers and a low-priority surface. Its content is user-plane IP data, not signalling. No finding in this
  project lives at SDAP.

---

## LLC — Logical Link Control (2G GPRS)
- **What it is / meaning:** **LLC** = *Logical Link Control*, an L2 sublayer used only in **2G GPRS/EGPRS**
  (packet-switched data on GSM). It provides a **logical link between the phone and the SGSN** (the packet
  core node), running **above RLC/MAC** and **below SNDCP**. It is the GPRS analogue of what PDCP+RLC-AM do
  in LTE: reliable, ciphered, addressed frames.
- **Purpose:**
  - Provide reliable (ARQ) or unacknowledged logical-link transfer between UE and SGSN.
  - Address multiple higher-layer entities via **SAPI** (Service Access Point Identifier).
  - Ciphering of GPRS user/signalling data; frame integrity via an **FCS**.
- **Specification:** **TS 44.064** (`https://www.3gpp.org/dynareport?code=44.064.htm`).
- **Packet / PDU disposition:**
  ```
  LLC frame (TS 44.064 §6):
  +------------------+-------------------------+---------------------+----------------+
  | Address (1 oct)  | Control (1–3+ octets)   | Information (var)    | FCS (3 octets) |
  +------------------+-------------------------+---------------------+----------------+

  Address octet:
   0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |P|C|X X| SAPI  |   PD = protocol discriminator (0), C/R = command/response,
  +-+-+-+-+-+-+-+-+   X = spare, SAPI = 4-bit service access point identifier

  Control field formats: I (Information, numbered+ACKed), S (Supervisory, flow/ACK),
                         UI (Unconfirmed Information, unnumbered), U (Unnumbered control).
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | **SAPI** | 4-bit Service Access Point Identifier — which higher-layer service (e.g. GMM signalling vs user data) the frame serves. |
  | **PD** | Protocol Discriminator bit in the address (spare, set 0). |
  | **C/R** | Command/Response bit. |
  | **Control** | Selects frame type: **I** / **S** / **UI** / **U**, carrying sequence numbers (N(S)/N(R)) for the ARQ modes. |
  | **FCS** | 24-bit **Frame Check Sequence** — error-detection checksum over the frame. |
- **Beginner notes / gotchas:** LLC exists **only in the GPRS packet-switched path** — circuit-switched
  voice/SMS does not use it. Its "SAPI" is a GPRS concept and is unrelated to the LAPDm SAPI on the
  CS control channel. The variable-length **control field** (1–3 octets depending on I/S/UI/U format) is
  the parsing subtlety.
- **Security relevance:** LLC is an early PS-domain parser reached over the 2G radio (fake-BTS territory).
  In this project the **LLC XID** parameter negotiation and **RLC→LLC reassembly** were audited and found
  correctly bounded (Appendix A, `../../99_APPENDIX.md`). No finding lives here.

---

## SNDCP — Subnetwork Dependent Convergence Protocol (2G GPRS)
- **What it is / meaning:** **SNDCP** = *SubNetwork Dependent Convergence Protocol*, the **top of the 2G
  GPRS user-plane L2 stack**, above LLC. It is the GPRS analogue of **PDCP/SDAP**: it multiplexes several
  packet data flows over LLC, compresses headers/data, and segments network-layer packets (**N-PDUs**,
  typically IP) to fit LLC frames.
- **Purpose:**
  - Multiplex multiple **PDP contexts** (data sessions) onto LLC links via **NSAPI**.
  - **Segmentation/reassembly** of N-PDUs (IP packets) into LLC-sized SN-PDUs.
  - **Header compression (PCOMP)** and **data compression (DCOMP)** to save radio bandwidth.
- **Specification:** **TS 44.065** (`https://www.3gpp.org/dynareport?code=44.065.htm`).
- **Packet / PDU disposition:**
  ```
  SNDCP SN-DATA PDU header (TS 44.065 §7):
   0 1 2 3 4 5 6 7
  +-+-+-+-+-+-+-+-+
  |X|F|T|M| NSAPI |   X=spare, F=First-segment, T=SN-DATA vs SN-UNITDATA type, M=More-segments
  +-+-+-+-+-+-+-+-+
  | DCOMP | PCOMP |   DCOMP = data-compression id, PCOMP = protocol(header)-compression id
  +-------+-------+
  |  N-PDU number / segment number (per type) ...                     |
  +-------------------------------------------------------------------+
  |  Data segment ...                                                 |
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | **NSAPI** | 4-bit Network-layer SAP Identifier — which PDP context / data session this belongs to. |
  | **F** / **M** | First-segment / More-segments flags — drive reassembly of a fragmented N-PDU. |
  | **T** | PDU type (SN-DATA acknowledged vs SN-UNITDATA unacknowledged). |
  | **DCOMP / PCOMP** | 4-bit identifiers selecting the negotiated data- and header-compression contexts. |
  | **X** | Spare bit. |
- **Beginner notes / gotchas:** SNDCP is where **N-PDU segmentation** happens in GPRS, so — like RLC/PDCP
  above — it maintains reassembly buffers keyed by segment flags and numbers. **NSAPI** (SNDCP) ≠ **SAPI**
  (LLC): NSAPI names the *data session*, SAPI names the *LLC service*. Compression (DCOMP/PCOMP) points at
  negotiated state, so a value referencing an unestablished context is an edge case.
- **Security relevance:** SNDCP reassembly and its compression handling are pre-/early-auth PS-domain
  parsers on the 2G path (fake-BTS reachable). They belong to the same 2G GSM/GPRS lower-layer surface that
  this project audited and cleared as bounded (Appendix A). No finding lives here; the segmentation and
  compression-context lookups remain the fields to scrutinize on any re-audit.
