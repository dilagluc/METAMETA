# Messaging services: SMS, Cell Broadcast, and Public Warning (ETWS/CMAS)

These three are **application/messaging services** rather than transport layers. **SMS** (point-to-point
text) is carried *inside* NAS signalling — it rides on the control plane of GSM/UMTS/LTE (and over IMS in
5G), so it reaches the modem even when there is no active call or data session. **Cell Broadcast (CBS)** and
the **Public Warning System (ETWS/CMAS)** are *one-way broadcasts*: the network transmits them to every
handset in a cell, with no per-subscriber connection and — importantly — no authentication or ciphering.
For the big-picture stack (NAS, RRC, the L1/L2/L3 split), see `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md`.

Why these matter for security: SMS is a classic **"zero-click"** surface — an incoming message is *parsed
by the modem on delivery*, before (and independently of) any user tap or notification. Broadcast services
are **pre-authentication** by design: the UE decodes warning payloads while merely camped on a cell, so a
rogue base station can inject them freely.

**Contents**
- [SMS — Short Message Service (point-to-point)](#sms--short-message-service-point-to-point)
- [CBS / SMS-CB — Cell Broadcast Service](#cbs--sms-cb--cell-broadcast-service)
- [ETWS / CMAS — Public Warning System (PWS)](#etws--cmas--public-warning-system-pws)

---

## SMS — Short Message Service (point-to-point)

- **What it is / meaning:** SMS = **Short Message Service**, the store-and-forward text service. It is used
  by GSM (2G), UMTS (3G), LTE (4G, "SMS over SGs / SMS in MME") and, over IMS, by 5G. SMS is not its own
  radio layer — it is a small **three-sublayer protocol suite** that travels as payload inside NAS Mobility
  Management messages (`CP-DATA`) on the control plane. From bottom to top the three sublayers are:
  - **CP — SM-Control Protocol** (TS 24.011): the transport that reliably shuttles one SMS-relay PDU
    between MS and network using `CP-DATA`/`CP-ACK`/`CP-ERROR` and a retransmission timer.
  - **RP — SM-Relay Protocol** (TS 24.011): routes the message between the MS and the SMS Service Centre
    (SMSC/SC) with `RP-DATA`/`RP-ACK`/`RP-ERROR`/`RP-SMMA`; carries the SC address and a reference number.
  - **TP — SM-Transfer Protocol** (TS 23.040): the actual message content — the **TPDU** (Transfer
    Protocol Data Unit), e.g. `SMS-DELIVER` (network→MS) and `SMS-SUBMIT` (MS→network).

  So the nesting on the wire is: `CP-DATA { RP-DATA { TPDU } }`.
- **Purpose:**
  - Deliver a short text/binary message store-and-forward via an SMSC, with no live end-to-end session.
  - Provide delivery acknowledgement and status reports (RP-ACK, SMS-STATUS-REPORT).
  - Carry binary/OTA payloads (SIM toolkit, MMS notifications, configuration) via the TP-PID/DCS and UDH.
- **Specification:**
  - Transport CP/RP: **3GPP TS 24.011** — https://www.3gpp.org/dynareport?code=24.011.htm
  - Application/TPDU: **3GPP TS 23.040** — https://www.3gpp.org/dynareport?code=23.040.htm
  - Data coding (alphabets/DCS): **3GPP TS 23.038** — https://www.3gpp.org/dynareport?code=23.038.htm
  - Overview/walk-through: https://www.sharetechnote.com/ (search "SMS", "TPDU").
- **Packet / PDU disposition (how it looks on the wire):**

  The full encapsulation (each layer prepends its own header):
  ```
  +--------- CP (TS 24.011) ---------------------------------------------+
  | TI/PD | CP-MTI | CP-User-Data =                                      |
  |       |        |  +------- RP (TS 24.011) --------------------------+ |
  |       |        |  | RP-MTI | RP-MR | RP-OA | RP-DA | RP-User-Data = | |
  |       |        |  |        |       |       |       |  [ TPDU ]      | |
  |       |        |  +------------------------------------------------+ |
  +---------------------------------------------------------------------+
  ```

  **SMS-DELIVER TPDU** (SC → MS), TS 23.040 §9.2.2.1 — first octet is a bit-field, then variable fields:
  ```
  Octet 0  (first octet):
   bit  7      6       5      4     3      2       1  0
       TP-RP TP-UDHI TP-SRI  (-)  TP-LP  TP-MMS   TP-MTI = 00b
  ------------------------------------------------------------------
  TP-OA   : Originating Address  (2–12 octets)
            +--------+--------+-----------------------------+
            | AddrLen| TOA    | address digits (BCD, nibble-|
            | (semi- | 1 oct  | swapped)                    |
            | octets)|        |                             |
            +--------+--------+-----------------------------+
            TOA: bit7=1 | bits6-4 Type-of-Number | bits3-0 Numbering-Plan
  TP-PID  : Protocol Identifier            (1 octet)
  TP-DCS  : Data Coding Scheme             (1 octet)   -> see TS 23.038
  TP-SCTS : Service-Centre Time Stamp      (7 octets, BCD, nibble-swapped:
                                            YY MM DD HH MM SS TZ)
  TP-UDL  : User-Data-Length               (1 octet)
  TP-UD   : User Data                       (0..140 octets; may start with UDH)
  ```

  **SMS-SUBMIT TPDU** (MS → SC), TS 23.040 §9.2.2.2 — same idea, different first octet and header order:
  ```
  Octet 0:
   bit  7      6       5      4  3        2      1  0
       TP-RP TP-UDHI TP-SRR  TP-VPF     TP-RD   TP-MTI = 01b
  TP-MR  : Message Reference  (1 octet)
  TP-DA  : Destination Address (2–12 octets, same layout as TP-OA)
  TP-PID, TP-DCS,
  TP-VP  : Validity Period (0 / 1 / 7 octets, per TP-VPF)
  TP-UDL, TP-UD
  ```

  **UDH — User Data Header** (present when `TP-UDHI = 1`), TS 23.040 §9.2.3.24. It sits at the *start* of
  TP-UD and is a length-prefixed list of TLV-style Information Elements:
  ```
  +------+---------------------------------------------------------------+
  | UDHL | IE #1 | IE #2 | ...                          | then SM text   |
  +------+---------------------------------------------------------------+
  each IE:  +------+------+---------------+
            | IEI  | IEDL | IE-Data (IEDL octets)
            +------+------+---------------+
  e.g. Concatenated-SMS (8-bit ref):  IEI=0x00, IEDL=03,
        data = { ref-number(1) | total-parts(1) | sequence-number(1) }
       Concatenated-SMS (16-bit ref): IEI=0x08, IEDL=04, ref = 2 octets
  ```

- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | TP-MTI | Message Type: `00`=DELIVER, `01`=SUBMIT (`10`=STATUS-REPORT / COMMAND) |
  | TP-MMS | More-Messages-to-Send: SC has more messages queued |
  | TP-RP | Reply-Path: a reply may be sent back via the same SC |
  | TP-UDHI| User-Data-Header-Indicator: TP-UD begins with a UDH |
  | TP-SRI/SRR | Status-Report Indication (deliver) / Request (submit) |
  | TP-OA / TP-DA | Originating / Destination address: `AddrLen` counts **semi-octets** (BCD digits), then a Type-of-Address octet, then nibble-swapped BCD digits |
  | TP-PID | Protocol Identifier (e.g. telematic interworking, SIM-data-download) |
  | TP-DCS | Data Coding Scheme — selects alphabet (GSM-7 / 8-bit / UCS2) and message class |
  | TP-SCTS| Timestamp the SC received the message (7 BCD octets incl. timezone) |
  | TP-UDL | User-data length: in **septets** for GSM-7, in **octets** for 8-bit/UCS2 |
  | TP-UD  | The payload, optionally prefixed by UDH; ≤140 octets / 160 GSM-7 chars |

  **7-bit packing (TS 23.038 §6.1.2.1):** the default GSM alphabet is a **7-bit** code, so characters
  ("septets") are packed into 8-bit octets to save space. Septet *n*'s bits are shifted left by `n mod 7`;
  the high bit(s) of each octet are borrowed from the *next* septet. Eight 7-bit septets therefore pack
  into seven octets. Unpacking reverses it — a running "`% 7`" bit-shift ladder that reads a byte cursor
  through the packed buffer and emits one char per step (exactly the loop pattern exercised by finding F8,
  below). DCS bits 3–2 select the alphabet: `00` = GSM-7 default, `01` = 8-bit data, `10` = UCS2/16-bit.

- **Beginner notes / gotchas:**
  - Three "layers" but they are *not* the OSI L1/L2/L3 — CP/RP/TP all live *inside* one NAS message.
    People say "SMS PDU" loosely; be precise about whether they mean the CP-DATA frame, the RP-DATA, or
    the TPDU.
  - `TP-UDL` counts **septets** for GSM-7 but **octets** otherwise — a frequent parser bug.
  - Addresses are **semi-octet** (BCD) with swapped nibbles and an odd-length half-byte pad; the length
    field counts digits, not bytes.
  - CDMA/C2K (IS-637) SMS is a *different* encoding (bearer-data sub-parameters, not TS 23.040 TPDUs) even
    though the service looks identical to the user — see finding F1.
- **Security relevance:** SMS is the textbook **zero-click** remote surface: an MT (mobile-terminated)
  message is decoded by the modem's SMS stack on arrival, *before* any user interaction, so every parser
  along CP→RP→TP→UDH→7-bit-unpack is attacker-reachable by simply sending a message to the victim's number
  (reachability **T2 — remote via network service**; also injectable from a rogue base station, T1-style).
  This project's finding **F1** lives exactly here: `ValSmsProcessDeliverParaMsg` decodes an MT CDMA
  SMS-DELIVER and a "type-174" sub-parameter's **record count is clamped for the stored copy but re-read
  unclamped as the loop bound**, giving a ~7 KB attacker-controlled `.bss` out-of-bounds write (see
  `../../F1.md`). Attacker-controlled data enters at every variable-length TP-* field (TP-OA length,
  TP-UDL, UDH IEDL, and the CDMA bearer-data counts) — all post-SMSC but with **no attacker↔UE
  authentication required**.

---

## CBS / SMS-CB — Cell Broadcast Service

- **What it is / meaning:** CBS = **Cell Broadcast Service** (also written **SMS-CB**, "SMS Cell
  Broadcast"). It is a *one-to-many, one-way* text broadcast: the network pushes short messages to **all
  UEs camped on a cell or area**, unacknowledged and connectionless. There is no addressing of individual
  subscribers and no uplink. On GSM it is carried on the CBCH and framed by the **BMC** (Broadcast/Multicast
  Control) layer; on UMTS via BMC over RRC; on LTE/NR the payload is delivered inside RRC **System
  Information Blocks (SIBs)**. Typical uses: area info, weather, and — as a special case — public warnings
  (next section).
- **Purpose:**
  - Broadcast the same short message to every handset in one or more cells without per-user signalling.
  - Support long messages by **paging**: split content into pages ("page K of N").
  - Categorise messages by **Message Identifier** so a UE can subscribe/filter by topic.
- **Specification:**
  - **3GPP TS 23.041** — Technical realization of Cell Broadcast Service:
    https://www.3gpp.org/dynareport?code=23.041.htm
  - Coding of the content reuses **TS 23.038** (DCS + GSM-7 packing):
    https://www.3gpp.org/dynareport?code=23.038.htm
  - Overview: https://www.sharetechnote.com/ (search "Cell Broadcast", "ETWS").
- **Packet / PDU disposition (how it looks on the wire):**

  A **CBS message page** (classic GSM/BMC layout, TS 23.041 §9.4.1). Each page carries a 6-octet header +
  content; a GSM CBCH page is 88 octets, leaving 82 octets of content:
  ```
   0                   1
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
  +-------------------------------+
  |        Serial Number  (2 oct) |  GS(2b)|Msg-Code(10b)|Update-Number(4b)
  +-------------------------------+
  |     Message Identifier (2 oct)|  topic / source (ETWS & CMAS use fixed ranges)
  +---------------+
  | DCS (1 octet) |                 Data Coding Scheme (TS 23.038)
  +---------------+
  | Page Parameter|                 bits7-4 = page number K, bits3-0 = total N
  +---------------+---------------------------------------------------+
  | CB-Data / Content of Message  (82 octets)                         |
  |   = up to 93 GSM-7 septets  (82 octets * 8 / 7 = 93 chars)        |
  +-------------------------------------------------------------------+
  ```
  On UMTS/LTE/NR the same logical fields (Serial Number, Message Identifier, DCS, and the warning content)
  are re-packaged into RRC SIB structures instead of the raw 88-octet CBCH page.

- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | Serial Number | Identifies a *version* of a message: **Geographical Scope** (2b), **Message Code** (10b), **Update Number** (4b). UE uses it to detect new/updated broadcasts |
  | Message Identifier | The "channel"/topic; specific ranges are reserved for ETWS and CMAS/PWS |
  | DCS | Data Coding Scheme — alphabet + language indication (TS 23.038) |
  | Page Parameter | "page K of N" — lets a UE reassemble a multi-page message |
  | Content of Message | The text, ≤ 82 octets per page = up to 93 GSM-7 characters |

- **Beginner notes / gotchas:**
  - "SMS-CB" shares the *name* and the *coding* (TS 23.038) with point-to-point SMS but is a **completely
    different delivery model** — broadcast, unacknowledged, no SMSC, no CP/RP/TP sublayers.
  - The content is still **7-bit packed** when DCS says GSM-7, so the same 7→8 septet unpack runs here.
  - "Page K of N" is *not* the same mechanism as concatenated-SMS UDH; it is a CBS-native field.
- **Security relevance:** CBS is a **pre-authentication, broadcast** surface — the UE decodes pages while
  merely camped on a cell, so a rogue base station (an IMSI-catcher / SDR cell the UE latches onto) can
  transmit arbitrary CB pages that the modem parses with no authentication or integrity check. This
  project's finding **F8** lives here: `smsal_decode_cb_page` (`0x90bfb952`) performs the **GSM-7
  septet→octet unpack** of a CB page with an index/length-driven `% 7` bit-shift loop writing into a
  caller buffer by a byte cursor — the classic packed-GSM unpack shape that hosts memory-safety bugs when
  the page length/cursor is attacker-influenced. Broadcast reception makes this a **T0 broadcast attack
  surface** (see ETWS below).

---

## ETWS / CMAS — Public Warning System (PWS)

- **What it is / meaning:** The **Public Warning System (PWS)** is the emergency-alert overlay on top of
  Cell Broadcast. **ETWS = Earthquake and Tsunami Warning System** (originating in Japan; fast, low-latency
  alerts). **CMAS = Commercial Mobile Alert System** (the US scheme; also deployed as WEA — Wireless
  Emergency Alerts; the European equivalent is EU-Alert / KPAS in Korea). Both are broadcast to every UE in
  the warning area, connectionless and unauthenticated, and are carried as CBS payloads inside RRC System
  Information. PWS defines **two tiers of notification**:
  - **Primary notification** — a tiny, latency-critical alert (warning type + minimal info + a serial
    number). It is signalled fast: the UE is told via **Paging** (an ETWS/CMAS indication) to read a
    dedicated SIB, so an alerted phone can vibrate/alarm within seconds.
  - **Secondary notification** — the full warning **message text**, delivered in a warning-message SIB or
    over ordinary CB, and reassembled/displayed to the user.
- **Purpose:**
  - Broadcast life-safety warnings to all handsets in an area with minimal latency.
  - Wake/alert even idle UEs via paging-triggered primary notification.
  - Carry human-readable warning text (secondary notification) with language and severity coding.
- **Specification:**
  - Content & realization: **3GPP TS 23.041** — https://www.3gpp.org/dynareport?code=23.041.htm
  - LTE carriage in SIBs: **3GPP TS 36.331** (RRC) — https://www.3gpp.org/dynareport?code=36.331.htm
  - NR carriage in SIBs: **3GPP TS 38.331** (RRC) — https://www.3gpp.org/dynareport?code=38.331.htm
- **Packet / PDU disposition (how it looks on the wire):**

  PWS reuses the CBS fields (Serial Number, Message Identifier, DCS, content) but maps them onto specific
  RRC **SIBs**, chosen by the paging indication:
  ```
  Paging (with ETWS / CMAS indication)  --> UE reads the matching SIB
  ------------------------------------------------------------------------
  LTE  (TS 36.331):
    SIB10  = ETWS  primary   notification   { messageIdentifier,
                                              serialNumber,
                                              warningType, [security info] }
    SIB11  = ETWS  secondary notification   { warningMessageSegment (paged),
                                              dataCodingScheme, ... }
    SIB12  = CMAS  warning   notification   { warningMessageSegment, DCS, ... }
  NR   (TS 38.331):
    SIB6   = ETWS  primary
    SIB7   = ETWS  secondary
    SIB8   = CMAS  warning
  ------------------------------------------------------------------------
  Secondary/warning text = same CB "page K of N" content, GSM-7 / UCS2 coded.
  ```

- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | Message Identifier | Distinguishes ETWS vs CMAS and the alert category (reserved ranges) |
  | Serial Number | Version/update of the warning (UE de-duplicates on it) |
  | warningType (primary) | Coded hazard type (earthquake, tsunami, test, …) + user-alert/popup flags |
  | warningMessageSegment (secondary) | A segment of the reassembled warning text (paged) |
  | dataCodingScheme | Alphabet/language of the text (TS 23.038) |
  | (optional) warningSecurityInfo | A timestamp + digital-signature field defined for ETWS primary — **rarely, if ever, deployed/enforced** |

- **Beginner notes / gotchas:**
  - Primary vs secondary is about **speed vs content**: primary wakes you fast; secondary carries the
    words. Both are just SIB-wrapped CBS.
  - The SIB numbers differ between LTE (10/11/12) and NR (6/7/8) — easy to mix up.
  - There is an *optional* digital signature in the spec, but in practice PWS is treated as **unsecured
    broadcast** — no ciphering, no integrity the UE actually verifies.
- **Security relevance:** ETWS/CMAS is the canonical **T0 broadcast surface** — decoded by every idle UE
  camped on a cell, **pre-authentication and unauthenticated**. A rogue base station (SDR) that a UE
  attaches to (or simply broadcasts SI that idle UEs read) can emit arbitrary primary/secondary
  notifications; there is no cryptographic gate before the modem parses them. This makes it the *widest*
  reach, lowest-precondition attack surface in the messaging family: it feeds the same CBS/GSM-7 decode
  paths as finding **F8** (`smsal_decode_cb_page`), but without even needing to send a message to a
  specific victim — any handset in radio range that reads the SIB is exposed. Beyond memory-safety, PWS is
  also abused for **spoofed emergency alerts** (fake warnings) precisely because the broadcast is
  unauthenticated by design.
