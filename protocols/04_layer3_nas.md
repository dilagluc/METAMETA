# Layer 3 — Non-Access-Stratum (NAS) signalling protocols

NAS ("Non-Access Stratum") is the set of **L3** protocols the phone (UE) uses to talk **through** the
base station to the operator's **core network** — registration, authentication, session/bearer setup,
SMS. It is the counterpart to the *Access Stratum* (RRC/RR, which talks to the base station itself); see
`../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` for where AS and NAS sit in the stack. This file covers the eight NAS
sublayers across four generations, plus the two things every NAS attacker cares about: the **message
header** (where the security bit lives) and the **information-element (IE) encoding rules** (where the
length octets that drive overflows live).

### Contents
- [NAS framing — the common message header](#nas-framing--the-common-message-header)
- [IE encoding formats (TS 24.007): T / V / TV / LV / TLV / TLV-E / LV-E](#ie-encoding-formats-ts-24007-t--v--tv--lv--tlv--tlv-e--lv-e)
- [Worked example: a 5GMM REGISTRATION ACCEPT skeleton](#worked-example-a-5gmm-registration-accept-skeleton)
- [MM — Mobility Management (2G/3G CS)](#mm--mobility-management-2g3g-cs)
- [CC — Call Control (2G/3G CS)](#cc--call-control-2g3g-cs)
- [SMS — Short Message Service transport (2G/3G, shared)](#sms--short-message-service-transport-2g3g-shared)
- [GMM — GPRS Mobility Management (2G/3G PS)](#gmm--gprs-mobility-management-2g3g-ps)
- [SM — Session Management (2G/3G PS)](#sm--session-management-2g3g-ps)
- [EMM — EPS Mobility Management (4G)](#emm--eps-mobility-management-4g)
- [ESM — EPS Session Management (4G)](#esm--eps-session-management-4g)
- [5GMM — 5GS Mobility Management (5G)](#5gmm--5gs-mobility-management-5g)
- [5GSM — 5GS Session Management (5G)](#5gsm--5gs-session-management-5g)

> **The one mental model.** Every NAS message begins with a **Protocol Discriminator (PD)** that says
> *which of these sublayers* owns the message, and a **Message Type** that says *which message*. In 4G/5G
> mobility-management messages, the half-octet that would otherwise be a "skip indicator" instead carries
> a **Security Header Type** — and that single field decides whether the rest of the message is plaintext
> or wrapped in a cryptographic envelope. Whether the firmware parses IEs *before* or *after* checking
> that envelope is the difference between a **pre-auth** (anyone with a radio) and a **post-auth** (needs
> valid keys) bug. See `../../PREAUTH_POSTAUTH_EXPLAINER.md`.

---

## NAS framing — the common message header

**Specification:** framing and PD rules are defined in **3GPP TS 24.007**
(<https://www.3gpp.org/dynareport?code=24.007.htm>), §11.2.3 (protocol discriminator, skip/security
header) and §11.2. The per-generation message layouts live in TS 24.008 / 24.301 / 24.501.

**Protocol Discriminator (PD).** A 4-bit value in the first octet (TS 24.007 §11.2.3.1.1). The ones you
meet in this report:

| PD (binary / hex) | Sublayer |
|---|---|
| `0011` / 3 | Call Control (CC) |
| `0101` / 5 | Mobility Management (MM) |
| `0110` / 6 | Radio Resources (RR) — *AS, not NAS* |
| `0111` / 7 | EPS Mobility Management (EMM) |
| `1000` / 8 | GPRS Mobility Management (GMM) |
| `1001` / 9 | SMS |
| `1010` / 10 | GPRS Session Management (SM) |
| `0010` / 2 | EPS Session Management (ESM) |
| `0x7E` (full octet) | 5GS Mobility Management (5GMM) — *Extended PD* |
| `0x2E` (full octet) | 5GS Session Management (5GSM) — *Extended PD* |

Note the 5G change: 5G NAS uses an **Extended Protocol Discriminator (EPD)** that occupies a **whole
octet** (`0x7E` / `0x2E`), so the security-header half-octet moves to octet 2.

### (a) Plain NAS message (no security envelope)

```
 2G/3G MM/GMM (TS 24.008)          4G EMM (TS 24.301)              5G 5GMM (TS 24.501)
 7 6 5 4 3 2 1 0                   7 6 5 4 3 2 1 0                 7 6 5 4 3 2 1 0
+-------+-------+                 +-------+-------+               +---------------+
| Skip  |  PD   |  octet 1        | SecHdr|  PD   |  octet 1      | Extended PD   | octet 1 (0x7E)
| Ind.  |       |                 | Type  | (0x7) |               +-------+-------+
+-------+-------+                 +-------+-------+               | Spare | SecHdr| octet 2
| Message Type  |  octet 2        | Message Type  |  octet 2      +-------+-------+
+---------------+                 +---------------+               | Message Type  | octet 3
| info elements |                 | info elements |               +---------------+
      ...                               ...                       | info elements |
```

- **PD** — 4 bits, selects the sublayer (table above).
- **Skip Indicator** (2G/3G MM/GMM) — 4 bits, normally `0000`; a message with a non-zero skip indicator
  is ignored. (CC and SM use this half-octet as a **Transaction Identifier / procedure transaction id**
  instead — see those sections.)
- **Security Header Type** (EMM/5GMM) — 4 bits; **`0` here means "this is a plain message"** (see below).
- **Message Type** — 1 octet, the opcode (e.g. 5GMM REGISTRATION ACCEPT = `0x42`).

Note that 5GSM and ESM messages carry extra header fields (bearer identity / PDU-session identity /
procedure transaction identity) — shown in their sections.

### (b) Security-protected NAS message (EMM and 5GMM only)

Once a NAS security context exists, mobility-management messages are wrapped in an integrity/cipher
envelope. The header stays in the clear; everything after the sequence number is the **original NAS
message, ciphered** (TS 24.301 §9.1 / TS 24.501 §9.1.1):

```
 EMM (TS 24.301 §9.1)                      5GMM (TS 24.501 §9.1.1)
+-------+-------+                          +---------------+
| SecHdr|  PD   |  octet 1                 | Extended PD   |  octet 1 (0x7E)
| Type  | (0x7) |                          +-------+-------+
+-------+-------+                          | Spare | SecHdr|  octet 2  (type = 1..4)
| Message Auth  |  octets 2-5              +-------+-------+
| Code  (MAC,   |   (4 octets)             | Message Auth  |  octets 3-6
| 32 bits)      |                          | Code  (MAC,   |   (4 octets)
+---------------+                          | 32 bits)      |
| Sequence Num  |  octet 6                 +---------------+
+---------------+                          | Sequence Num  |  octet 7
| ciphered NAS  |  octet 7...              +---------------+
| message       |  (the plain header       | ciphered NAS  |  octet 8...
|   ...         |   of §(a) + IEs)         | message  ...  |
```

- **MAC — Message Authentication Code** — **4 octets**. A keyed integrity tag (EIA/NIA algorithm)
  computed over the sequence number + the plaintext NAS message. This is the signature the UE checks; a
  fake base station without the key cannot produce a valid one.
- **Sequence Number** — 1 octet, anti-replay counter; also feeds the cipher/integrity input.
- **ciphered NAS message** — the entire plain message from §(a) (its own PD + Security-Header-Type=0 +
  Message Type + IEs), encrypted when the header type says so.

**Security Header Type values** (EMM: TS 24.301 §9.3.1; 5GMM: TS 24.501 §9.3):

| Value | Meaning |
|---|---|
| `0` | **Plain** NAS message, *not* security protected (layout §(a)) |
| `1` | **Integrity protected** (has MAC, not ciphered) |
| `2` | **Integrity protected AND ciphered** (the steady-state case) |
| `3` | Integrity protected **with a new security context** (SECURITY MODE COMMAND) |
| `4` | Integrity protected + ciphered with a new security context (SECURITY MODE COMPLETE; LTE also uses 4/5 for SMC) |

> **Why this table is the crux of the report.** For a value-0 message there is nothing to verify, so the
> firmware parses the IEs immediately — **pre-auth**. For values 1–4 the firmware is *supposed* to verify
> the MAC before it unpacks. The recurring bug question is: *does the decoder run before or after that
> check?* If integrity is verified first, the bug needs valid keys (**T4**); if the unpacker runs first,
> the bug is reachable by any rogue base station (**T1**). Finding **F13** is exactly a flaw *inside* the
> integrity check itself (see EMM below).

---

## IE encoding formats (TS 24.007): T / V / TV / LV / TLV / TLV-E / LV-E

After the header, a NAS message is a sequence of **Information Elements (IEs)**. TS 24.007 §11.2.1.1
(<https://www.3gpp.org/dynareport?code=24.007.htm>) defines how each is framed. **T** = a 1-octet (or
½-octet) *type/identifier* tag called the **IEI**; **L** = a length octet; **V** = the value bytes.

```
 T   (Type only, type 2 IE — a presence flag, no value)
   +----------+
   |   IEI    |                       e.g. "Follow-on request" flag
   +----------+

 V   (Value only — no IEI, no length; length is fixed/known by position)
   +----------+----------+----
   |        value bytes       |
   +----------+----------+----

 TV  (Type + Value, fixed length; type 1 uses ½-octet IEI+value, type 3 uses 1-octet IEI)
   +----------+   +----------+----------+----
   |IEI | val |   |   IEI    |   value bytes  |
   +----------+   +----------+----------+----

 LV  (Length + Value; 1-octet length, no IEI — a MANDATORY variable IE)
   +----------+----------+----------+----
   |  length  |        value bytes       |    length counts the value octets (0..255)
   +----------+----------+----------+----

 TLV (Type + Length + Value; 1-octet length — an OPTIONAL variable IE)
   +----------+----------+----------+----------+----
   |   IEI    |  length  |        value bytes       |
   +----------+----------+----------+----------+----

 LV-E  (Length-Value Extended; **2-octet** length)
   +----------+----------+----------+----------+----
   | length hi| length lo|        value bytes       |    length 0..65535
   +----------+----------+----------+----------+----

 TLV-E (Type + 2-octet Length + Value; for large IEs)
   +----------+----------+----------+----------+----------+----
   |   IEI    | length hi| length lo|        value bytes       |
   +----------+----------+----------+----------+----------+----
```

TS 24.007 also names these by **format type**: type 1 (½-octet TV/V), type 2 (T, single-octet flag),
type 3 (fixed-length V/TV), type 4 (LV/TLV, 1-octet length), and **type 6 (LV-E/TLV-E, 2-octet length)**.
The extended (`-E`) forms were introduced for EPS/5GS because some IEs exceed 255 bytes — e.g. **LADN
information**, **PCO / extended PCO**, and **Operator-defined access category definitions**.

> **Where the overflow bugs live.** In every format that carries an `L`, that **length octet (or the
> 2-octet extended length, or a count field nested in the value) drives a copy loop**. If the decoder
> trusts it without clamping to the destination size, you get an out-of-bounds write. This is the exact
> shape of findings F3, F4, F5, F11, F12, and (as an *underflow*) F13. The extended `-E` lengths are
> especially dangerous: a 2-octet length reaches 65535, so an unclamped TLV-E copy can be tens of KB.

---

## Worked example: a 5GMM REGISTRATION ACCEPT skeleton

REGISTRATION ACCEPT (message type `0x42`, TS 24.501 §8.2.7) is the message a real network sends after
accepting the UE. It is normally sent **security-protected** (header type 2), so on the wire it is wrapped
in the §(b) envelope; below is the **inner plain message** the decoder sees after deciphering:

```
 octet 1     : 0x7E                      Extended protocol discriminator (5GMM)
 octet 2     : 0x00                      Spare(½) | Security Header Type = 0 (½)  [inner=plain]
 octet 3     : 0x42                      Message Type = REGISTRATION ACCEPT
 --- mandatory (no IEI) ---
 octet 4..5  : LV   len=1, value         5GS registration result   (LV)
 --- optional IEs, each starts with its IEI ---
 IEI 0x77 :  TLV-E  | len_hi len_lo | 5G-GUTI value ...            (5GS mobile identity, TLV-E)
 IEI 0x54 :  TLV    | len | TAI-list value ...                    (5GS tracking area identity list)
 IEI 0x15 :  TLV    | len | Allowed NSSAI value ...
 IEI 0x79 :  TLV-E  | len_hi len_lo | LADN information value ...   (<-- finding F4 lives here)
 IEI 0x34 :  TLV    | len | Emergency number list value ...        (<-- finding F5 lives here)
 IEI 0x76 :  TLV-E  | len_hi len_lo | Operator-defined access      (<-- finding F11 lives here)
                                       category definitions ...
```

Reading order: the decoder consumes the fixed header + mandatory LV, then walks the optional part IE by
IE — read one IEI byte, look it up, read its length (1 octet for TLV, 2 for TLV-E), then copy `length`
value bytes. **Three of this project's findings are IEs in this single message:** LADN (`0x79`, TLV-E),
Emergency number list (`0x34`, TLV), and Operator-defined access category (`0x76`, TLV-E) — each is a
length/count that a decoder copied without clamping.

---

## MM — Mobility Management (2G/3G CS)

- **What it is / meaning:** **MM = Mobility Management**, the circuit-switched (voice/SMS) mobility
  sublayer of GSM (2G) and UMTS (3G) NAS. It runs on L3 above the RR/RRC access stratum and talks to the
  core **MSC/VLR**. It handles the UE's *location* and *identity* on the CS domain and sets up the secure
  MM connection that CC and SMS then ride on. PD = `0101` (5).
- **Purpose:**
  - Location updating (registering the UE's location area with the MSC).
  - Authentication and TMSI reallocation (identity confidentiality).
  - IMSI attach/detach; providing an "MM connection" for CC/SS/SMS.
- **Specification:** **3GPP TS 24.008** (<https://www.3gpp.org/dynareport?code=24.008.htm>), §4 (MM
  procedures), §9.2 (MM message contents), §10 (IE coding). Framing per TS 24.007.
- **Packet / PDU disposition:**
  ```
   7 6 5 4 3 2 1 0
  +-------+-------+
  | Skip  |  PD=5 |  octet 1
  +-------+-------+
  | Message Type  |  octet 2   (bit 6 = "send sequence number" for some msgs)
  +---------------+
  | info elements |  octet 3...  (mix of V/TV/LV/TLV IEs)
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | PD | `0101` = MM |
  | Skip indicator | 4 bits, `0000`; non-zero ⇒ ignore message |
  | Message Type | e.g. LOCATION UPDATING REQUEST, AUTHENTICATION REQUEST, TMSI REALLOCATION COMMAND |
- **Beginner notes / gotchas:** MM is **CS-domain only**; its packet-domain twin is **GMM** (below). MM,
  CC and SMS are the classic "shared across 2G and 3G" trio — the *same* TS 24.008 message set is reused
  whether the radio is GSM or UMTS; only the access stratum below differs. Do not confuse MM (PD 5) with
  RR (PD 6, access stratum).
- **Security relevance:** Location-updating and identity/authentication messages are processed
  **pre-auth** (the UE has to answer AUTHENTICATION REQUEST before any key exists), making MM a classic
  fake-base-station attack surface. No headline finding in this file lands in 2G/3G MM specifically, but
  it is the template all later mobility sublayers (EMM, 5GMM) descend from.

---

## CC — Call Control (2G/3G CS)

- **What it is / meaning:** **CC = Call Control**, the sublayer that sets up, maintains and tears down
  **circuit-switched voice calls** in 2G/3G. It runs on top of an MM connection (MM must be established
  first) and talks to the MSC. PD = `0011` (3).
- **Purpose:**
  - Establish a call (SETUP / CALL PROCEEDING / ALERTING / CONNECT).
  - Modify and release calls (MODIFY, DISCONNECT, RELEASE).
  - Carry DTMF, in-band signalling, supplementary-service invocations.
- **Specification:** **3GPP TS 24.008** (<https://www.3gpp.org/dynareport?code=24.008.htm>), §5 (CC
  procedures), §9.3 (CC message contents).
- **Packet / PDU disposition:** CC replaces the skip indicator with a **Transaction Identifier (TI)** so
  several calls can run concurrently:
  ```
   7 6 5 4 3 2 1 0
  +-+-----+-------+
  |F| TI  |  PD=3 |  octet 1   (F = TI flag; TI value = 3 bits, "8" = TI extension)
  +-+-----+-------+
  | Message Type  |  octet 2
  +---------------+
  | info elements |  octet 3...
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | PD | `0011` = CC |
  | TI flag (F) | which side allocated the transaction |
  | TI value | 3-bit transaction id (distinguishes parallel calls) |
  | Message Type | SETUP, ALERTING, CONNECT, DISCONNECT, ... |
- **Beginner notes / gotchas:** CC is **only for CS voice**; VoLTE/VoNR calls do *not* use CC — they use
  SIP/IMS over the packet domain (a different world; see the VoLTE findings F2/F7 elsewhere). The
  Transaction Identifier here is the CS ancestor of the "PDU session id / procedure transaction id" you
  see in ESM/5GSM.
- **Security relevance:** CC messages arrive **only after** an MM connection (hence after
  authentication), so pure-CC parsing is effectively post-auth. No finding in this file is a CC decoder.

---

## SMS — Short Message Service transport (2G/3G, shared)

- **What it is / meaning:** SMS is carried as a **NAS transport** (PD = `1001`, 9). Above the NAS PD sit
  three sublayers: **CM/CP** (control protocol, TS 24.011) → **RP** (relay protocol, TS 24.011) → **TPDU**
  (the SMS-SUBMIT/SMS-DELIVER transfer protocol, TS 23.040). The same SMS stack is reused across 2G and 3G
  (and, tunnelled, in 4G/5G).
- **Purpose:**
  - Deliver short messages to/from the UE (mobile-terminated / mobile-originated).
  - Carry concatenation, class, and user-data-header (UDH) metadata for multi-part SMS.
- **Specification:** **TS 24.011** (CP/RP; <https://www.3gpp.org/dynareport?code=24.011.htm>) and **TS
  23.040** (TPDU / SMS-DELIVER; <https://www.3gpp.org/dynareport?code=23.040.htm>).
- **Packet / PDU disposition (RP → TPDU nesting, simplified):**
  ```
  +-------+-------+   CP header (PD=9 + TI)
  | Message Type  |   CP-DATA / CP-ACK / CP-ERROR
  +---------------+
  | RP header     |   RP-MTI, RP-MR, originator/destination address
  +---------------+
  | RP-User-Data  |   contains the TPDU:
  |   +-----------+
  |   | TP-MTI ...|   SMS-DELIVER / SMS-SUBMIT; TP-UDL length + TP-UD user data
  |   +-----------+
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | TP-MTI | transfer-protocol message type (DELIVER vs SUBMIT) |
  | TP-UDL | user-data length — a length octet driving the copy of TP-UD |
  | UDH | optional header with concatenation (part number / total parts) |
- **Beginner notes / gotchas:** SMS is *transport-agnostic* — the same message can arrive over CS
  signalling, over packet, or over IMS. **Finding F1 is a CDMA2000 (IS-637) SMS decoder**, not the 3GPP
  SMS stack above, but it is the *same bug class*: a bearer-data sub-parameter is a `{id,len,value}` TLV,
  and a record **count** was clamped for storage yet the raw over-the-air count byte was reused as the
  copy-loop bound (count desync).
- **Security relevance:** SMS is **remotely reachable by just sending a message** to the victim (tier
  **T2**), with no rogue-base-station needed. **F1** (`ValSmsProcessDeliverParaMsg`) is a ~7 KB `.bss`
  out-of-bounds write from an MT SMS-DELIVER — Huawei-only (the Samsung build compiles out the CDMA2000
  module). It is the highest-reach finding that needs no radio proximity.

---

## GMM — GPRS Mobility Management (2G/3G PS)

- **What it is / meaning:** **GMM = GPRS Mobility Management**, the *packet-switched* mobility sublayer
  (the PS-domain twin of MM). It manages the UE's presence and identity on the packet domain and talks to
  the **SGSN**. PD = `1000` (8).
- **Purpose:**
  - GPRS attach/detach; routing-area updating.
  - PS-domain authentication and P-TMSI (packet TMSI) reallocation.
  - Establish the MM context that SM (PDP contexts) rides on.
- **Specification:** **3GPP TS 24.008** (<https://www.3gpp.org/dynareport?code=24.008.htm>), §4 (GMM
  procedures), §9.4 (GMM messages).
- **Packet / PDU disposition:**
  ```
   7 6 5 4 3 2 1 0
  +-------+-------+
  | Skip  |  PD=8 |  octet 1
  +-------+-------+
  | Message Type  |  octet 2   (ATTACH REQUEST, ROUTING AREA UPDATE REQUEST, ...)
  +---------------+
  | info elements |  octet 3...
  ```
- **Key fields explained:** identical header shape to MM (skip indicator + PD + message type); message
  set is the PS analog (ATTACH, ROUTING AREA UPDATE, P-TMSI REALLOCATION, AUTHENTICATION AND CIPHERING).
- **Beginner notes / gotchas:** MM ↔ CS, GMM ↔ PS — same idea, two domains, two core nodes (MSC vs SGSN).
  GMM is the 2G/3G ancestor of **EMM** (4G) and **5GMM** (5G): the "mobility half" of the mobility/session
  split that the rest of this file is organised around.
- **Security relevance:** GPRS attach and RAU are **pre-auth** entry points (fake-base-station reachable).
  No headline finding in this file targets 2G/3G GMM directly.

---

## SM — Session Management (2G/3G PS)

- **What it is / meaning:** **SM = (GPRS) Session Management**, the sublayer that sets up **PDP contexts**
  — the 2G/3G equivalent of a data bearer / IP session — with the SGSN/GGSN. It runs above a GMM context.
  PD = `1010` (10).
- **Purpose:**
  - Activate / modify / deactivate PDP contexts (ACTIVATE PDP CONTEXT REQUEST, ...).
  - Negotiate QoS and **Protocol Configuration Options (PCO)** — DNS, P-CSCF, MTU, PAP/CHAP.
- **Specification:** **3GPP TS 24.008** (<https://www.3gpp.org/dynareport?code=24.008.htm>), §6 (SM
  procedures), §9.5 (SM messages), §10.5.6.3 (**PCO** IE — reused verbatim by 4G ESM).
- **Packet / PDU disposition:** SM carries a **Transaction Identifier** (like CC) so multiple PDP contexts
  coexist:
  ```
   7 6 5 4 3 2 1 0
  +-+-----+-------+
  |F| TI  | PD=10 |  octet 1
  +-+-----+-------+
  | Message Type  |  octet 2
  +---------------+
  | info elements |  octet 3...  (QoS, APN, PCO as TLV IEs)
  ```
- **Key fields explained:** transaction identifier (per PDP context) + message type + IEs. The PCO IE
  defined here (§10.5.6.3) is the *same* structure the 4G ESM layer parses — which is why the PCO findings
  cite both TS 24.008 and TS 24.301.
- **Beginner notes / gotchas:** SM ("session") vs GMM ("mobility") is the 2G/3G version of the ESM/EMM and
  5GSM/5GMM splits. The **PCO IE originates here** and is inherited unchanged by LTE — a good example of
  how a legacy IE format (and its parsing bugs) propagates across generations.
- **Security relevance:** No file-specific finding lives in 2G/3G SM itself, but its **PCO** IE is the
  direct ancestor of the LTE-ESM PCO handling that carries **F3** and **F12**.

---

## EMM — EPS Mobility Management (4G)

- **What it is / meaning:** **EMM = EPS Mobility Management** ("EPS" = Evolved Packet System = the 4G/LTE
  core). It is the 4G mobility sublayer, talking to the **MME**. It handles attach, tracking-area update,
  identity, authentication, and — crucially — **NAS security setup** (SECURITY MODE COMMAND). PD = `0111`
  (7). EMM is where the **Security Header Type** field first appears in the NAS header.
- **Purpose:**
  - EPS attach/detach and tracking-area updating.
  - EPS-AKA authentication and NAS SECURITY MODE (establishing integrity + ciphering).
  - Carry ESM messages during attach (ESM is piggybacked in EMM).
- **Specification:** **3GPP TS 24.301** (<https://www.3gpp.org/dynareport?code=24.301.htm>), §5 (EMM
  procedures), §8/§9 (message + header formats), §9.3.1 (security header type). Framing per TS 24.007.
- **Packet / PDU disposition:** plain form §(a); when protected, the §(b) envelope
  (SecHdrType | PD=7 · MAC[4] · SEQ · ciphered message).
  ```
   7 6 5 4 3 2 1 0
  +-------+-------+
  | SecHdr| PD=7  |  octet 1
  | Type  |       |
  +-------+-------+
  | Message Type  |  octet 2 (plain) — or MAC[4]+SEQ+ciphered (protected)
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | PD | `0111` = EMM |
  | Security Header Type | 0=plain, 1=integrity, 2=integrity+cipher, 3/4=new context (SMC) |
  | MAC (protected) | 4-octet integrity tag |
  | Sequence Number (protected) | 1-octet anti-replay counter |
- **Beginner notes / gotchas:** EMM is the "mobility" half of 4G; **ESM** is the "session" half — this
  mobility/session split (inherited into 5GMM/5GSM) is the single most important structural fact for a
  beginner. Both EMM and ESM share PD-numbered NAS framing but EMM=7, ESM=2.
- **Security relevance:** EMM is where integrity checking is *implemented*, and **finding F13** is a bug
  **inside the integrity check itself**: `CEmmSec::chkIntegrity` computes `(u16)(len − 5)` with no
  minimum-length guard, so a NAS PDU with `len < 5` **underflows to ~65531**, driving a ~64 KB
  out-of-bounds **read** during MAC computation — i.e. *before* integrity can pass. Because it fires
  inside the verify step, its reach depends on whether a selected EIA algorithm id is already set, which
  is why its tier straddles **T1→T4**. This is the concrete demonstration of the "parsed before or after
  integrity" question at the top of this file.

---

## ESM — EPS Session Management (4G)

- **What it is / meaning:** **ESM = EPS Session Management**, the 4G sublayer that sets up **EPS bearers**
  (the LTE data pipes) with the MME/SGW/PGW. It is the LTE successor to 2G/3G SM. PD = `0010` (2). ESM
  messages carry an **EPS bearer identity** and a **procedure transaction identity** in their header.
- **Purpose:**
  - Activate/modify/deactivate default and dedicated EPS bearer contexts.
  - Carry **PCO / extended PCO** (DNS, P-CSCF, MTU) between UE and network.
  - Bearer resource allocation/modification.
- **Specification:** **3GPP TS 24.301** (<https://www.3gpp.org/dynareport?code=24.301.htm>), §6 (ESM
  procedures), §9.9.4 (ESM IEs incl. **PCO** §9.9.4.11, which points back to TS 24.008 §10.5.6.3).
- **Packet / PDU disposition:**
  ```
   7 6 5 4 3 2 1 0
  +-------+-------+
  | EPS   | PD=2  |  octet 1   (EPS bearer identity in the high half-octet)
  | BearId|       |
  +-------+-------+
  | Proc. Trans.  |  octet 2   (procedure transaction identity)
  | Identity      |
  +---------------+
  | Message Type  |  octet 3
  +---------------+
  | info elements |  octet 4...  (PCO as a TLV IE)
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | PD | `0010` = ESM |
  | EPS bearer identity | which bearer this message concerns |
  | Procedure transaction id | matches request/response pairs |
  | PCO IE | container list of `{2-octet id, 1-octet len, value}` protocol options |
- **Beginner notes / gotchas:** The *Activate Default EPS Bearer Context Request* that carries PCO is
  **piggybacked inside the EMM Attach Accept**, so the UE parses ESM (and PCO) *as part of coming up on a
  cell* — early, before full NAS security is established for a false network. That timing is what makes
  the ESM PCO bug pre-auth reachable.
- **Security relevance:** two findings live here.
  - **F3** — `esm_event_decode_pco_ie`: each PCO container is appended at an 8-byte-stride index into an
    84-byte context list with **no capacity check**; a 255-byte PCO drives ~84 entries → ~2 KB overflow of
    the persistent ESM context. **T1 (pre-auth unicast)** via the piggybacked bearer request.
  - **F12** — `esm_cmn_copy_esm_pco_to_pco`: on the ESM→SM **re-serialization** (encode-back) path,
    `stride × count` is copied into a fixed 35-container buffer with the count unclamped → multi-KB heap
    overflow. Distinct from F3 (decode vs encode). Notably a *clamped* sibling (`esm_cmn_copy_pco`) exists,
    proving the developers knew the count was untrusted — the re-serialize variant just omits the guard.
    **T4 (post-auth).**

---

## 5GMM — 5GS Mobility Management (5G)

- **What it is / meaning:** **5GMM = 5GS Mobility Management**, the 5G-NR mobility sublayer, talking to the
  **AMF** (Access and Mobility management Function). It is the 5G successor to EMM. It uses an **Extended
  Protocol Discriminator** occupying a full octet (`0x7E`), and the Security Header Type moves to octet 2.
- **Purpose:**
  - 5GS registration (the 5G "attach"), deregistration, mobility/periodic registration updates.
  - 5G-AKA authentication and 5G NAS SECURITY MODE.
  - Deliver network configuration to the UE: 5G-GUTI, TAI list, allowed NSSAI, **LADN info**, **emergency
    number list**, **operator-defined access categories**, configuration updates.
- **Specification:** **3GPP TS 24.501** (<https://www.3gpp.org/dynareport?code=24.501.htm>), §5 (5GMM
  procedures), §8.2 (message contents, e.g. REGISTRATION ACCEPT §8.2.7), §9.1.1/§9.3 (header + security
  header type), §9.11.3 (5GMM IEs). Framing per TS 24.007.
- **Packet / PDU disposition:** plain form §(a) with EPD `0x7E`; protected form §(b) with MAC[4]+SEQ. See
  the [REGISTRATION ACCEPT skeleton](#worked-example-a-5gmm-registration-accept-skeleton) above.
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | Extended PD | `0x7E` = 5GMM (full octet) |
  | Security Header Type | octet 2 low half; 0=plain … 2=integrity+cipher |
  | Message Type | e.g. REGISTRATION ACCEPT `0x42`, CONFIGURATION UPDATE COMMAND `0x54` |
  | IEs | many TLV / **TLV-E** IEs (LADN 0x79, Emergency list 0x34, Op-access-cat 0x76) |
- **Beginner notes / gotchas:** 5GMM = mobility, **5GSM** = session — same split as EMM/ESM. The
  full-octet EPD and the introduction of `NSSAI`/`LADN`/network-slicing IEs are the main 5G novelties. The
  large network-config IEs are precisely the ones using **TLV-E** (2-octet length) — big attacker-controlled
  copies.
- **Security relevance:** the richest cluster of findings in this report. REGISTRATION ACCEPT is normally
  integrity-protected (header type 2), so these are nominally **T4 (post-auth)** — but each hinges on the
  same open "does the unpacker run before MAC verify?" question, which would upgrade them to T1.
  - **F4** — `vgmm_decode_ladn_info`: a DNN length octet (0..255) is `memcpy`'d into a **100-byte stack
    buffer** with no `≤100` clamp → 155-byte stack overflow reaching saved registers. LADN info IE `0x79`
    (**TLV-E**). **T4.**
  - **F5** — `vgmm_decode_emergency_number_list`: per-entry digit length unclamped against the 43-byte
    entry stride → ~180 B past a 689-byte control buffer. Emergency number list IE `0x34` (**TLV**). **T4
    (→T1 if pre-MAC).**
  - **F11** — `vgmm_set_op_def_access_category_definitions`: the raw 2-octet IE length is `memcpy`'d into a
    fixed ~4 KB global scratch buffer with no clamp → up to ~61 KB overflow of the 5GMM global context.
    Operator-defined access category definitions IE `0x76` (**TLV-E** — the 2-octet length is exactly why
    the overflow can be so large). **T4.**

---

## 5GSM — 5GS Session Management (5G)

- **What it is / meaning:** **5GSM = 5GS Session Management**, the 5G sublayer that establishes and manages
  **PDU sessions** (the 5G data connections) with the **SMF** (Session Management Function). It is the
  successor to ESM. Extended PD = `0x2E` (full octet). Its header carries a **PDU session identity** and a
  **procedure transaction identity**.
- **Purpose:**
  - Establish/modify/release PDU sessions (PDU SESSION ESTABLISHMENT REQUEST/ACCEPT, ...).
  - Negotiate QoS rules, session-AMBR, and **PCO / extended PCO** for the session.
  - 5GSM messages are transported *inside* 5GMM messages (the NAS transport container).
- **Specification:** **3GPP TS 24.501** (<https://www.3gpp.org/dynareport?code=24.501.htm>), §6 (5GSM
  procedures), §8.3 (5GSM message contents), §9.11.4 (5GSM IEs).
- **Packet / PDU disposition:**
  ```
   7 6 5 4 3 2 1 0
  +---------------+
  | Extended PD   |  octet 1 (0x2E)
  +---------------+
  | PDU Session   |  octet 2
  | Identity      |
  +---------------+
  | Procedure     |  octet 3
  | Trans. Id     |
  +---------------+
  | Message Type  |  octet 4
  +---------------+
  | info elements |  octet 5...
  ```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | Extended PD | `0x2E` = 5GSM |
  | PDU session identity | which PDU session this message concerns |
  | Procedure transaction id | matches request/response pairs |
  | Message Type | PDU SESSION ESTABLISHMENT REQUEST/ACCEPT/REJECT, ... |
- **Beginner notes / gotchas:** unlike EMM/ESM, 5GSM messages are **never sent directly on the air** — they
  are always wrapped in a 5GMM transport message, so their security posture is inherited from the enclosing
  5GMM envelope. The PCO/ePCO IEs mirror those of ESM.
- **Security relevance:** no file-specific finding lands in 5GSM itself in this build, but it is the
  session-management peer of the ESM PCO surface (F3/F12) and shares the same PCO container-count risk
  pattern; it is the natural place to look for the 5G analog of those bugs.

---

*Cross-references:* stack overview `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md`; pre-/post-auth tiers
`../../PREAUTH_POSTAUTH_EXPLAINER.md`; finding deep-dives `../../F1.md`, `../../F3.md`, `../../F4.md`,
`../../F5.md`, and the consolidated table `/workspace/CONSOLIDATED_FINDINGS.md` (F11/F12/F13).*
