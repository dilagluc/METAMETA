# 08 — Cellular Security (AKA, key hierarchy, NAS/AS protection, algorithms, MAC)

This chapter explains **how a phone and the network prove who they are and then protect their
signalling**. Everything here sits *beside* the protocol stack rather than at one layer: authentication
happens in **NAS** (core-network signalling), the resulting keys protect both **NAS** (end-to-end to the
core) and **AS** (the radio link, inside **PDCP**). If you have not read the layer map yet, start with
`../fundamentals/01_3GPP_LAYERS_EXPLAINER.md`; for the pre-auth/post-auth threat model this all feeds into, see
`../../PREAUTH_POSTAUTH_EXPLAINER.md`.

### What a "security context" is (and why pre-/post-auth hinges on it)

A **security context** is the bundle of state the UE and network share *after* they have authenticated:
a set of derived keys (integrity + ciphering), the chosen algorithms, and a **COUNT** (message counter,
for replay protection). Before that bundle exists, the UE **has no key to check a signature with**, so
it *must* process certain messages "in the clear":

- **Pre-auth** = no security context yet. Broadcast (SIB, paging) and the first NAS messages
  (Identity Request, Authentication Request, some Rejects) are accepted **with no integrity check**.
  Anyone with a radio can send them → cheap, mass, remote. This is why bugs in those parsers are the
  crown jewels of baseband research.
- **Post-auth** = a security context is up. Every accepted message must carry a valid 32-bit MAC
  (integrity signature). To trigger a bug here you must **be the real network or a MITM holding the
  keys**.

So the single question that classifies a signalling bug is: *does the vulnerable decoder run before or
after the security context verifies the message?* That is the theme of this whole report.

### Contents
1. [AKA — Authentication and Key Agreement](#1-aka--authentication-and-key-agreement)
2. [The key hierarchy](#2-the-key-hierarchy)
3. [NAS security (integrity + ciphering of signalling)](#3-nas-security-integrity--ciphering-of-signalling)
4. [AS security (PDCP-level, the radio link)](#4-as-security-pdcp-level-the-radio-link)
5. [Integrity algorithms (EIA/NIA) and ciphering algorithms (EEA/NEA)](#5-integrity-algorithms-eiania-and-ciphering-algorithms-eeanea)
6. [The integrity tag / MAC (32-bit)](#6-the-integrity-tag--mac-32-bit)

> **Anchor specs for the whole chapter:** LTE security **TS 33.401**
> (`https://www.3gpp.org/dynareport?code=33.401.htm`); 5G security **TS 33.501**
> (`https://www.3gpp.org/dynareport?code=33.501.htm`); 3G AKA framework **TS 33.102**
> (`https://www.3gpp.org/dynareport?code=33.102.htm`); algorithm specifications
> **TS 35.201+** (`https://www.3gpp.org/dynareport?code=35.201.htm`); **Milenage** authentication
> functions **TS 35.205 / 35.206** (`https://www.3gpp.org/dynareport?code=35.206.htm`); NAS security
> procedures within **TS 24.301** (LTE, `https://www.3gpp.org/dynareport?code=24.301.htm`) and
> **TS 24.501** (5G, `https://www.3gpp.org/dynareport?code=24.501.htm`).

---

## 1. AKA — Authentication and Key Agreement

- **What it is / meaning:** **AKA** (**A**uthentication and **K**ey **A**greement) is the challenge-
  response handshake in which the UE and the network **mutually** prove they both possess the secret
  subscriber key **K**. K lives *only* in two places: the **USIM** (the SIM card's application) and the
  operator's **AuC/ARPF** (home-network authentication centre). It is never transmitted. AKA runs as NAS
  signalling (EMM in LTE, 5GMM in 5G) right after the UE announces itself. It produces the fresh session
  keys everything else is built from. Used by all modern RATs (UMTS/LTE/5G); GSM's older single-sided
  auth is the weak ancestor.
- **Purpose:**
  - Prove the SIM holds K (network authenticates the UE via **RES**).
  - Prove the network is genuine (UE authenticates the network via **AUTN** — this is what a plain
    fake base station *cannot* fake, because it has no K).
  - Derive fresh **CK/IK** (cipher key / integrity key) for this session.
  - Provide replay protection via a sequence number **SQN**.
- **Specification:** framework **TS 33.102** (3G); LTE binding **TS 33.401**; 5G variants **TS 33.501**;
  the crypto functions f1–f5 are **Milenage** in **TS 35.205/35.206** (an alternative, TUAK, is
  TS 35.231). NAS message carriers: **TS 24.301 / 24.501**. See also ShareTechnote
  `https://www.sharetechnote.com/` ("Authentication").

**Disposition — the AKA exchange (LTE EPS-AKA shown):**

```
        NETWORK (MME / AuC)                                   UE (ME + USIM)
             |                                                     |
             |   Authentication Request  (NAS, EMM)                |
             |   +------------------+   +------------------+       |
             |-->|  RAND  (16 bytes) |   |  AUTN (16 bytes)  |----->|  USIM runs Milenage f1..f5 with K,RAND:
             |   +------------------+   +------------------+       |   - checks AUTN's MAC  (network is genuine?)
             |                                                     |   - checks SQN freshness (not a replay?)
             |                                                     |   - computes RES, CK, IK, AK
             |   Authentication Response (NAS, EMM)                |
             |   +--------------------------+                      |
             |<--|  RES (4..16 bytes)        |<---------------------|
             |   +--------------------------+                      |
             |   compare RES == XRES ?  --> yes: proceed to SMC    |
             |                          --> no : Auth Reject        |
```

**AUTN internal layout (16 bytes, per TS 33.102 §6.3):**

```
 byte:  0                 5 6       7 8                15
       +-------------------+---------+-------------------+
       |  SQN xor AK (6B)  | AMF(2B) |    MAC-A  (8B)    |
       +-------------------+---------+-------------------+
        SQN = sequence no.   AMF =     network's own 8-byte
        masked by AK (f5)    auth-    integrity tag over the
                             mgmt fld  challenge (verified by f1)
```

**Key fields explained:**

| Field | Size | Meaning |
|---|---|---|
| **RAND** | 16 B | Random challenge the network picks each time. |
| **AUTN** | 16 B | Authentication token the UE checks to trust the network (contains SQN⊕AK, AMF, MAC-A). |
| **RES / XRES** | 4–16 B | UE's computed response (**RES**) vs network's expected (**XRES**). Equal ⇒ SIM has K. |
| **CK / IK** | 16 B each | Cipher key / integrity key produced by f3 / f4 — the root of the session key ladder. |
| **AK** | 6 B | Anonymity key (f5) that masks SQN so it isn't sent in clear. |
| **SQN** | 6 B | Sequence number for replay protection; if stale, UE sends **Sync Failure**. |

- **5G variants:** two methods, negotiated by the home network.
  - **5G-AKA** — the same challenge/response, but the UE returns **RES\*** (RES run through a KDF binding
    the serving-network name), and the home network compares **XRES\***. Keys go into the 5G ladder.
  - **EAP-AKA'** — AKA wrapped in the EAP framework (RFC-style EAP messages inside NAS), used especially
    for non-3GPP/Wi-Fi access; the "'" (prime) marks the key-derivation binding to the access-network
    name. Defined in TS 33.501; algorithm still Milenage/TUAK.
- **Beginner notes / gotchas:**
  - "MAC" *inside* AUTN (MAC-A / XMAC) is the network's integrity tag over the challenge — yet another
    use of the word "MAC". It is a crypto MAC, not the MAC layer (see §6).
  - The USIM does the secret math; the modem ("ME") shuttles messages and holds the derived keys. K
    never leaves the card.
- **Security relevance:** AKA is the **auth** in pre-/post-auth. Because a rogue base station lacks K, it
  *cannot complete* AKA — so it either skips straight to exploiting pre-auth messages, or downgrades. Any
  message parsed *before* the Authentication Response is verified is pre-auth reachable.

---

## 2. The key hierarchy

- **What it is / meaning:** a **tree of derived keys**. AKA yields CK/IK; from those, a chain of **KDFs**
  (key-derivation functions, HMAC-SHA-256 based, TS 33.401 Annex A / 33.501 Annex A) produces separate
  keys for each purpose and each layer. The point: a compromise of one leaf key does not expose the
  others, and each hop (core → access) gets its own key.
- **Purpose:** isolate NAS keys from AS keys; give the radio side (eNB/gNB) a key that never reveals the
  master; allow re-keying on handover without a new AKA.
- **Specification:** LTE ladder **TS 33.401** §6.2 + Annex A; 5G ladder **TS 33.501** §6.2 + Annex A.

**Disposition — LTE (EPS) key tree:**

```
        K            (permanent subscriber key — USIM & AuC only, 128b)
        │  AKA (Milenage f3/f4)
        ▼
     CK , IK         (cipher key / integrity key, 128b each)
        │  KDF( + serving-network id, SQN xor AK )
        ▼
     K_ASME          ("Access Security Mgmt Entity" key — held by MME, 256b)
        ├───────────────► K_NASenc   (NAS ciphering)     ─┐  used by EMM/ESM
        ├───────────────► K_NASint   (NAS integrity)     ─┘  (this chapter §3)
        └───────────────► K_eNB      (given to the base station)
                              ├──► K_RRCenc  (RRC ciphering)   ─┐ AS, in PDCP
                              ├──► K_RRCint  (RRC integrity)   ─┤ (§4)
                              └──► K_UPenc   (user-plane ciph) ─┘
```

**Disposition — 5G (5GS) key tree (TS 33.501):**

```
        K
        │  AKA
        ▼
     CK , IK
        │
        ▼
     K_AUSF   (in home network's AUSF)
        │
        ▼
     K_SEAF   (anchor key in the serving network's SEAF)
        │
        ▼
     K_AMF    (held by the AMF — the 5G mobility function)
        ├──► K_NASenc , K_NASint            (5GMM/5GSM NAS protection)
        └──► K_gNB
                ├──► K_RRCenc , K_RRCint     (AS, in PDCP)
                └──► K_UPenc , K_UPint       (5G can integrity-protect user plane too)
```

**Key fields explained:**

| Key | Where it lives | Protects |
|---|---|---|
| **K** | USIM + AuC/ARPF | root of everything; never sent |
| **CK / IK** | USIM output → ME | input to KASME / KAUSF derivation |
| **K_ASME** (4G) / **K_SEAF→K_AMF** (5G) | MME / AMF | the "master" for this registration |
| **K_NASint / K_NASenc** | UE + MME/AMF | NAS integrity / ciphering (§3) |
| **K_eNB / K_gNB** | UE + base station | seeds the AS keys |
| **K_RRCint/enc, K_UPenc/(K_UPint)** | UE + base station | AS integrity/ciphering (§4) |

- **Beginner notes:** the derived keys are 256-bit in the KDF but the *algorithms today are 128-bit*, so
  keys are truncated to 128 bits before use (that is why algorithms are named "**128**-EIA2" etc.). The
  base station only ever gets **K_eNB/K_gNB** — never KASME/KAMF — so a compromised radio node cannot
  read NAS or derive the master.
- **Security relevance:** the split is exactly what makes "post-auth" hard for an attacker: to forge an
  AS or NAS message you need the specific leaf key, which is only obtainable by completing AKA (needing
  K). On this firmware the NAS branch is derived by `CEmmSecCtxtSmc::calAndSetKnasKey()` /
  `calAndSet5gKnasKey()` and `calNativeKasme()`/`calMappedKasme()` (see `../catalog/catalog_cross.md`).

---

## 3. NAS security (integrity + ciphering of signalling)

- **What it is / meaning:** protection of **NAS** messages — the L3 signalling that runs end-to-end
  between the UE and the **core** (EMM/ESM in LTE, 5GMM/5GSM in 5G), *through* the base station. It is
  turned on by the **Security Mode Command (SMC)** procedure after AKA. From then on every NAS message is
  wrapped in a **security-protected NAS message** header carrying a 32-bit MAC and a sequence number; most
  are also ciphered. For the NAS message formats themselves, cross-reference the **NAS chapter** in this
  directory and **TS 24.301 §9 / 24.501 §9**.
- **Purpose:**
  - **Integrity:** attach a MAC so the UE/network can detect any tampering or forgery (mandatory once on).
  - **Ciphering:** encrypt the NAS body for confidentiality (IMSI/SUCI, location, SMS-over-NAS…).
  - **Replay protection:** the NAS **COUNT** (sequence number + overflow counter) feeds the MAC.
  - **Algorithm negotiation:** SMC tells the UE which EIA/EEA (NIA/NEA) to use.
- **Specification:** **TS 24.301** (LTE) / **TS 24.501** (5G) for the header + procedures; **TS 33.401 /
  33.501** for the crypto binding.

**Disposition — the security-protected NAS message header (TS 24.301 §9.1):**

```
 0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-------+-------+-------------------------------+---------------+
| SHT   |  PD   |   Message Authentication Code  (MAC, 4 bytes) |
+-------+-------+-------------------------------+---------------+
|  ...MAC (cont.)  | Seq.No (1B)  |   NAS message (ciphered) ...  |
+------------------+--------------+------------------------------+
  SHT = Security Header Type (4 bits)   PD = Protocol Discriminator (4 bits)
```

Field order on the wire: **[ PD | SHT ]** (1 octet) · **MAC** (4 octets) · **Sequence Number**
(1 octet) · **NAS message** (the inner plaintext, ciphered when SHT selects it).

**Security Header Type (SHT) values — the "is this protected?" selector (TS 24.301 Table 9.3.1):**

| SHT | Meaning | Context |
|---|---|---|
| `0000` (0) | **Plain NAS**, not security protected | pre-security messages (Attach/Identity/Auth Req, some Rejects) |
| `0001` (1) | Integrity protected | after SMC |
| `0010` (2) | Integrity protected **and ciphered** | normal post-security messages |
| `0011` (3) | Integrity protected, **new** security context (used for SMC itself) | SMC / Attach start |
| `0100` (4) | Integrity protected + ciphered, new security context | SMC complete path |
| `1100` (0xC) | Service Request (LTE special short header) | idle→connected |

- **Beginner notes / gotchas:**
  - A **plain NAS message (SHT=0)** has *no* MAC/seq-no fields at all — the whole header above collapses
    to just the normal PD+message-type. That is the pre-auth surface.
  - The 5G format (TS 24.501) is the same shape; the plaintext-allowed whitelist for SHT=0 is what
    findings **F4/F5** hinge on (Registration/Config-Update are **not** on it → must be verified first).
- **Security relevance:** this is the exact boundary between pre- and post-auth. On this modem, the
  top-level dispatch is `CEmmSec::chkNasMsgSecurity()`, which decides whether a received NAS message needs
  integrity (`chkIntegrity`) and/or decipher (`deciphMsg`) based on its SHT — cross-ref
  `../catalog/catalog_cross.md`.

---

## 4. AS security (PDCP-level, the radio link)

- **What it is / meaning:** **AS** = **A**ccess **S**tratum — the signalling and data on the *radio link*
  between the UE and the base station (eNB/gNB). Its security is applied inside **PDCP** (Packet Data
  Convergence Protocol, an L2 sublayer). Two things get protected: **RRC** (radio-resource control
  signalling) and the **user plane** (your IP traffic). AS security is set up by the RRC
  **SecurityModeCommand** *after* NAS security, using keys derived from K_eNB/K_gNB.
- **Purpose:**
  - **RRC integrity + ciphering:** protect radio-control messages (measurement config, handover, bearer
    setup).
  - **User-plane ciphering:** encrypt user data over the air (K_UPenc); **5G optionally adds UP
    integrity** (K_UPint).
  - Re-key on handover so each cell has its own K_eNB/K_gNB.
- **Specification:** **TS 33.401** §7 (LTE AS); **TS 33.501** §6.4–6.7 (5G AS); PDCP carriers
  **TS 36.323** (LTE) / **TS 38.323** (NR).

**Disposition — where AS security sits (downlink receive):**

```
   radio ─► PHY ─► MAC ─► RLC ─► [ PDCP:  decipher (EEA/NEA)  +  RRC integrity check (EIA/NIA) ] ─► RRC / IP
                                          ▲ uses K_RRCenc/K_UPenc      ▲ uses K_RRCint
   (MAC-layer parsing runs BEFORE PDCP ciphering ⇒ MAC/RLC are a pre-auth parser surface — see §01)
```

**Key fields explained:**

| Item | LTE key | 5G key | Notes |
|---|---|---|---|
| RRC ciphering | K_RRCenc | K_RRCenc | encrypts RRC signalling body |
| RRC integrity | K_RRCint | K_RRCint | 32-bit MAC-I in PDCP control/data PDU |
| User-plane ciphering | K_UPenc | K_UPenc | encrypts DRB data |
| User-plane integrity | — | K_UPint | **5G-only**, optional per-DRB |

- **Beginner notes / gotchas:**
  - AS integrity protects **RRC signalling** always (once on); LTE does **not** integrity-protect user
    data — only 5G can. So "the data is encrypted" ≠ "the data is authenticated" on LTE.
  - The **MAC/RLC layers run before PDCP deciphering**, so those parsers see attacker bytes pre-security
    (a rich pre-auth surface — see `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md`). PDCP is where the crypto boundary
    actually is.
- **Security relevance:** RRC AS setup is itself reachable pre-auth (the SecurityModeCommand and the
  RRC setup that precedes it). Broadcast SIB and paging (finding **F6** area) are AS-layer but *never*
  protected — no AS key exists for them by design.

---

## 5. Integrity algorithms (EIA/NIA) and ciphering algorithms (EEA/NEA)

- **What it is / meaning:** the interchangeable cipher suites plugged into the MAC computation and the
  encryption. LTE names them **EIA*x*** (EPS Integrity Algorithm) and **EEA*x*** (EPS Encryption
  Algorithm); 5G renames the identical algorithms **NIA*x*** / **NEA*x***. The network *selects* one of
  each in the Security Mode Command; the UE advertises which it supports in its capabilities.
- **Purpose:** provide the pluggable primitive that (a) produces the 32-bit integrity MAC and (b) the
  keystream for ciphering. Multiple algorithms exist for crypto-agility and export/regional reasons.
- **Specification:** algorithm set **TS 33.401** Annex B / **33.501** Annex D; the primitives:
  **TS 35.201–35.202** (SNOW 3G / f8-f9), **TS 35.215–35.216** (128-EEA1/EIA1 = SNOW 3G),
  the AES-based set (128-EEA2/EIA2), **TS 35.221–35.222** (128-EEA3/EIA3 = ZUC). Milenage (auth, §1)
  is **TS 35.205/206**.

**The algorithm identifiers (same value = same primitive in LTE and 5G):**

| ID (4-bit) | Integrity | Ciphering | Primitive | Notes |
|---|---|---|---|---|
| `000` | **EIA0 / NIA0** | **EEA0 / NEA0** | **NULL** | no protection — pre-security **and** unauthenticated **emergency** calls only |
| `001` | EIA1 / NIA1 | EEA1 / NEA1 | **SNOW 3G** | stream cipher (128-bit) |
| `010` | EIA2 / NIA2 | EEA2 / NEA2 | **AES** | EEA2 = AES-CTR; EIA2 = AES-CMAC |
| `011` | EIA3 / NIA3 | EEA3 / NEA3 | **ZUC** | stream cipher; common in CN deployments |

- **Beginner notes / gotchas:**
  - **EIA0/EEA0 = the null algorithm.** EEA0 "encrypts" by doing nothing; EIA0 produces an all-zero MAC.
    They are legitimate only pre-security and for **unauthenticated emergency calls**. A network that
    forces EIA0 onto a normal call is a classic **downgrade attack** — the UE is supposed to refuse it
    outside the emergency case.
  - "128-" prefix (128-EIA2 etc.) just states the 128-bit key length; the algorithm number is the part
    that matters.
  - Searching firmware for the bare strings `eia`/`eea` is misleading — on this modem those mostly match
    unrelated AT-command handlers (`atp_d2at_eia*`), **not** the integrity algorithm (see
    `../catalog/catalog_cross.md`).
- **Security relevance:** the algorithm-selection code (`CEmmSec::mapIntegrityAlgToEnum()`,
  `chkSelectedAlg()`, `setIntegrityAlg/setCipheringAlg`) and the EIA0 handling
  (`ifEIA0Used`/`applyEia0SuccessCommonHandler`) are security-critical: mishandling "null selected" or a
  bad algorithm index turns protection off.

---

## 6. The integrity tag / MAC (32-bit)

- **What it is / meaning:** the **MAC** (**M**essage **A**uthentication **C**ode) — also written **MAC-I**
  / **NAS-MAC** / **XMAC** — is a **32-bit (4-byte)** cryptographic checksum computed with the integrity
  algorithm (EIA/NIA) over a signalling message plus its counter. The receiver recomputes it and compares.
  **This is a completely different "MAC" from the Medium Access Control layer** (see the two-MACs note
  below). It is the concrete artefact that makes a message "integrity-protected".
- **Purpose:** detect any modification (integrity) and prove the sender holds the integrity key
  (authenticity); the COUNT input also gives replay protection.
- **Specification:** input construction **TS 33.401** §B.2 / **33.501** §D.3; placement in NAS
  **TS 24.301/24.501 §9**; placement in AS **TS 36.323/38.323** (PDCP).

**Disposition — how the 32-bit MAC is computed (EIA function inputs):**

```
        KEY (K_NASint / K_RRCint, 128b)
                     │
   COUNT ──►┌────────────────────┐
   BEARER ─►│  EIA / NIA  (SNOW3G │──► MAC  (32 bits / 4 bytes)
 DIRECTION ►│   / AES-CMAC / ZUC) │        └─ carried in the NAS header (§3)
  MESSAGE ─►└────────────────────┘           or PDCP PDU (§4)

  COUNT     = NAS/PDCP COUNT (overflow || sequence number) — replay protection
  BEARER    = a small bearer/identity value (fixed for NAS)
  DIRECTION = 0 uplink / 1 downlink  (stops a DL message being replayed as UL)
  MESSAGE   = the signalling bytes being protected
```

**Verify path (receive side):**

```
 received message  =  [ header | RECEIVED_MAC (4B) | body ]
                                    │
 recompute EIA over (KEY,COUNT,BEARER,DIR,body) ─► COMPUTED_MAC (4B)
                                    │
        compare COMPUTED_MAC == RECEIVED_MAC  ?  ── yes ─► accept
                                                └─ no  ─► DROP (integrity failure)
```

- **Beginner notes / gotchas — clearing the "two MACs" confusion:**

  | Term | What it is | Layer | In this report |
  |---|---|---|---|
  | **MAC (crypto)** | 32-bit integrity signature from EIA/NIA | security (NAS/PDCP) | *this section* |
  | **MAC (layer)** | Medium Access Control — scheduling, HARQ, MAC PDUs/CEs | L2 radio | see `../01_...` |

  They share only the letters. If someone says "the MAC failed," ask *which* — a crypto-MAC mismatch drops
  a message for integrity; a MAC-layer bug is an L2 parser issue. The report's glossary flags this too.

- **Where the check happens in the modem — and the subtle bug class:**
  On this firmware the NAS integrity compare is **`CEmmSec::chkIntegrity()` @ 0x904dfbdc — this project's
  finding F13**. It selects the algorithm from the SMC/AKA context, **copies the received NAS body
  (pointer `a3+5`, length `a2-5`) into a scratch buffer**, computes the MAC via `l2_cp_int_nas`, then does
  `compareCharArray(computed, a3+1, 4)` against the received 4-byte MAC — returning 0 (ok) / 1 (fail).

  Two things beginners must internalise here:
  1. **The compare is 4 bytes** — exactly the 32-bit MAC. That is the entire integrity guarantee for a NAS
     message.
  2. **Some processing happens *before* the compare passes.** The body is copied (and length-arithmetic
     like `a2 - 5` is done) *before* the verdict is known. If a crafted short/absent-MAC message drives
     that length negative or the copy runs on unverified bytes, you get a **check-before-verify** slip:
     memory is touched *before* integrity is confirmed. F13 is exactly the **integrity-check underflow**
     in that region — a length underflow reachable on the receive path *ahead of* a successful MAC
     compare. That is what turns a nominally "post-auth" integrity gate into a **pre-auth reachable**
     surface (attacker-controlled bytes reach the copy before any key check can reject them).

- **Security relevance:** this section is *why* the pre-/post-auth model exists. A message with no MAC
  (pre-security, SHT=0, EIA0) needs **no keys** to reach the parser — SIB, paging, and pre-security NAS
  are open to any radio (tiers T0/T1 in `../../PREAUTH_POSTAUTH_EXPLAINER.md`). A message *with* a valid
  MAC needs the network's integrity key — post-auth (T4). **F13 matters because it is a flaw in the gate
  itself:** if the integrity check can be made to corrupt memory *before* it verifies, the usual "you must
  hold the key" barrier is bypassed. Cross-ref the finding notes in `../catalog/catalog_cross.md` and the tier
  model in `../../PREAUTH_POSTAUTH_EXPLAINER.md`.
