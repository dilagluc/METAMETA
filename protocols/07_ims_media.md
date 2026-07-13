# IMS / VoLTE / VoWiFi — signalling and media-plane protocols

These are the protocols that carry **voice, video, and real-time text over LTE/5G/Wi-Fi** as packets,
replacing the old circuit-switched voice path. IMS is the framework; **SIP + SDP** set up calls
(control plane), and **RTP + RTCP** carry the actual audio/video/text bits (media plane) using
**codecs** such as EVS and AMR. In this baseband the split matters: **SIP/SDP signalling is largely an
application-processor (AP) job while the RTP media path — depacketisation, jitter buffer, codec
framing — runs on the modem**, which is where this project's two media-plane findings live. See
`../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` for how these sit above the radio stack (they ride on IP over the
default/dedicated EPS bearers, i.e. on top of PDCP/RLC/MAC/PHY, or over IPsec on Wi-Fi for VoWiFi).

**Contents**
1. [IMS](#ims--ip-multimedia-subsystem) — the framework (and where each piece runs)
2. [SIP](#sip--session-initiation-protocol) — call signalling
3. [SDP](#sdp--session-description-protocol) — media negotiation
4. [RTP](#rtp--real-time-transport-protocol) — the media carrier
5. [RTCP](#rtcp--rtp-control-protocol) — stats/control
6. [RTP redundancy / RTT](#rtp-redundancy--rtt--rfc-2198--rfc-4103) — RFC 2198 + RFC 4103 (finding **F2**)
7. [EVS & AMR](#evs--amr--voice-codec-rtp-payloads) — voice-codec RTP payloads / ToC framing (finding **F7**)

---

## IMS — IP Multimedia Subsystem
- **What it is / meaning:** **IMS** (IP Multimedia Subsystem) is the operator's SIP-based framework for
  delivering real-time multimedia (voice = **VoLTE** "Voice over LTE", video = ViLTE, voice-over-Wi-Fi =
  **VoWiFi**, and RTT) as IP packets rather than over a circuit-switched channel. It sits **above** the
  IP/bearer stack: the UE registers to the IMS core (P-CSCF/S-CSCF/I-CSCF, HSS) using SIP, then places
  media over RTP. RAT: LTE, 5G NR (VoNR), and any IP access including Wi-Fi (VoWiFi over IPsec/IKEv2 to
  an ePDG). It is an **application-layer** overlay — the radio stack just provides IP connectivity.
- **Purpose:**
  - Register the UE and authenticate it to the IMS core (SIP REGISTER + IMS-AKA).
  - Set up / modify / tear down media sessions (calls) via SIP + SDP.
  - Carry the negotiated media as RTP/RTCP, and provide supplementary services (SMS-over-IMS, RTT, etc.).
- **Specification:** 3GPP **TS 26.114** — IMS Multimedia Telephony; Media handling and interaction
  (the master spec for VoLTE codecs, RTP payloads, jitter, RTT): <https://www.3gpp.org/dynareport?code=26.114.htm>.
  SIP profile / call control: **TS 24.229** (IMS using SIP and SDP): <https://www.3gpp.org/dynareport?code=24.229.htm>.
- **Where it runs (important for this report):** the **SIP/SDP signalling is text parsing and IMS-state
  machinery that typically lives on the AP** (Android's IMS stack / telephony service), while the modem
  is handed the **negotiated media parameters** and then does the **RTP receive/transmit, jitter buffer,
  and codec (de)packetisation** itself. So the attack surface *on the baseband* is dominated by the RTP
  media plane, not the SIP text — which is exactly where F2 and F7 sit.
- **Beginner notes / gotchas:** "VoLTE" is a marketing/deployment name; on the wire it is IMS + SIP + SDP
  + RTP. VoWiFi is the same IMS session but the IP travels through an IPsec tunnel over untrusted Wi-Fi to
  the ePDG — the media parsing on the modem is identical. Registration/auth (IMS-AKA) is a *control-plane*
  gate; it does **not** protect the *content* of RTP media packets once a call is up.
- **Security relevance:** IMS media is reachable only **in-call** (tier **T3**). The media plane is
  usually **unauthenticated and unencrypted at the RTP layer** (SRTP is frequently not negotiated on the
  access leg), so any call peer or on-path injector controls the bytes the modem's depacketisers parse.
  Both project findings **F2** (RTT redundancy) and **F7** (EVS ToC) are IMS media-plane bugs.

---

## SIP — Session Initiation Protocol
- **What it is / meaning:** **SIP** (Session Initiation Protocol) is a **text-based** request/response
  signalling protocol (modelled on HTTP) that creates, modifies, and terminates media sessions. It is the
  control plane of IMS: `REGISTER` logs the UE in, `INVITE`/`ACK`/`BYE` set up and tear down calls,
  `MESSAGE` carries SMS-over-IMS, etc. It runs over UDP/TCP/TLS (SCTP possible), usually to the P-CSCF.
- **Purpose:**
  - Locate and reach the far party (registration + routing via CSCFs).
  - Negotiate the session: an SIP `INVITE` carries an **SDP** body offering media/codecs; the answer
    carries the SDP answer (offer/answer model, RFC 3264).
  - Manage the dialog lifecycle (ringing, connected, re-INVITE for hold/codec change, BYE).
- **Specification:** IETF **RFC 3261** (SIP): <https://datatracker.ietf.org/doc/html/rfc3261>. 3GPP profile
  in **TS 24.229**. Offer/answer with SDP: RFC 3264.
- **Packet / PDU disposition (how it looks on the wire):** SIP is **plain text**, line-oriented (CRLF),
  not a bit-packed binary header. A request is a start line, then headers, a blank line, then the body:
```
INVITE sip:bob@example.com SIP/2.0            <- request line: METHOD Request-URI SIP-Version
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bK  <- header (name: value)
From: <sip:alice@example.com>;tag=1928
To: <sip:bob@example.com>
Call-ID: a84b4c76e66710
CSeq: 1 INVITE
Content-Type: application/sdp
Content-Length: 142
                                               <- empty line = end of headers
v=0 ...                                        <- message body (an SDP block, see below)
```
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | Request line | `METHOD Request-URI SIP/2.0` (e.g. `INVITE sip:…`); responses use `SIP/2.0 200 OK` |
  | `Via` | path the response must retrace; `branch` is the transaction ID |
  | `From` / `To` / `Call-ID` / `CSeq` | dialog identity + sequence number |
  | `Content-Type` / `Content-Length` | describe the body (usually `application/sdp`) |
- **Beginner notes / gotchas:** SIP looks like HTTP but is its own protocol; responses reuse HTTP-style
  status codes (100 Trying, 180 Ringing, 200 OK, 4xx/5xx errors). The **body is where SDP lives** — SIP
  transports it, SDP describes the media.
- **Security relevance:** SIP parsing (headers, length fields) is a classic text-parser surface, but in
  this baseband **the modem largely shuttles SIP while the AP parses it**, so the SIP text bugs (if any)
  are AP-side, not the modem findings here. Reachability is pre-call signalling; auth is via IMS-AKA.

---

## SDP — Session Description Protocol
- **What it is / meaning:** **SDP** (Session Description Protocol) is a small **text** format that
  *describes* a media session — which media (audio/video/text), which transport (RTP/UDP), which codecs
  (payload types) and their parameters. It is **not** a transport; it is carried **inside** SIP bodies
  (the `INVITE`/answer). This is where the codecs, RTP payload types, and RTT/redundancy for a call are
  agreed.
- **Purpose:**
  - Offer/answer the set of media streams and their codecs (offer/answer per RFC 3264).
  - Bind each **RTP payload type (PT)** number to a codec via `a=rtpmap` (e.g. PT 96 = `EVS`, PT 98 =
    `red`, PT 99 = `t140`).
  - Convey codec parameters (`a=fmtp`) — e.g. EVS bandwidth/bit-rate, AMR mode-set, RTT redundancy config.
- **Specification:** IETF **RFC 4566** (SDP): <https://datatracker.ietf.org/doc/html/rfc4566>. Offer/answer
  usage: RFC 3264. 3GPP usage/codec fmtp: TS 26.114.
- **Packet / PDU disposition (how it looks on the wire):** line-oriented `type=value`, one per line:
```
v=0                                   <- protocol version
o=- 20518 0 IN IP4 10.0.0.1           <- origin (session id / addr)
s=-                                   <- session name
c=IN IP4 10.0.0.1                     <- connection: media destination IP
t=0 0                                 <- timing
m=audio 49170 RTP/AVP 96 97           <- MEDIA line: type port transport PT-list
a=rtpmap:96 EVS/16000/1               <- attribute: PT 96 -> EVS codec
a=fmtp:96 br=5.9-24.4; bw=nb-swb      <- attribute: codec params
m=text 49172 RTP/AVP 98 99            <- a second media line: real-time text
a=rtpmap:98 red/1000                  <- redundancy (RFC 2198)
a=rtpmap:99 t140/1000                 <- T.140 real-time text (RFC 4103)
```
- **Key fields explained:**

  | Line | Meaning |
  |---|---|
  | `m=` | media type, port, transport, and the list of RTP payload-type numbers offered |
  | `c=` | connection address the media (RTP) is sent to |
  | `a=rtpmap:` | maps a PT number → codec name/clock rate |
  | `a=fmtp:` | format-specific parameters for that PT (bit-rate, mode-set, redundancy) |
- **Beginner notes / gotchas:** the PT numbers in `m=`/`rtpmap` are what later appear in each RTP packet's
  **PT field** — that's how the receiver knows which codec/depacketiser to run. Dynamic PTs (96–127) are
  negotiated per call, so PT→codec is only meaningful within the SDP context.
- **Security relevance:** SDP negotiation decides *whether the vulnerable paths are live*: an `m=text`
  line with `red`+`t140` arms F2; an `m=audio` line with `EVS` arms F7. Like SIP, SDP text is parsed
  AP-side; the modem consumes the *resulting* codec/PT config. It gates reachability rather than being the
  bug locus itself.

---

## RTP — Real-time Transport Protocol
- **What it is / meaning:** **RTP** (Real-time Transport Protocol) is the protocol that actually **carries
  the media** — encoded audio/video/text frames — over UDP. Each RTP packet has a small fixed binary
  header followed by the codec payload. It provides sequencing and timing so the receiver can reorder,
  detect loss, and play out at the right rate; it does **not** itself guarantee delivery or (by default)
  security. This is the **media plane** and it runs **on the modem** in this baseband.
- **Purpose:**
  - Carry codec frames with a **sequence number** (reordering / loss detection) and **timestamp** (playout).
  - Identify the stream/source via **SSRC**, and select the codec via the **payload type (PT)**.
  - Feed the modem's jitter buffer and codec depacketisers.
- **Specification:** IETF **RFC 3550** (RTP/RTCP): <https://datatracker.ietf.org/doc/html/rfc3550>. 3GPP
  media handling / payload usage: TS 26.114.
- **Packet / PDU disposition (RFC 3550 §5.1):**
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            contributing source (CSRC) identifiers  [0..CC]    |
|                             ....                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| optional extension header (present iff X=1)                   |
+---------------------------------------------------------------+
| payload (codec frames: EVS/AMR/T.140-red …)                   |
```
- **Key fields explained:**

  | Field | Width | Meaning |
  |---|---|---|
  | **V** | 2 | version, always 2 |
  | **P** | 1 | padding present |
  | **X** | 1 | extension header present |
  | **CC** | 4 | number of CSRC identifiers that follow (0–15) |
  | **M** | 1 | marker (e.g. frame boundary / talk-spurt start) |
  | **PT** | 7 | **payload type — selects the codec/depacketiser** (from SDP `rtpmap`) |
  | **sequence number** | 16 | increments per packet; used for reordering + loss detection |
  | **timestamp** | 32 | media sampling instant; drives jitter buffer / playout |
  | **SSRC** | 32 | synchronisation source (stream identity) |
  | **CSRC[CC]** | 32 each | contributing sources (present only for mixed streams) |
- **Beginner notes / gotchas:** the fixed header is **12 bytes**; total header grows by `4·CC` bytes and by
  the extension if `X=1`. PT tells you which codec parser runs next — get the SDP mapping wrong and you
  parse the payload with the wrong depacketiser. SN and TS are independent: SN counts packets, TS counts
  media samples.
- **Security relevance:** RTP is the **entry point for attacker-controlled media bytes** into the modem.
  Its payload is normally **unauthenticated/unencrypted** (no SRTP on the access leg), so the peer or an
  on-path injector spoofing the 5-tuple/SSRC controls everything after the header. The **PT** value routes
  the payload to the vulnerable depacketisers behind F2 (text/`red` PT) and F7 (EVS PT). In-call only
  (**T3**).

---

## RTCP — RTP Control Protocol
- **What it is / meaning:** **RTCP** (RTP Control Protocol) is RTP's companion control channel, sent on a
  separate port (or multiplexed via RTCP-mux). It carries **statistics and control**, not media: how many
  packets were lost, jitter, round-trip estimates, and participant identity. It lets each side adapt (e.g.
  codec rate) and detect problems.
- **Purpose:**
  - Report reception quality: **Sender Report (SR)** and **Receiver Report (RR)** with loss/jitter stats.
  - Identify participants: **SDES** (source description — CNAME etc.).
  - App-specific and membership control: **APP**, **BYE**.
- **Specification:** IETF **RFC 3550** (same document as RTP): <https://datatracker.ietf.org/doc/html/rfc3550>.
- **Packet / PDU disposition:** RTCP packets share a common header and are usually stacked ("compound"):
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|  RC/SC  |  packet type  |            length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            SSRC of sender / packet-type-specific body …       |
```
  Common `packet type` values: **200 = SR**, **201 = RR**, **202 = SDES**, **203 = BYE**, **204 = APP**.
- **Key fields explained:**

  | Field | Meaning |
  |---|---|
  | V/P | version / padding, as in RTP |
  | RC/SC | report count (SR/RR) or source count (SDES) in this packet |
  | packet type | which RTCP report this is (200–204) |
  | length | packet length in 32-bit words minus one |
- **Beginner notes / gotchas:** RTCP is **control/telemetry, not media** — it never carries voice frames.
  It is easy to confuse SR/RR (quality feedback) with the actual RTP stream. Bandwidth is capped (~5% of
  session).
- **Security relevance:** a parsing surface in its own right (variable report blocks, SDES text), but the
  project's findings are in the RTP media depacketisers, not RTCP. Same in-call reachability (**T3**).

---

## RTP redundancy / RTT — RFC 2198 + RFC 4103
- **What it is / meaning:** For **Real-Time Text (RTT)** — live character-by-character text in a VoLTE
  call, the successor to TTY/textphone — 3GPP uses **RFC 4103** ("RTP Payload for Text Conversation")
  carrying **ITU-T T.140** text, almost always wrapped in the **RFC 2198** *redundancy* encoding (the SDP
  `red` payload type). Redundancy means each RTP packet repeats a few previous text generations so a lost
  packet does not drop characters. The redundancy is expressed as a **list of block headers** at the front
  of the payload.
- **Purpose:**
  - Protect real-time text against packet loss by carrying N older ("redundant") generations plus the new
    ("primary") one in each packet.
  - Tell the receiver, per block, its payload type, timestamp age, and length so it can split the payload.
- **Specification:** IETF **RFC 2198** (RTP redundant data): <https://datatracker.ietf.org/doc/html/rfc2198>;
  IETF **RFC 4103** (RTP payload for text / T.140): <https://datatracker.ietf.org/doc/html/rfc4103>;
  ITU-T **T.140**; 3GPP RTT usage in **TS 26.114**.
- **Packet / PDU disposition (RFC 2198 §3):** one or more **redundant** block headers (4 bytes each,
  F=1), terminated by a single **primary** header (1 byte, F=0), then the data blocks:
```
 redundant block header (4 bytes, F=1):
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F|  block PT   |    timestamp offset (14 bits)   | block length |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ (10 bits) ----+

 primary (final) block header (1 byte, F=0):
+-+-+-+-+-+-+-+-+
|0|  block PT   |
+-+-+-+-+-+-+-+-+

 [ redundant block header #1 ][ … #N ][ primary header ][ block#1 data ]…[ primary data ]
```
- **Key fields explained:**

  | Field | Width | Meaning |
  |---|---|---|
  | **F** | 1 | **1** = another redundant header follows; **0** = this is the final/primary header (list ends) |
  | **block PT** | 7 | payload type of that (redundant) generation |
  | **timestamp offset** | 14 | how old this redundant block is, relative to the RTP timestamp |
  | **block length** | 10 | length in bytes of that redundant data block |
- **Beginner notes / gotchas:** the **F-bit is the list terminator** — you walk 4-byte headers while F=1,
  then hit a 1-byte header with F=0. By design there are only a *handful* of redundant generations. The
  header list and the data blocks are two separate regions of the payload.
- **Security relevance:** **This is the exact structure finding F2 walks.** The modem's
  `ltecsr_tty_dl_count_blocks` (@`0x90cf9500`) loops over these 4-byte headers appending one entry per
  F-bit-set header into fixed ~5-slot stack arrays, with the block index only byte-truncated
  (`andi …,0xFF`) and **never bounded** against capacity. ≥70 concatenated F=1, block-length-0 headers
  drive the index to 69 and the halfword store at `struct+0x2A+2·v10` overwrites the caller's saved return
  address → **saved-RA stack overflow / RCE**. Attacker-controlled RTP text payload, **in-call (T3)**,
  unauthenticated media plane. Full detail: `../../F2.md`.

---

## EVS & AMR — voice-codec RTP payloads
- **What it is / meaning:** **AMR** (Adaptive Multi-Rate) and **EVS** (Enhanced Voice Services) are the
  **speech codecs** used for VoLTE/VoWiFi voice. AMR/AMR-WB (narrow/wideband) is the older mandatory codec;
  **EVS** is the modern high-quality codec (3GPP Rel-12+). What matters for the baseband is not the DSP but
  the **RTP payload framing** — the small header bytes that say how many speech frames are in the packet
  and what type each is. These framing bytes are parsed on the modem before the samples are decoded.
- **Purpose:**
  - Pack one or more speech frames per RTP packet with a per-frame **Table of Contents (ToC)** describing
    each frame's type/size.
  - Support **bandwidth/bit-rate adaptation** (mode changes signalled in the framing).
  - Feed the correct number of bytes to the decoder per frame.
- **Specification:** **AMR/AMR-WB** RTP payload: IETF **RFC 4867**:
  <https://datatracker.ietf.org/doc/html/rfc4867> (codecs: 3GPP **TS 26.071** AMR, **TS 26.171** AMR-WB).
  **EVS** codec: 3GPP **TS 26.445** (<https://www.3gpp.org/dynareport?code=26.445.htm>), with the EVS RTP
  payload format in **TS 26.445 Annex A** and usage in **TS 26.114**.
- **Packet / PDU disposition:**

  **AMR (RFC 4867, bandwidth-efficient/octet-aligned):** a payload header (CMR) then a **ToC**, one entry
  per frame:
```
 AMR ToC entry (one per speech frame):
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|F|  FT   |Q|P P|      F = 1 -> another ToC entry follows (more frames)
+-+-+-+-+-+-+-+-+      FT = frame type (mode / bit-rate)   Q = frame OK (quality)
```
  So the receiver walks ToC entries while **F=1**, then the frame-data blocks follow.

  **EVS (TS 26.445 Annex A):** two formats.
  - **Compact format:** no ToC byte — the RTP payload **length itself** selects the frame type via a size
    table (this is what `VOLTE_FM_EVS_CF_CountFrames` @`0x90cec370` does: maps `8·len` against a size
    ladder `0x140`, `0x1E8`, `0x500`, …).
  - **Header-full format:** a CMR byte then a **ToC**, one byte per frame, each with a **continuation bit**:
```
 EVS header-full ToC byte (one per frame):
 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+
|H| F | FT(...) |   H = header-type, F = "another ToC byte follows" (continuation),
+-+-+-+-+-+-+-+-+   FT = EVS mode / frame type -> frame byte-length
```
- **Key fields explained:**

  | Field | Codec | Meaning |
  |---|---|---|
  | **CMR** | AMR / EVS | Codec Mode Request — asks the sender for a rate/mode |
  | **F** (AMR) / continuation (EVS) | both | **1** = another ToC/frame follows; drives the ToC walk |
  | **FT** | both | frame type → decodes to the frame's bit-rate and byte-length |
  | **Q** | AMR | frame quality/OK bit |
  | length→type | EVS compact | payload length alone selects the frame type (no ToC) |
- **Beginner notes / gotchas:** the "ToC" is just a list of tiny per-frame descriptors; the number of
  frames is implied by the **continuation/F bit**, not an explicit count — so a malformed stream can claim
  "more frames" indefinitely. EVS has *two* framing modes (compact vs header-full) that look nothing alike
  on the wire; which one is used affects how length maps to frame type.
- **Security relevance:** **This is the structure finding F7 walks.** The EVS depacketiser loops over ToC
  entries driven by the per-frame continuation bit / by a length→size table on attacker-influenced RTP
  payload size, and (like F2) writes per-frame results into a fixed stack buffer without a hard bound on
  the frame count — a length/index-driven parse that overflows the saved return area (saved-RA overflow in
  an EVS depacketiser). Attacker-controlled RTP voice payload, **in-call (T3)**, unauthenticated media
  plane. See `../../catalog/catalog_cross.md` (F7 area, `VOLTE_FM_EVS_CF_CountFrames` @`0x90cec370`).
