# Encoding schemes — how messages become bytes (and why decoders are buggy)

Every protocol in this stack eventually has to put a structured message *onto the wire*: turn a nested
"here is a System Information message with these fields" into a flat run of octets, and back again. The
rules for that packing are the **encoding scheme**. This chapter is the "why decoders are hard" chapter,
because:

> **Attackers control bytes. The decoder turns bytes → structs. Every unchecked length, count, or index
> inside a decoder is a candidate bug.**

A decoder is just `parse(attacker_bytes) → struct`. When it reads an attacker-supplied *number* and uses
it as a **length** (how many bytes to copy), a **count** (how many elements follow), or an **index**
(where to store), and does not first check that value fits the destination, you get an out-of-bounds
read or write. That single shape — an unclamped length/count/index — is the root cause of **most of this
project's findings** (see `/workspace/CONSOLIDATED_FINDINGS.md`). The encoding scheme decides *how* that
number is packed into the bytes, so knowing the scheme tells you where to look.

For the big-picture placement of these encodings in the L1/L2/L3 stack, see
`../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` §3.

### Which RAT / layer uses which encoding

| Encoding | Used by | Where |
|---|---|---|
| **ASN.1 + PER/UPER** | RRC (3G UMTS, 4G LTE, 5G NR) | radio control, broadcast SI, paging |
| **TLV / TV / LV / TLV-E** | NAS (EMM/ESM, 5GMM/5GSM), some RR | core-network signalling IEs |
| **CSN.1** | GSM RR + GPRS RLC/MAC | 2G control channels, packet data |
| **BCD** | phone numbers, IMSI, digits — inside the above | Emergency Number List, SMS addresses |

### Contents
1. [ASN.1 with PER / UPER](#1-asn1-with-per--uper--rrc)
2. [The TLV family — TLV / TV / LV / TLV-E](#2-the-tlv-family--tlv--tv--lv--tlv-e--nas)
3. [CSN.1](#3-csn1--gsm-rr--gprs)
4. [BCD](#4-bcd--packed-decimal-digits)

---

## 1. ASN.1 with PER / UPER  (RRC)

**What it is / meaning.** **ASN.1** = *Abstract Syntax Notation One*. It is two things: (a) a **schema
language** to *describe* the shape of a message abstractly — "a `SEQUENCE` with an optional integer, a
list of up to 8 cells, …" — and (b) a family of **encoding rules** that say how to serialise a value of
that shape into bytes. RRC (the radio control layer of 3G/4G/5G — see the RRC protocol doc in this
folder) uses the **Packed Encoding Rules**: **PER** (aligned) and **UPER** (Unaligned PER). "Packed"
means bit-level tight: fields are not byte-aligned padded, they are laid down bit after bit to make
broadcast messages as small as possible. The RRC ASN.1 *schema* is not a separate spec — it lives as an
**ASN.1 module at the very end of each RRC spec** (TS 25.331 / 36.331 / 38.331). A code generator turns
that module into the thousands of `AsnDecode_RRC_*` / `AsnDecode_NR_*` functions in this image.

**Purpose.**
- Compress control-plane messages to the minimum number of bits (broadcast is expensive airtime).
- Provide a formal, versionable schema so base station and phone agree on structure.
- Support forward compatibility via **extension markers** (new fields added in later releases).

**Specification.**
- ASN.1 syntax: **ITU-T X.680** — https://www.itu.int/rec/T-REC-X.680
- PER / UPER encoding: **ITU-T X.691** — https://www.itu.int/rec/T-REC-X.691
- RRC schema modules: **TS 25.331** (UMTS) https://www.3gpp.org/dynareport?code=25.331.htm ·
  **TS 36.331** (LTE) https://www.3gpp.org/dynareport?code=36.331.htm ·
  **TS 38.331** (NR) https://www.3gpp.org/dynareport?code=38.331.htm — the ASN.1 module is the last annex.

**How PER/UPER packs bits.** There is no per-field type tag or delimiter on the wire (unlike TLV) — the
decoder knows the field order and widths *from the schema*, so it reads a fixed number of bits for each
field in sequence. The variable-length machinery rests on three mechanisms:

- **Optional-field bitmap (preamble).** A `SEQUENCE` with N `OPTIONAL` fields is preceded by an N-bit
  bitmap: bit=1 means "this optional field is present below". The decoder reads N bits, then reads only
  the present fields.
- **Extension marker (`...`).** If the schema has an extension marker, one leading bit says "extension
  bits follow" (a later release added fields). This lets an old decoder skip fields it does not know.
- **Length determinant.** For anything variable-length (a `SEQUENCE OF`, an octet string, a constrained
  integer count), PER writes a **length determinant** before the payload. Its encoding (X.691 §10.9):

  ```
  value < 128        →  1 octet :  0xxxxxxx                (the length, 0..127)
  128 ≤ value <16384 →  2 octets:  10xxxxxx xxxxxxxx       (14-bit length, 0..16383)
  value ≥ 16384      →  fragmented: 11000nnn  then nnn×16K-item chunks, repeated
  ```

  So the top 1–2 bits are a *self-describing size prefix*, and the rest is the count/length.

**Aligned vs unaligned.** In **aligned PER**, after such a length determinant the encoder inserts padding
bits so the payload starts on an octet boundary (easier to memcpy). In **UPER** there is no padding —
everything is bit-packed with no alignment, which is what LTE/NR SI use. The decoder therefore must run a
**bit-reader** to pull arbitrary bit-runs across byte boundaries.

**Worked example (UPER `SEQUENCE OF`).** Schema `neighCellList SEQUENCE (SIZE(0..8)) OF Cell`. Because
the max is 8, the count fits in `ceil(log2(9)) = 4` bits — so the decoder reads a **4-bit count** (0..8),
then decodes exactly that many `Cell` elements. If instead the size constraint were large/unbounded, the
count arrives as a **length determinant** (the 1/2-octet form above) and can be up to 16383 before
fragmentation. That number is the danger.

### The shared PER runtime in this image

All the generated decoders call one small set of hand-written primitives (Huawei symbols):

| Primitive | Address | Job |
|---|---|---|
| `getShortBits` | `0x900901c0` | read a small bit-run (≤ a few bits) from the PDU |
| `getBits` | `0x…` | read a mid-width bit-run |
| `getLongBits` | `0x9009028a` | read a wide bit-run / octet string body |
| `GetUperLengthDeterminant` | `0x9009021e` | decode the length-determinant per the table above |
| `AsnError` | `0x900900bc` | `longjmp` target on PDU overrun |

**The systemic weakness (this is the crux).** The bit-readers are **source-bounded**: if a read would run
off the end of the received PDU they `longjmp` to `AsnError`, so you cannot over-**read** the input past
its end. **But there is no destination bounding.** `GetUperLengthDeterminant` returns an **unclamped
0..16383** to **~202 call sites**, and `getLongBits` / the `__wrap_memcpy` sinks do **no check against the
destination buffer size**. Memory safety is therefore delegated to ~200 hand-written or codegen'd clamps
scattered across the decoders, with **no central enforcement**. Any decoder that takes a length
determinant or a `SEQUENCE OF` count and copies/indexes that many units into a **fixed-size** buffer
**without clamping to the destination** is a bug of the exact F1–F6 shape. (See
`/workspace/VULN_REPORT.md` "Systemic weakness" and `/workspace/BASEBAND_VULN_DEEPDIVE.md` §Systemic root
cause.)

**Why an unclamped count is the classic RRC bug.** Because PER is so compact, a *few bytes* of length
determinant can request a *huge* number of elements — the message expands dramatically on decode. If the
decoder writes those elements into a buffer sized for the schema's real maximum but never re-checks the
attacker's count against that maximum, the surplus elements land past the buffer. This is exactly **F6/F9
— NR System-Information reassembly** (`NL1_CTRL_Nrrc_Reconstruct_Raw_Data` @`0x90ee9e26`): a segment
descriptor's `nseg × segLen` drives an unbounded copy into a 380-byte stack buffer, the only guard being
`nseg == 0`, and it is **pre-auth broadcast (T0)** — the worst tier. It is also the shape of **F10** (a
9-bit PCID indexing a 63-byte bitmap with values 504..511 not rejected → 1-bit OOB, T0 broadcast).

> Beginner note: the 3G **UMTS** RRC decoders (all ~1296 `AsnDecode_RRC_*`) plus the core PER runtime were
> found to be *systematically bounded* here (exact-fit buffers, `longjmp` guards). The live UPER problems
> cluster in the **NR / LTE SI reassembly** glue that runs *before* the ASN dispatcher, not in the core
> primitives themselves.

---

## 2. The TLV family — TLV / TV / LV / TLV-E  (NAS)

**What it is / meaning.** NAS (the core-network signalling layer — EMM/ESM in 4G, 5GMM/5GSM in 5G; see
the NAS protocol doc in this folder for the message layouts) does **not** use ASN.1. Its messages are a
fixed header followed by a series of **Information Elements (IEs)**, each hand-encoded in one of a small
family of formats built from three parts: **T**ype (the IEI, an identifier tag), **L**ength (how many
value octets), and **V**alue. The formats differ in which of T/L are present and how wide L is.

**Purpose.**
- Let a NAS message carry optional IEs in any order, each self-identified by its Type tag.
- Keep mandatory fixed fields compact (no length overhead) while variable fields carry a length.

**Specification.** The generic IE format rules are in **3GPP TS 24.007** §11.2.1 —
https://www.3gpp.org/dynareport?code=24.007.htm . The actual IE catalogues are per-protocol: TS 24.301
(4G EMM/ESM), TS 24.501 (5G 5GMM/5GSM), TS 24.008 (legacy CS/PS).

**The five layouts on the wire.**

```
 T  (Type only, "T"):        +--------+
                             |  IEI   |                        1 octet, no value
                             +--------+

 V  (Value only):            +========+ ...                    fixed length, position-defined
                             | value  |                        (no tag, no length)
                             +========+

 TV (Type-Value):            +--------+========+ ...           1-octet IEI, then fixed-len value
                             |  IEI   | value..|               (often IEI+value packed in 1 octet
                             +--------+========+                for a "half-octet" TV)

 LV (Length-Value):          +--------+========+ ...           1-octet length, then that many octets
                             | length | value..|               (no tag — position identifies it)
                             +--------+========+

 TLV (Type-Length-Value):    +--------+--------+========+ ...  1-octet IEI, 1-octet length, value
                             |  IEI   | length | value..|
                             +--------+--------+========+

 TLV-E (TLV, Extended len):  +--------+--------+--------+====+ 1-octet IEI, TWO-octet length, value
                             |  IEI   | len hi | len lo |val.|  (value up to 65535 octets)
                             +--------+--------+--------+====+
```

**Key point:** in **LV / TLV / TLV-E** an attacker-controlled **length octet(s)** directly says how many
value bytes to copy. TLV uses **one** length octet (0..255); **TLV-E** uses **two** (0..65535) — used for
large IEs like *LADN Information* (IEI `0x79`) and containers. The classic NAS bug is: read the length,
copy that many bytes into a fixed struct field, **never check it fits**. That is the direct cause of:

- **F3** — LTE ESM PCO: container count/length index into an 84-byte context list with no bound (T1).
- **F4** — 5GMM LADN: a TLV-E DNN length copied into a 100-byte stack buffer (T4).
- **F5** — 5GMM Emergency Number List: per-entry length not clamped to the 43-byte entry stride (T4).
- **F13** — EMM integrity check: `(u16)(len − 5)` underflows to ~65531 when `len < 5` → ~64 KB OOB read.

See the NAS protocol doc for how these IEs sit inside their messages, and `../F3.md`/`../F4.md`/`../F5.md`
for the traces.

---

## 3. CSN.1  (GSM RR / GPRS)

**What it is / meaning.** **CSN.1** = *Concrete Syntax Notation One*. It is a **bit-field description
language** used by 2G — GSM Radio Resource (RR) messages and GPRS RLC/MAC control blocks. Where ASN.1/PER
separates an abstract schema from encoding rules, CSN.1 describes the **concrete bit layout directly**:
each construct is spelled out as literal bits, choices, and repetitions. It reads like a grammar of `0`/`1`
literals, `<field : bit(n)>` fields, `{ … | … }` alternatives, and `{ 0 | 1 < … > } **` style optional /
repeating groups. Messages are decoded by a **bespoke, hand-written bit-reader** that walks the grammar.

**Purpose.**
- Pack 2G control messages (System Information, Immediate Assignment, packet assignments) into tight
  bit-fields on narrow, error-prone radio channels.
- Express complex optionality and repetition (linked lists of frequency descriptions, etc.) at bit
  granularity.

**Specification.** CSN.1 itself is defined in an informative description (Bellcore / the CSN.1
specification by J. Nurmi et al.) and is used normatively throughout **3GPP TS 44.060** (GPRS RLC/MAC —
the messages are given as CSN.1) https://www.3gpp.org/dynareport?code=44.060.htm and TS 44.018 (GSM RR).
The CSN.1 language and its use are summarised in TS 44.060 and related annexes.

**How it packs (worked shape).** A CSN.1 repeated list often looks like:

```
{ 1 < Frequency : bit(10) > } ** 0        ; "while next bit == 1, read a 10-bit frequency; 0 ends the list"
```

The bit-reader reads a 1-bit flag; if `1`, it reads a 10-bit field and stores it, then loops; a `0`
terminates. **The danger:** the *number of iterations is attacker-controlled by the stream of 1-bits*, and
if the reader stores each element into a fixed array without capping the iteration count, an attacker can
drive the list past the array. This is the same unclamped-**count** shape as a PER `SEQUENCE OF`, just in a
hand-rolled reader. In this image the GSM/GPRS CSN.1 paths (RLC/MAC, Immediate Assignment, SI/PSI freq
lists) were largely found **bounded** (loops capped `!= 16`/`< 30`, two-pass count-then-allocate), but two
live issues sit right here: **F8** (GSM Cell-Broadcast 7→8-bit septet unpack, unclamped count — latent
T0) and **F10** (neighbour E-UTRAN PCID bitmap off-by-one, T0), plus an unconfirmed SI2quater inline
frequency-list lead (`sub_90786014`, up to 124 entries stored without the 64-clamp — see
`hunt_RRC_legacy.md`).

---

## 4. BCD  — packed decimal digits

**What it is / meaning.** **BCD** = *Binary-Coded Decimal*. Decimal digits (0–9) are stored **two per
octet**, one digit in each **nibble** (4-bit half). 3GPP uses a *semi-octet swapped* variant: within each
octet the **low nibble holds the first digit, the high nibble the second** — i.e. the two digits are
"swapped" relative to reading order. When there is an **odd** number of digits, the final high nibble is
padded with **`0xF`** (the filler). BCD is not a message format on its own — it is how *digit strings*
(phone numbers, IMSI/IMEI, SMS addresses, emergency numbers) are packed **inside** TLV/CSN.1/ASN.1 IEs.

**Purpose.**
- Store dialled/identity digits compactly (2 digits per byte) while staying decimal-exact.
- Encode phone-number-style fields uniformly across CS, SMS, and NAS.

**How it packs (worked example).** The number **"123"** (odd length):

```
 nibbles per octet, LOW nibble first (semi-octet swap):
   octet 0:  digit2=2 (hi) | digit1=1 (lo)  →  0x21
   octet 1:  filler=F (hi) | digit3=3 (lo)  →  0xF3
 on the wire:  21 F3
```

To decode you read each octet, emit `low nibble` then `high nibble`, and **stop at `0xF`**. The
attacker-facing risks are: (1) a **length octet** counting BCD octets that is not clamped to the digit
buffer, and (2) the digit-count derived from that length (`digit_len = length − 1` etc.) used as a copy
size or store index without bound.

**Where it bites in this project.**
- **F5 — 5GMM Emergency Number List** (`vgmm_decode_emergency_number_list` @`0x9187772c`): each entry is
  `{ length | service-category | BCD-packed emergency digits }`. The decoder computes `digit_len =
  length − 1` and stores that many BCD digit octets into a **43-byte-stride** entry via an indexed store
  **never bounded** against the 43-byte slot or the 689-byte buffer → heap overflow (`../F5.md`).
- **SMS address decode** (SMS-AL): TP-Originating/Destination-Address digits are BCD; the mainline here
  *does* clamp (TP-address to 20 semi-octets, UD to 0x8C) — a good example of the clamp that F5 is
  missing.

---

## Takeaway for a beginner

Four different schemes, **one recurring bug**. Whether the size arrives as a PER **length determinant**, a
PER/CSN.1 **element count**, a TLV **length octet**, or a **BCD digit length**, the vulnerability is the
same: the decoder trusts an attacker-supplied number and uses it as a length/count/index into a
fixed-size destination **without clamping**. The bit-readers here guard the *source* (you can't read past
the received PDU), but almost nothing guards the *destination* — which is why "find the missing clamp" is
the whole game, and why the pre-auth broadcast decoders (RRC SI via UPER, GSM SI via CSN.1) are the
scariest place for one to be missing. Cross-reference `/workspace/CONSOLIDATED_FINDINGS.md` and the
per-finding docs `../F1.md … ../F6.md`.
