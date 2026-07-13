# L1 / Physical layer (PHY) across 2G/3G/4G/5G

The **physical layer (PHY, "L1")** is the bottom of the stack: it turns bits into radio waveforms and
back (modulation, channel coding, timing, power control) and carries **transport blocks** for L2/L3.
Unlike the byte-parsed protocols higher up, PHY is a *waveform*, so this file shows each generation's
**frame/subframe/slot timing structure** and the **channel-mapping** (logical → transport → physical)
instead of bit-exact PDUs. On this MediaTek modem most of PHY runs on a **separate Coresonic DSP**, not
the nanoMIPS core — L1 hands *transport blocks plus descriptors* (lengths, segment counts) UP to L2/L3,
and that L1→RRC handoff is where the NR System-Information reassembly bug (F6/F9) lives.

See `../fundamentals/01_3GPP_LAYERS_EXPLAINER.md` §L1 for the big picture, and `../fundamentals/03_GLOSSARY_AND_NAMING.md` for terms.

**Contents**
- [Channel mapping — logical vs transport vs physical](#channels--logical-vs-transport-vs-physical-channels)
- [GSM PHY (2G)](#gsm-phy--2g-physical-layer-tdmagmsk)
- [WCDMA PHY (3G)](#wcdma-phy--3g-umts-physical-layer-cdma)
- [LTE PHY (4G)](#lte-phy--4g-physical-layer-ofdma)
- [NR PHY (5G)](#nr-phy--5g-new-radio-physical-layer-flexible-ofdma)

---

## Channels — logical vs transport vs physical channels
- **What it is / meaning:** A single concept beginners MUST grasp before anything else makes sense.
  3GPP does not send data on one kind of "channel" — it stacks **three abstractions**, each owned by a
  different layer. **Logical channels** (owned by RLC/MAC, L2) describe *what kind of information* is
  carried (control vs traffic, broadcast vs dedicated). **Transport channels** (the MAC↔PHY boundary)
  describe *how* it is delivered over the air (with what coding/format). **Physical channels** (owned by
  PHY, L1) are the actual sets of radio resources (time/frequency/code) the bits ride on. MAC maps
  logical→transport; PHY maps transport→physical. This applies to UMTS, LTE and NR (GSM uses a simpler,
  older channel taxonomy — see that section).
- **Purpose:**
  - Separate "meaning" from "delivery" so the same info can be sent different ways (e.g. broadcast SI can
    go via PBCH or via PDSCH).
  - Give MAC a clean scheduling job: multiplex several logical channels onto one transport channel.
  - Let PHY optimise coding/modulation per transport channel independently of content.
- **Specification:** LTE mapping TS 36.321 (MAC) §4.5 + TS 36.211; NR mapping TS 38.321 §4.5 + TS 38.211.
  3GPP browser: <https://portal.3gpp.org/> · direct: <https://www.3gpp.org/dynareport?code=38.321.htm> ·
  diagrams: <https://www.sharetechnote.com/>
- **The mapping (downlink example — the one everyone memorises):**
```
  LOGICAL  (L2/RLC-MAC: "what")   TRANSPORT (MAC↔PHY: "how")   PHYSICAL (L1: "where on the air")
  ─────────────────────────────   ──────────────────────────   ────────────────────────────────
  BCCH  Broadcast Control  ─┬────▶ BCH   Broadcast Ch      ────▶ PBCH   (carries MIB)
                           └────▶ DL-SCH Downlink Shared   ─┬──▶ PDSCH  (carries SIBs, and all user data)
  PCCH  Paging Control      ────▶ PCH   Paging Ch          ─┘
  CCCH  Common Control      ────▶ DL-SCH ──────────────────────▶ PDSCH
  DCCH  Dedicated Control   ────▶ DL-SCH ──────────────────────▶ PDSCH
  DTCH  Dedicated Traffic   ────▶ DL-SCH ──────────────────────▶ PDSCH
       (scheduling grants, no logical/transport ch) ───────────▶ PDCCH  (carries DCI)
  Uplink: CCCH/DCCH/DTCH ─▶ UL-SCH ─▶ PUSCH ; random access ─▶ RACH ─▶ PRACH ; feedback ─▶ PUCCH
```
- **Key names explained:**

| Channel | Layer | Meaning |
|---|---|---|
| BCCH / PCCH / CCCH / DCCH / DTCH | logical | Broadcast / Paging / Common / Dedicated control, Dedicated traffic |
| BCH / PCH / DL-SCH / UL-SCH / RACH | transport | Broadcast, Paging, DL-Shared, UL-Shared, Random-Access |
| PBCH / PDSCH / PDCCH / PUSCH / PUCCH / PRACH | physical | Broadcast, DL-Shared-data, DL-Control, UL-data, UL-Control, Random-Access |
- **Beginner notes / gotchas:** the same acronym prefix (P = "Physical") only appears at the physical
  layer (PBCH, PDSCH…). Do not confuse **BCCH** (logical) with **BCH** (transport) with **PBCH**
  (physical) — they are three views of "broadcast". PDCCH carries **DCI** (Downlink Control Information =
  scheduling grants), which has no logical/transport channel — it is pure L1 control. GSM predates this
  model and uses its own flat channel names (BCCH, CCCH, SDCCH, TCH…) directly on timeslots.
- **Security relevance:** the attacker rarely byte-parses PHY, but the **channel that carries the bits
  decides reachability**. Anything mapped to **PBCH/PDSCH-as-broadcast (BCCH→BCH/DL-SCH)** is read
  pre-auth by every phone in range (tier **T0**) — this is precisely the path the NR SI reassembly bug
  rides in on.

---

## GSM PHY — 2G physical layer (TDMA/GMSK)
- **What it is / meaning:** **GSM** (Global System for Mobile communications) PHY is a **TDMA**
  (Time-Division Multiple Access) system: a carrier is split in time into repeating **timeslots**, and
  users take turns. Modulation is **GMSK** (Gaussian Minimum-Shift Keying), a constant-envelope phase
  modulation (EDGE adds 8-PSK). It sits at L1 with GSM **RR** (Radio Resource) / LAPDm above it.
- **Purpose:**
  - Multiplex up to 8 logical users onto one 200 kHz carrier via time slots.
  - Channel-code and interleave data for robustness; frequency-hop for diversity.
  - Maintain frame/burst timing so the network can align many phones (timing advance).
- **Specification:** general TS 45.001, multiplexing/multiple-access TS 45.002, channel coding TS 45.003,
  modulation TS 45.004, transmission/reception TS 45.005, radio link control TS 45.008; device
  conformance **TS 51.010**. Direct: <https://www.3gpp.org/dynareport?code=45.002.htm> ·
  <https://www.3gpp.org/dynareport?code=45.001.htm> · <https://www.sharetechnote.com/html/BasicProcedure_GSM.html>
- **Timing / burst structure (this is GSM's "PDU"):**
```
  Hyperframe (2048 superframes ≈ 3h 28m)
   └─ Superframe (26×51 = 1326 TDMA frames ≈ 6.12 s)
       └─ Multiframe : 26-frame (traffic, 120 ms)  or  51-frame (control, 235 ms)
           └─ TDMA frame = 8 timeslots ≈ 4.615 ms
               └─ Timeslot ≈ 577 µs = 156.25 bit periods → carries one BURST

  Normal burst (156.25 bits):
  +----+-----------+---+----------------+---+-----------+----+---------+
  | T3 | 57 data   | S | 26 training    | S | 57 data   | T3 | 8.25 GP |
  +----+-----------+---+----------------+---+-----------+----+---------+
   tail  encrypted  stealing  midamble  stealing encrypted tail guard
```
- **Key fields explained:**

| Element | Meaning |
|---|---|
| Tail bits (3+3) | Known bits letting the equaliser converge at burst edges |
| Data (57+57) | Payload half-bursts (ciphered under A5 when encryption on) |
| Stealing flags (1+1) | Mark whether the burst was "stolen" for FACCH signalling |
| Training seq (26) | Known midamble for channel estimation |
| Guard period (8.25) | Silence between bursts to absorb timing spread |
- **Beginner notes / gotchas:** GSM channels are named directly on timeslots (**BCCH, CCCH, SDCCH,
  SACCH, TCH**) — there is no logical/transport/physical three-tier split like UMTS+. "Frame" here is a
  4.615 ms TDMA frame, not an LTE 10 ms frame. GPRS (2.5G) reuses these bursts for packet data
  (PDTCH/PACCH). EDGE swaps GMSK for 8-PSK on the same timeslots.
- **Security relevance:** PHY bits are ciphered by A5 but the **BCCH/CCCH are broadcast in the clear** so
  the phone can camp — the parseable attack surface is at RR/L2 above, not the waveform. No PHY-layer
  finding in this project is on 2G; relevance is indirect (lengths/counts fed up to RR).

---

## WCDMA PHY — 3G UMTS physical layer (CDMA)
- **What it is / meaning:** **WCDMA** (Wideband Code-Division Multiple Access) is the 3G/UMTS air
  interface. Instead of time slots, all users share the **same 5 MHz carrier at the same time**, separated
  by orthogonal **spreading codes** (CDMA). Each data symbol is multiplied ("spread") by a fast code at
  **3.84 Mcps** (mega-chips/sec); the receiver de-spreads with the matching code. Modulation is QPSK.
  UMTS **RRC**/MAC sit above.
- **Purpose:**
  - Spread each user's symbols with an **OVSF** code (spreading factor 4–512) so many users coexist.
  - Apply per-cell/per-UE **scrambling codes** to separate cells and uplinks.
  - Fast **closed-loop power control** (1500 Hz) to fight the near-far problem.
- **Specification:** general TS 25.201; physical channels & transport-channel mapping (FDD) TS 25.211;
  multiplexing/channel coding TS 25.212; spreading/modulation TS 25.213; physical procedures TS 25.214.
  Direct: <https://www.3gpp.org/dynareport?code=25.211.htm> ·
  <https://www.3gpp.org/dynareport?code=25.213.htm> · <https://www.sharetechnote.com/html/Handbook_WCDMA.html>
- **Timing / spreading structure:**
```
  Radio frame = 10 ms = 38 400 chips
   └─ 15 slots × 0.667 ms  (2560 chips/slot)   [superframe = 72 frames = 720 ms]

  Spreading:  data symbol ── × OVSF code (SF 4..512) ──▶ chips ── × scrambling code ──▶ Tx
              (SF sets data rate: low SF = high rate)

  Transport→physical mapping (FDD downlink):
    BCH  ─▶ P-CCPCH (primary common control physical ch)
    PCH ┐
    FACH┘─▶ S-CCPCH        DCH ─▶ DPCH (dedicated)     (+ SCH/CPICH for sync/pilot, no transport ch)
```
- **Key fields explained:**

| Concept | Meaning |
|---|---|
| Chip / chip rate (3.84 Mcps) | The fast spreading rate; symbols are made of many chips |
| Spreading Factor (SF) | Chips per symbol; SF=n gives n orthogonal codes at 1/n the rate |
| OVSF code | Orthogonal Variable Spreading Factor code — separates channels within a cell |
| Scrambling code | Separates cells (DL) / UEs (UL); does not change bandwidth |
| Transport Format (TF) / TFCI | Tells the receiver the block size/coding used this frame |
- **Beginner notes / gotchas:** there are **no OFDM subcarriers or resource blocks** in 3G — that is a
  4G/5G idea. UMTS transport channels (BCH/PCH/FACH/RACH/DCH) map to **CCPCH/DPCH** physical channels, not
  PDSCH/PDCCH (those are LTE+ names). "Frame" is 10 ms (same duration as LTE, but structured as 15 slots
  of chips, not OFDM symbols).
- **Security relevance:** as with GSM, the waveform is not the attack surface; **BCH broadcast (System
  Information)** is read pre-auth and the parse bug (if any) is in UMTS RRC above. No 3G PHY finding here.

---

## LTE PHY — 4G physical layer (OFDMA)
- **What it is / meaning:** **LTE** (Long-Term Evolution) PHY replaces CDMA with **OFDMA** (Orthogonal
  Frequency-Division Multiple Access) on the downlink and **SC-FDMA** on the uplink: the band is split
  into many narrow **15 kHz subcarriers**, grouped into **resource blocks (RB)**, and users get
  rectangles of time×frequency. Modulation is QPSK/16QAM/64QAM. **PDCP/RLC/MAC** sit above, feeding
  transport blocks down.
- **Purpose:**
  - Schedule users in the time-frequency grid (frequency-selective scheduling, HARQ).
  - Carry broadcast (PBCH/MIB, PDSCH/SIB), paging, control (PDCCH/DCI) and shared data (PDSCH).
  - Provide PRACH for initial random access and PUCCH/PUSCH uplink.
- **Specification:** general TS 36.201; physical channels & modulation TS 36.211; multiplexing/channel
  coding TS 36.212; physical procedures TS 36.213. Direct:
  <https://www.3gpp.org/dynareport?code=36.211.htm> · <https://www.3gpp.org/dynareport?code=36.201.htm> ·
  <https://www.sharetechnote.com/html/Handbook_LTE_FrameStructure_DL.html>
- **Timing / resource-grid structure:**
```
  Radio frame = 10 ms
   └─ 10 subframes × 1 ms
       └─ subframe = 2 slots × 0.5 ms
           └─ slot = 7 OFDM symbols (normal CP)  |  6 (extended CP)

  Resource grid:  Resource Block (RB) = 12 subcarriers (=180 kHz) × 1 slot
                  Resource Element (RE) = 1 subcarrier × 1 OFDM symbol  (smallest unit)

  Physical channels:  PBCH(MIB) · PDCCH(DCI/scheduling) · PDSCH(SIB + user data)
                      PRACH(random access) · PUSCH(UL data) · PUCCH(UL control)
```
- **Key fields explained:**

| Concept | Meaning |
|---|---|
| Subcarrier spacing | Fixed **15 kHz** in LTE |
| Resource Block (RB) | 12 subcarriers × 1 slot — the unit the scheduler allocates |
| Resource Element (RE) | 1 subcarrier × 1 symbol — the atomic time-freq cell |
| CP (Cyclic Prefix) | Guard copied to symbol front to absorb multipath (normal/extended) |
| Transport Block (TB) | The MAC payload PHY delivers per TTI (1 ms) with a size descriptor |
| DCI (on PDCCH) | Downlink Control Information: the grant telling the UE where its PDSCH is |
- **Beginner notes / gotchas:** LTE fixes SCS at 15 kHz and slot=0.5 ms — this becomes **flexible** in 5G
  (next section). MIB rides **PBCH**; SIBs ride **PDSCH** scheduled by PDCCH — both are broadcast/pre-auth.
  The **transport block** PHY hands up is what L2/L3 then parse; PHY also supplies its **size/length**.
- **Security relevance:** PHY itself is not byte-parsed by an attacker, but **its transport-block lengths
  and counts feed MAC/RLC/RRC**. If those are trusted unchecked, an L1→L2/L3 boundary bug appears. The
  4G analogue of the NR SI bug lives at this handoff (see `../catalog/catalog_4G.md`).

---

## NR PHY — 5G New Radio physical layer (flexible OFDMA)
- **What it is / meaning:** **NR** (New Radio) is the 5G air interface — OFDMA like LTE but with
  **flexible numerology**: the subcarrier spacing is **SCS = 15 × 2^µ kHz** for numerology µ = 0…4
  (15/30/60/120/240 kHz), letting the same framework serve sub-6 GHz and **mmWave**. It introduces the
  **SS/PBCH block ("SSB")**, **bandwidth parts (BWP)**, and **mini-slots**. **SDAP/PDCP/RLC/MAC** sit above.
- **Purpose:**
  - Scale slot length with µ (higher SCS = shorter slot = lower latency) for diverse services.
  - Pack sync + broadcast into one compact **SSB** the UE finds during cell search.
  - Let the UE operate on a narrow **BWP** rather than the whole (wide) carrier to save power.
  - Support **mini-slot** (2/4/7-symbol) scheduling for latency-critical bursts.
- **Specification:** general TS 38.201; physical channels & modulation TS 38.211; multiplexing/channel
  coding TS 38.212; PHY procedures for control TS 38.213; PHY procedures for data TS 38.214. Direct:
  <https://www.3gpp.org/dynareport?code=38.211.htm> · <https://www.3gpp.org/dynareport?code=38.201.htm> ·
  <https://www.sharetechnote.com/html/5G/5G_FrameStructure.html>
- **Timing / flexible-numerology structure:**
```
  Radio frame = 10 ms  (fixed) ── 10 subframes × 1 ms (fixed)
   └─ slots per subframe = 2^µ    slot = 14 OFDM symbols (normal CP)
        µ=0  SCS 15 kHz  → 1 slot/ms  (1 ms slot)     µ=3 SCS 120 kHz → 8 slots/ms (125 µs)
        µ=1  SCS 30 kHz  → 2 slots/ms (0.5 ms)        µ=4 SCS 240 kHz → 16 slots/ms (SSB only)

  SSB (SS/PBCH block): 4 OFDM symbols × 240 subcarriers → PSS + SSS + PBCH(MIB)
  BWP: a contiguous subset of RBs the UE is told to use.  Mini-slot: 2/4/7-symbol grant.

  Channels: PBCH(MIB in SSB) · PDCCH(DCI) · PDSCH(SIB1+/user data) · PRACH/PUSCH/PUCCH
```
- **Key fields explained:**

| Concept | Meaning |
|---|---|
| Numerology µ | Selects SCS = 15·2^µ kHz and slots-per-subframe = 2^µ |
| SSB | SS/PBCH block: PSS/SSS (sync) + PBCH (MIB) in 4 symbols — the cell-search beacon |
| BWP (Bandwidth Part) | Active RB subset a UE uses, so it need not tune the whole carrier |
| Mini-slot | Sub-slot scheduling (type-B) for low latency |
| Transport Block + descriptor | What PHY hands to L2/L3, with length/segment metadata |
- **Beginner notes / gotchas:** the **frame (10 ms) and subframe (1 ms) are fixed**; only the **slot
  count** changes with µ — the classic 5G confusion. MIB is in the **SSB/PBCH**, but **SIB1 and other SI**
  ride PDSCH and are **segmented/reassembled** by the UE — that reassembly is the exact spot of interest.
- **Security relevance:** **HIGH — this is where a project finding lives.** NR **System Information is
  broadcast, pre-auth (tier T0)**, and large SI is split into segments the UE reassembles at the L1→RRC
  handoff. `NL1_CTRL_Nrrc_Reconstruct_Raw_Data` copies `nseg × segLen` (taken from the low-level delivery
  **descriptor**) into a 380-byte stack buffer with no bound → overflow (**F6/F9**; present on Huawei,
  **fixed** on the newer Samsung build). The `nseg`/`segLen` values are written by the **Coresonic DSP**,
  so full external reach hinges on whether the DSP forwards oversized counts — the canonical illustration
  of "PHY isn't byte-parsed by the attacker, but its lengths/counts feed the higher layers." See
  `../../triggering/F6_trigger_NR-SI.md` and `../catalog/catalog_5G.md`.
