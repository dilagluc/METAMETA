# Catalog brief — per-RAT / per-layer function inventory (Huawei symbolized DB)

Target: Huawei `MD1IMG_22.img` → `000_md1rom`, symbolized. IDA query client:
    source /workspace/.venv-ida/bin/activate
    python /workspace/idaq search "<python-regex>" <limit>      # find functions by name
    python /workspace/idaq decompile "<name|0xaddr>"            # to sample what a function does
    python /workspace/idaq xrefs "<name|0xaddr>"                # callers/callees

Your job: for your assigned RAT, produce a Markdown section that (a) documents the EXACT `idaq search`
commands (the regexes) you used to identify functions for each protocol layer, and (b) gives per-layer
TABLES of representative functions: | function | addr | layer | protocol/sublayer | what it does |.

- Map every function group to the OSI-style baseband layering: **L1 (PHY)**, **L2** (MAC / RLC / PDCP /
  for 2G: MAC/RLC + LLC/SNDCP), **L3** (RRC/RR + NAS: MM/GMM/CC/SM/EMM/ESM/5GMM/5GSM), plus
  cross-cutting (SMS, IMS, security).
- Use the function-name prefixes as the anchor (this DB is symbolized). Sample a few with `decompile`
  to write an accurate "what it does" — do NOT invent behavior; if unsure, say "decoder for X IE" based
  on the name.
- Don't dump all thousands — give the SCHEMA (the regex per layer + the count) and then a curated,
  representative TABLE per layer (~15-40 rows each, chosen to cover the sublayers), clearly noting the
  total count returned by each regex so the reader knows the full size.
- Note the naming conventions you discover (e.g. `AsnDecode_RRC_*` = UMTS RRC ASN.1 decoders,
  `FDD_rr_*` = GSM RR, `errc_*` = LTE RRC, `nrrc/Nrrc*` = NR RRC, `vgmm_/vgsm_*` = 5G NAS,
  `emm_/esm_*` = LTE NAS, `smsal_*` = SMS abstraction layer, `ltecsr_*` = VoLTE/IMS CS-over-RTP).
- Keep it beginner-friendly: 1-2 sentences introducing each layer for your RAT before its table.

Write your section to your assigned file. Be accurate and cite counts.
