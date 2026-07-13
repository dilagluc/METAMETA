# Catalog — cross-cutting subsystems (IMS/VoLTE, SMS, Security, Data/QoS)

Target DB: Huawei `MD1IMG_22.img` → `000_md1rom`, symbolized, served on port 8799.
All commands below were run as:

```
source /workspace/.venv-ida/bin/activate
python /workspace/idaq search "<python-regex>" <limit>
python /workspace/idaq decompile "<name|0xaddr>"
```

This section covers the subsystems that sit **above / across** the per-RAT (2G/3G/4G/5G) radio
stacks: the IMS/VoLTE media plane, the SMS abstraction layer, NAS/AS security, and the data/QoS
plumbing. These are the parts of the modem a remote peer can reach *after* a call/registration is up
or via a delivered message, so they matter a lot for attack surface.

Where the layered stacks (RRC/NAS ASN.1 decoders, etc.) are documented in the per-RAT sections, this
section anchors on the **subsystem prefixes**: `ltecsr_` (VoLTE CS-over-RTP), `imc_` (IMS Call
Manager), `VOLTE_FM_` (VoLTE frame manager), `sp_ps_codec_evs_` / EVS (codec depacketizers),
`smsal_` (SMS abstraction), `CEmmSec::` (LTE/5G NAS security), `sdap_`/`ipf_` (data plane).

> **Where the known findings live (read the vuln reports alongside this catalog):**
> - **F2 / F7** — VoLTE **RTP / EVS** media plane → `ltecsr_*` and the EVS depacketizers
>   (`VOLTE_FM_EVS_*`, `sp_ps_codec_evs_*`, `convert_EVS*`).
> - **F1 / F8** — **SMS** → `smsal_*` (TPDU/UDH/Cell-Broadcast decode paths).
> - **F13** — **NAS integrity** → `CEmmSec::chkIntegrity()`.

---

## 1. IMS / VoLTE / VoWiFi

**Beginner intro.** VoLTE is "a phone call carried as IP packets." Signalling (who is calling, which
codec) is **SIP/SDP** text; the actual voice is **RTP** packets, with **RTCP** for quality reports.
On this MediaTek-based modem the **SIP/SDP text parser lives largely AP-side** (the application
processor's IMS stack builds and parses the SIP messages). The **modem handles the media plane**: it
receives/sends RTP, depacketizes the **EVS/AMR** codec payloads, runs the jitter buffer, and reports
stats. So the interesting modem-side attack surface here is **RTP payload / codec depacketization**,
not SIP header parsing.

The three modem-side building blocks:
- `imc_*` — **IMS Call Manager**: the control glue on the modem that talks to the AP-side SIP stack
  and drives call/registration state. SIP/SDP appear here only as *pass-through* fields
  (`atp_imc_sip_header_*` just shuttles a header blob), confirming the text parse is elsewhere.
- `ltecsr_*` — **LTE CS-over-RTP** ("CSR"): the actual RTP/RTCP media engine — sends/receives RTP,
  demuxes RTP vs RTCP, runs the jitter buffer (`jbm`), handles DTMF and Real-Time Text (TTY/RTT).
- `VOLTE_FM_*` + EVS/AMR codec functions — the **frame manager** and **depacketizers** that carve a
  received RTP payload into speech frames per RFC 4867 (AMR) / RFC being the EVS RTP format.

### Regexes used and counts

| regex | limit | count | note |
|---|---|---|---|
| `ltecsr_` | 5000 | **319** | VoLTE CS-over-RTP media engine (F2/F7 area) |
| `imc_` | 5000 | **879** | IMS Call Manager glue (broad; many `imcb_`/`imcsms_` helpers) |
| `atp_imc` | 5000 | **91** | AT/AP↔IMS bridge (SIP header pass-through lives here) |
| `rtp` | 5000 | **439** | broad substring — real RTP media is `ltecsr_*rtp*` + `rtp_avprofile_*`; many hits are unrelated (`AsnEncode_CQI_ReportPeriodic…`) |
| `rtcp` | 5000 | **124** | RTCP quality-report path (`ltecsr_rtcp_*`, `sdp_get_rtcp_*`) |
| `evs` | 5000 | **295** | EVS codec (depacketize / speech-frame handling) |
| `amr` | 5000 | **155** | AMR/AMR-WB codec (broad substring) |
| `VOLTE_FM` | 5000 | **32** | VoLTE frame manager (RTP payload → speech frames) |
| `fm_` | 5000 | **315** | broad substring; frame-manager subset is `VOLTE_FM_*` |
| `sip` | 5000 | **701** | broad substring; modem-side SIP is pass-through only (`atp_imc_sip_*`, `imc_cc_*sip*`) |
| `sdp` | 5000 | **247** | SDP helpers (`cc_call_sdp_*`, `sdp_get_rtcp_fb_*`) — build/format SDP media lines, not a full text parser |

**Naming convention:** `ltecsr_` = LTE **C**S-over-RTP media; `_dl_cb` = downlink (received)
callback; `_ul_` = uplink; `jbm` = **j**itter **b**uffer **m**anager; `em_send_*` = engineering-mode
stats reporting; `VOLTE_FM_EVS_CF_*` = EVS **C**ompact **F**ormat, `_HF_` = **H**eader **F**ull format.

### Table — VoLTE media plane (`ltecsr_` / EVS / frame manager)

| function | addr | subsystem | protocol/sublayer | what it does |
|---|---|---|---|---|
| `ltecsr_voice_rtp_dl_cb` | 0x90cf2340 | ltecsr | RTP (voice, DL) | Downlink RTP receive callback — entry for an inbound voice RTP packet; large function that unpacks header/payload and feeds the jitter buffer (**F2/F7 surface**) |
| `ltecsr_text_rtp_dl_cb` | — | ltecsr | RTP (RTT, DL) | Same for Real-Time Text media |
| `ltecsr_voice_rtcp_dl_cb` | — | ltecsr | RTCP (DL) | Downlink RTCP receiver-report handling |
| `ltecsr_rtcp_mux_check_pt` | — | ltecsr | RTP/RTCP demux | Decides RTP-vs-RTCP on a muxed port by payload type |
| `ltecsr_rtp_send` / `ltecsr_rtcp_send` | — | ltecsr | RTP/RTCP (UL) | Build & send uplink RTP / RTCP |
| `ltecsr_jbm_init` / `ltecsr_media_update_jbm_call_mode` | — | ltecsr | jitter buffer | Init / reconfigure the de-jitter buffer |
| `ltecsr_recv_codec_check` | — | ltecsr | codec negotiation | Validate the codec of a received packet against the running codec |
| `ltecsr_tty_dl_parse_pkt` | 0x90cf9940 | ltecsr | RTT (T.140) | Parse a Real-Time-Text DL packet: `count_blocks()` then `handle_blocks()` if block count nonzero |
| `ltecsr_tty_dl_count_blocks` / `ltecsr_tty_dl_handle_blocks` | — | ltecsr | RTT | Count / decode the redundancy blocks inside an RTT payload |
| `ltecsr_dtmf_uplink_process` / `ltecsr_dtmf_ascii_to_eventid` | — | ltecsr | DTMF (RFC 4733) | Map DTMF tone → RTP event id and send |
| `ltecsr_update_rtp_filter` | — | ltecsr | RTP filtering | Update the SSRC/port receive filter |
| `VOLTE_FM_GetFrames` / `VOLTE_FM_CountFrames` | — | frame mgr | AMR depacketize | Carve speech frames out of an AMR RTP payload (ToC/CMR walk) |
| `VOLTE_FM_EVS_CF_CountFrames` | 0x90cec370 | frame mgr | EVS depacketize | Count EVS **Compact-Format** speech frames; maps payload byte-length → frame type via a size table (**F7 surface** — length-driven parse) |
| `VOLTE_FM_EVS_HF_CountFrames` / `VOLTE_FM_EVS_Config` | — | frame mgr | EVS depacketize | EVS Header-Full framing / config |
| `convert_EVSHeaderFullCMR_to_SP4GCodecEnum` | — | EVS | EVS RTP header | Parse the CMR (codec-mode-request) byte from an EVS RTP header |
| `convert_EVSCompactFormatCMR_to_SP4GCodecEnum` | — | EVS | EVS RTP header | Same for compact-format CMR |
| `sp_ps_codec_evs_DL_EVS_PutSpeechFrame` | — | EVS | codec DL | Hand a depacketized EVS frame to the speech decoder |
| `sp_ps_codec_evs_Get_EVS_AWB_RAB_subflow` | — | EVS | codec DL | Split AMR-WB-IO / channel-aware subflows |
| `rtp_avprofile_pt_amr_set` / `rtp_avprofile_pt_amrwb_set` | — | RTP profile | AV profile | Register AMR / AMR-WB payload types |

### Table — IMS Call Manager (`imc_`, control/glue — SIP/SDP pass-through)

| function | addr | subsystem | protocol/sublayer | what it does |
|---|---|---|---|---|
| `atp_imc_sip_header_req_construct_func` | — | imc | SIP (pass-through) | Package a SIP header blob for the AP-side IMS stack (no parse) |
| `atp_imc_sip_cpi_ind_encode_func` | — | imc | SIP (pass-through) | Encode SIP call-progress indication toward AP |
| `imc_cc_sip_call_progress_ind_handler` | — | imc | call control | React to SIP call-progress from AP, drive modem call state |
| `atp_process_imc_ims_reg_status_ind` | — | imc | IMS registration | Relay IMS registration status to AT/AP |
| `imc_cc_send_mngr_reg_emergency_reg_req` | — | imc | emergency reg | Kick off emergency IMS registration |
| `cc_call_sdp_set_rtcp_bandwidth` / `sdp_get_rtcp_fb_param_string` | — | imc/sdp | SDP media lines | Format/read RTCP-FB & bandwidth SDP attributes (formatting, not a text parser) |
| `imc_cc_send_ltecsr_media_new` / `_media_update` / `_media_del` | — | imc→ltecsr | media control | Tell the `ltecsr` media engine to open/update/close a media stream |
| `enpdcp_ltecsr_voice_bearer_ind` | — | pdcp→ltecsr | bearer bind | Bind the voice RTP flow to its dedicated bearer |

---

## 2. SMS — `smsal_` abstraction layer

**Beginner intro.** An SMS is a compact binary blob (a **TPDU**, per 3GPP TS 23.040). The modem must
decode fields like the originating address (semi-octet BCD), the **DCS** (data-coding scheme:
GSM-7bit / 8-bit / UCS-2), the timestamp, and the user data — which may carry a **UDH** (User-Data
Header) for concatenation (multi-part SMS), ports, etc. Separately, **Cell Broadcast (CB)** messages
(TS 23.041) are area-wide pages the network pushes. Underneath, SMS rides two thin CS transport
sublayers: **CP** (Connection-oriented Protocol) and **RP** (Relay Protocol). All of this decoding is
exactly the kind of length-driven bit-unpacking that hosts memory bugs.

`smsal_` = **SMS A**bstraction **L**ayer: the modem's central SMS store/decode module used by all
RATs and by the IMS SMS-over-IP path.

### Regexes used and counts

| regex | limit | count | note |
|---|---|---|---|
| `smsal_` | 5000 | **592** | full SMS abstraction layer (F1/F8 area) |
| `tpdu` | 5000 | **21** | TPDU-named helpers (most decode is inside `smsal_*decode*`, not `tpdu`-named) |
| `smrl\|smcm\|smrp\|smcp\|_cp_\|_rp_` | 5000 | (sampled) | CS SMS CP/RP transport: `sms_process_cp_header`, `imcsms_process_rp_header`, etc. |

**Naming convention:** `smsal_` core; `l4csmsal_*` = L4C↔SMSAL message handlers (the `_cnf_hdlr` /
`_ind_hdlr` suffixes are confirm/indication handlers); `smsal_cb_*` = Cell Broadcast;
`smsal_ims_*` / `l4csmsal_ims_*` = SMS-over-IMS; `sms_*_cp_*` = CP transport, `imcsms_*_rp_*` /
`sms_rp_*` = RP transport.

### Table — SMS decode / Cell Broadcast / CP-RP

| function | addr | subsystem | protocol/sublayer | what it does |
|---|---|---|---|---|
| `smsal_decode_cb_page` | 0x90bfb952 | smsal | CB / GSM-7bit unpack | Unpacks a Cell-Broadcast page's packed 7-bit septets into 8-bit chars via a `v6 % 7` bit-shift ladder; writes into caller buffer indexed by `*a3` (byte cursor) — classic packed-GSM unpack, **length/index-driven (F1/F8 surface)** |
| `smsal_decode_cbsdcs` | — | smsal | CB / DCS | Decode the CB data-coding scheme byte |
| `smsal_cb_conver_CBDCS_to_ISO639` / `_ISO639_to_CBDCS` | — | smsal | CB / language | Map CB DCS ↔ ISO-639 language tag |
| `smsal_cb_fill_page_header` (`ratcm`/`eval`) | — | smsal | CB / TS 23.041 | Fill the CB page header from received data |
| `smsal_cb_update_cntx` / `smsal_cb_init_context` | — | smsal | CB state | Maintain CB channel/page reassembly context |
| `l4csmsal_new_msg_pdu_ind_hdlr` | — | smsal | TPDU delivery | Handle an inbound MT SMS **PDU** indication (raw TPDU up from the RAT) |
| `l4csmsal_new_msg_text_ind_hdlr` | — | smsal | TPDU delivery | Same, text-mode variant |
| `l4csmsal_cb_msg_pdu_ind_hdlr` / `_cb_msg_text_ind_hdlr` | — | smsal | CB delivery | Deliver decoded CB message to L4C |
| `smsal_get_rp_sms_info` / `smsal_rp_addr_cmp` | — | smsal | RP transport | Extract / compare RP-layer SMS addressing |
| `sms_rp_addr2_l4_addr` / `l4_addr2_sms_rp_addr` | — | sms cp/rp | RP address | Convert between RP address and internal L4 address (semi-octet) |
| `sms_process_cp_header` | — | sms cp/rp | CP transport | Parse a CP-DATA/CP-ACK/CP-ERROR header (CS SMS) |
| `sms_send_cp_data` / `sms_send_cp_ack` / `sms_send_cp_error` | — | sms cp/rp | CP transport | Build & send CP messages |
| `sms_mt_first_cp_data` / `sms_cp_mt_handler` | — | sms cp/rp | CP MT | Drive the MT (received) CP transaction |
| `imcsms_process_rp_header` | — | ims sms | RP over IMS | Parse the RP header of an SMS carried over IMS (SMS-over-IP) |
| `imcsms_form_rp_data` / `imcsms_form_rp_ack` / `imcsms_form_rp_error` | — | ims sms | RP over IMS | Construct RP-DATA / RP-ACK / RP-ERROR for IMS |
| `l4csmsal_ims_new_msg_pdu_ind_hdlr` | — | smsal | SMS-over-IMS | Deliver an inbound IMS SMS PDU |

---

## 3. Security — NAS/AS integrity & ciphering

**Beginner intro.** After you attach to a network, the phone and network run **authentication** (AKA:
Authentication and Key Agreement, using the SIM's Milenage function) to derive keys, then protect NAS
signalling messages with:
- **Integrity (EIA / "128-EIA*x*")** — a MAC (message authentication code) computed over each NAS
  message; the receiver recomputes it and compares. If it mismatches, the message must be dropped.
  `EIA0` = the *null* integrity algorithm (only allowed for emergency/unauth calls).
- **Ciphering (EEA / "128-EEA*x*")** — encryption of the NAS message body.

The algorithms are SNOW-3G, AES (128-EEA2/EIA2), and ZUC (128-*3). On this modem the NAS security
state machine is the C++ class **`CEmmSec`** (EPS/LTE + mapped 5G context), and the raw crypto is done
by AES/`CHE_AES_*` primitives plus an L2 helper (`l2_cp_int_nas`). **F13 is the integrity-check
function `CEmmSec::chkIntegrity()`** — the exact place where a MAC is recomputed and compared, so a
logic slip there (e.g. accepting a bad/absent MAC) breaks the whole security guarantee.

> **Regex caveat:** searching `eia` / `eea` as bare substrings is *misleading* here — those regexes
> mostly match unrelated AT-command handlers like `atp_d2at_eiaapn_req` / `atp_d2at_eiareg_handler`
> ("eia" = an enterprise-IMS AT feature), **not** the EIA integrity algorithm. The real
> integrity/ciphering surface is under `CEmmSec::` and the `l2_cp_*` / `CHE_AES_*` primitives.

### Regexes used and counts

| regex | limit | count | note |
|---|---|---|---|
| `CEmmSec` | 5000 | **171** | LTE/5G NAS security state machine (F13 area) |
| `chkIntegrity` | 5000 | **1** | exactly `CEmmSec::chkIntegrity()` (F13) |
| `milenage` | 5000 | **6** | AKA Milenage f1–f5 primitives |
| `aka` | 5000 | **116** | broad; AKA auth context (`CEmmSecCtxtAka`, `authFailProc`, …) |
| `kdf` | 5000 | **37** | key-derivation (`pkey_ec_kdf_derive`, `PKCS5_PBKDF2_*`) — mostly TLS/crypto-lib, not NAS KDF |
| `eia` | 5000 | **15** | ⚠ mostly `atp_d2at_eia*` AT handlers, NOT integrity |
| `eea` | 5000 | **16** | ⚠ same caveat |
| `CHE_AES_\|AES_` | 5000 | (sampled) | AES engine: `CHE_AES_f8_encrypt`, `CHE_AES_ctr_encrypt`, `CAL_aes_128_*`, `AES_encrypt` |

**Naming convention:** `CEmmSec::` = EMM (LTE NAS) security; `CEmmSecCtxtAka` = the AKA
authentication context (RAND/RES/keys); `CEmmSecCtxtSmc` = the Security-Mode-Command context (chosen
alg + KNASint/KNASenc keys); `Knasint`/`Knasenc` = derived NAS integrity/ciphering keys;
`cal…Kasme`/`makeKnasKey`/`make5gKnasKey` = the NAS key-derivation ladder.

### Table — NAS security (`CEmmSec::` and crypto primitives)

| function | addr | subsystem | protocol/sublayer | what it does |
|---|---|---|---|---|
| `CEmmSec::chkIntegrity()` | 0x904dfbdc | CEmmSec | NAS integrity (EIA) | **F13.** Selects integrity alg from the SMC/AKA context, copies the NAS body into a scratch buffer, calls `l2_cp_int_nas` to compute the MAC, then `compareCharArray(…,4)` against the received 4-byte MAC; returns 0 (ok) / 1 (fail) and sets fail flags |
| `CEmmSec::deciphMsg()` | — | CEmmSec | NAS ciphering (EEA) | Decrypt a ciphered NAS message body |
| `CEmmSec::chkNasMsgSecurity()` | — | CEmmSec | NAS security header | Top-level check of a received secured NAS message (dispatches integrity/decipher) |
| `CEmmSec::ifEIA0Used()` / `applyEia0SuccessCommonHandler` | — | CEmmSec | EIA0 (null integrity) | Detect/handle the null-integrity (emergency) case |
| `CEmmSec::mapIntegrityAlgToEnum()` / `chkSelectedAlg()` | — | CEmmSec | alg negotiation | Map/validate the network-selected integrity algorithm |
| `CEmmSecCtxtSmc::calAndSetKnasKey()` / `calAndSet5gKnasKey()` | — | CEmmSec | NAS KDF | Derive KNASint/KNASenc from KASME (4G) / KAMF (5G) |
| `CEmmSec::calNativeKasme()` / `calMappedKasme()` | — | CEmmSec | key derivation | Derive native / inter-RAT-mapped KASME |
| `CEmmSecCtxtSmc::setIntegrityAlg()` / `setCipheringAlg()` | — | CEmmSec | SMC | Store the chosen EIA/EEA algorithm from Security Mode Command |
| `CEmmSec::getNasCount()` / `CEmmSecCtxtSmc::calDlNasCount()` | — | CEmmSec | replay protection | Manage the NAS COUNT (sequence) used in the MAC input |
| `CEmmSec::authFailProc()` / `compareRand()` | — | CEmmSec | AKA | Authentication-failure handling / RAND comparison |
| `l2_cp_int_nas` | — | L2 helper | integrity engine | The actual MAC computation invoked by `chkIntegrity` |
| `CHE_AES_f8_encrypt` / `CHE_AES_ctr_encrypt` | — | AES engine | EEA2 / f8 | AES in f8 / counter mode (ciphering primitive) |
| `CAL_aes_128_ctr` / `CAL_aes_128_cbc` / `CAL_aes_128_gcm` | — | crypto lib | AES modes | Generic AES-128 mode wrappers |

---

## 4. Data / QoS plane (PDCP / SDAP / IP filtering)

**Beginner intro.** Once bearers are up, user data flows through **PDCP** (header compression +
ciphering, see the per-RAT L2 sections) and, in 5G, **SDAP** (Service Data Adaptation Protocol) which
tags each packet with a **QoS flow identifier (QFI)** and maps QoS flows to radio bearers. A hardware
**IP filter (IPF)** classifies downlink IP packets to the right bearer. This plane is mostly
config/steering (much of it offloaded to hardware/coprocessor), so it is a smaller software surface
than the parsers above — noted here for completeness.

### Regexes used and counts

| regex | limit | count | note |
|---|---|---|---|
| `sdap` | 5000 | **27** | 5G SDAP: QFI↔DRB mapping, end-marker handling |
| `qos` | 5000 | **343** | broad; QoS-flow config, mostly `custom_*`/NVRAM tunables |
| `ipf_\|dl_ipf_\|ipsec` | 5000 | (sampled) | DL IP filter + IPsec (VoWiFi) |

### Table — data-plane steering

| function | addr | subsystem | protocol/sublayer | what it does |
|---|---|---|---|---|
| `sdap_ulproc_data_req_handler` | — | SDAP | 5G SDAP UL | Uplink SDAP data-request processing (adds SDAP header/QFI) |
| `sdap_clear_qos_flow_to_drb` | — | SDAP | QoS mapping | Clear a QoS-flow→DRB mapping entry |
| `sdap_rdi_bitmap_process` / `sdap_end_marker_bitmap_process` | — | SDAP | flow control | Handle RDI / end-marker bitmaps during flow remap |
| `_exec_drb_sdap_cfg` | — | SDAP | config | Apply an SDAP config for a data radio bearer |
| `AsnEncode_NR_SDAP_Parameters` | — | RRC/SDAP | ASN.1 | Encode the SDAP config IE (belongs to NR RRC layer) |
| `dl_ipf_update_filter` / `dl_ipf_set_hw_sdap_cfg` | — | IP filter | DL classify | Program the HW downlink IP filter / SDAP mapping |
| `ipf_pn_bind_rb2pdn` / `ipf_pn_match_bind_pdn2ncid` | — | IP filter | bearer bind | Bind radio bearer ↔ PDN connection for filtering |
| `atp_ipsec_spi_alloc_req` / `atp_ipsec_entry_func` | — | IPsec | VoWiFi | IPsec SA (SPI) management for VoWiFi (ePDG tunnel) |
| `enpdcp_ulproc_send_sdap_end_marker` | — | PDCP↔SDAP | UL | Emit an SDAP end-marker during bearer change |

---

## Appendix — sampled decompiles (evidence for "what it does")

**`CEmmSec::chkIntegrity()` @ 0x904dfbdc (F13):** selects the integrity algorithm from either the SMC
context (`a1+308`) or the AKA/native context (`a1+231`) depending on `a4`, copies the received NAS
body (`a3+5`, length `a2-5`) into a cacheable scratch buffer, computes the MAC via `l2_cp_int_nas`,
then `CEmmSec::compareCharArray(&computed, a3+1, 4)` against the 4-byte received MAC. Returns `0` on
match, `1` on mismatch (and raises `*a6`/`*a7` fail flags when not the `a4==1` path). This is the
canonical NAS integrity gate.

**`smsal_decode_cb_page` @ 0x90bfb952 (F1/F8 area):** GSM 7-bit septet→octet unpacking loop driven by
`v6 % 7`; each iteration reads `*(a2 + a4 + v6)` and writes the reconstructed byte at
`*(result + *a3)` while incrementing the `*a3` output cursor. Bounds are governed by `a4`/`a5`
(start/end) with `unsigned __int8` truncation on the counters — a length/index-driven unpack, the
shape that hosts SMS memory bugs.

**`VOLTE_FM_EVS_CF_CountFrames` @ 0x90cec370 (F7 area):** takes a payload bit-length (`8 * a2`) and
walks a size ladder (`0x140`, `0x1E8`, `0x500`, …) to classify the EVS compact-format frame type,
writing frame-type/count fields into the output struct `a3`. Length-table-driven parsing of
attacker-influenced RTP payload size.

**`ltecsr_tty_dl_parse_pkt` @ 0x90cf9940:** thin dispatcher — `ltecsr_tty_dl_count_blocks()` then, if
`*(a3+24)` (block count) is nonzero, `ltecsr_tty_dl_handle_blocks(a1, a3)`; the real Real-Time-Text
(T.140 redundancy) decode is in `handle_blocks`.
