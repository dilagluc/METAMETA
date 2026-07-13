# 4G — LTE / E-UTRAN function catalog (Huawei symbolized baseband)

Target image: `MD1IMG_22.img` → `000_md1rom`, symbolized. All functions below were located with
the IDA query client against the live DB (port 8799):

```
source /workspace/.venv-ida/bin/activate
python /workspace/idaq search "<python-regex>" <limit>   # find functions by name
python /workspace/idaq decompile "<name|0xaddr>"         # sample what a function does
python /workspace/idaq xrefs   "<name|0xaddr>"           # callers / callees
```

## How LTE is layered (beginner orientation)

An LTE modem is a stack. A byte arriving over the air travels **up** the stack; a byte you send
travels **down**. Each layer has one job:

- **L1 / PHY** — turns bits into radio symbols and back (modulation, coding, HARQ, cell search,
  measurements). In this firmware the LTE physical layer is the `el1_*` (E-UTRAN Layer-1) family.
- **L2** — three sublayers stacked between PHY and RRC:
  - **MAC** (`emac_*`) — schedules transmissions, runs the random-access (RACH) procedure, builds
    transport blocks, HARQ, buffer-status/power-headroom reporting, DRX sleep control.
  - **RLC** (`erlc*`) — reliable delivery: segments/reassembles packets, and in Acknowledged Mode
    does ARQ retransmission, in-order reordering and duplicate detection.
  - **PDCP** (`epdcp_*`) — ciphering/deciphering and integrity protection of user + signalling
    data, header compression (ROHC), and in-order delivery / re-establishment handling.
- **L3 RRC** (`errc_*`) — the control brain of the radio: reads broadcast system information (SIBs),
  handles paging, sets up/reconfigures/releases radio bearers, runs cell (re)selection, measurement
  and handover, and the public-warning (ETWS/CMAS) receiver. This is the largest single family.
- **L3 NAS** — end-to-end signalling with the core network, transparent to the eNB:
  - **EMM** (`CEmm*` / `emm_*`) — EPS Mobility Management: Attach, Tracking-Area-Update, Service
    Request, identity/authentication, NAS security mode, paging response, CSFB.
  - **ESM** (`esm_*`) — EPS Session Management: PDN connectivity, EPS bearers, QoS, TFT, PCO.
  - **mcd_unpack** — the shared NAS/RRC message-codec engine that decodes IE-encoded OTA messages.

### Naming conventions discovered

| Prefix | Meaning |
|--------|---------|
| `el1_*` | E-UTRAN Layer-1 (LTE PHY): `el1_csr`=cell search, `el1_irt`=inter-RAT, `el1_meas`=measurement, `el1_chmgm`/`el1_ch_sch`=channel mgmt & scheduling |
| `emac_*` | LTE MAC |
| `erlcdl_*` / `erlcul_*` | LTE RLC downlink / uplink |
| `epdcp_*` | LTE PDCP |
| `errc_*` | LTE RRC. Sub-families: `errc_cel_*`=cell/RRC-entity control, `errc_mob_*`=mobility, `errc_lsys_*`=system/SI dispatch, `errc_asn1_*`=ASN.1 codec, `errc_cel_pwsrcv_*`=public warning receiver |
| `AsnDecode_SystemInformationBlockType*` | Per-SIB ASN.1 UPER decoders |
| `CEmm*` (C++ classes) / `emm_*` | LTE NAS EMM |
| `esm_*` | LTE NAS ESM |
| `mcd_unpack*` | Message-codec-descriptor unpacker (NAS/CSN.1 IE decoder engine) |

> Note on `ephy` / `l1.*lte` regexes from the brief: on this DB `ephy` matches only 8 UMTS
> `FDD_/TDD_RRC_ReleasePHY*` functions (not LTE), and `l1.*lte` (436 hits) is dominated by generic
> trace-**filter** setters (`Set_*_Filter`, `dhl_filter_*`). The accurate LTE-PHY anchor is `^el1`.
> Likewise `lte.*phy` → 0 hits and `^mac.*lte` → 0 hits. The tables below use the anchors that
> actually isolate each layer.

---

## L1 / PHY — the LTE physical layer (`el1_*`)

The PHY converts between the antenna and Layer-2. In idle mode it searches for cells and measures
signal quality; in connected mode it decodes control channels and moves scheduled data. This
firmware splits it into functional blocks by infix.

**Regexes & counts:**

| Regex | Count | What it isolates |
|-------|------:|------------------|
| `^el1` | 4000+ (limit hit) | Whole LTE PHY family (very large) |
| `^el1_` | 1799 | Core `el1_*` PHY functions |
| `^el1_meas` | 316 | PHY measurement / L1 filtering |
| `^el1_irt` | 142 | Inter-RAT (LTE↔other) L1 handling |
| `^el1_csr` | 77 | Cell search / scan-list |
| `ephy` | 8 | (UMTS RRC release-PHY, **not** LTE) |
| `l1.*lte` | 436 | mostly trace-filter setters (noise) |

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `el1_csr_scan_list_blacklist_filter` | 0x9030ce0c | L1 | PHY / cell search | Filters blacklisted cells from the scan candidate list |
| `el1_csr_scan_list_bw_filter` | 0x9030d0bc | L1 | PHY / cell search | Filters scan list by supported channel bandwidth |
| `el1_csr_scan_list_overlap_filter` | 0x9030cf84 | L1 | PHY / cell search | Removes overlapping frequencies from scan list |
| `el1_meas_phy_l3_filter` | 0x9033d156 | L1 | PHY / measurement | Applies RRC L3 filter coefficient to raw L1 measurements |
| `el1_meas_phy_serving_l1_filtering_check` | 0x9033e2ca | L1 | PHY / measurement | L1-filtering gate for the serving cell |
| `el1_meas_phy_neighbor_l1_filtering_check` | 0x9033e5ba | L1 | PHY / measurement | L1-filtering gate for neighbour cells |
| `el1_meas_phy_report_l1_filtering_results_to_el1d` | 0x9034182e | L1 | PHY / measurement | Reports filtered results up to the L1 driver task |
| `el1_meas_phy_linear_combined_ar_filter` | 0x9033d0fc | L1 | PHY / measurement | Linear-combines antenna results before filtering |
| `el1_irt_lte_state_map` | 0x9031b99a | L1 | PHY / inter-RAT | Maps LTE L1 state for inter-RAT transitions |
| `el1_irt_actv_set_lteafc_value` | 0x9031fc10 | L1 | PHY / inter-RAT | Sets LTE AFC (auto-freq-control) value on activation |
| `el1_ch_abs_to_lte_time` | 0x902ef366 | L1 | PHY / timing | Converts absolute time ↔ LTE frame/subframe time |
| `el1_ch_lte_to_after_abs_time` | 0x902ef328 | L1 | PHY / timing | LTE-time → absolute-time conversion helper |
| `el1_chmgm_send_el1_nl1_unlock_lte_rfdb_ntf` | 0x902f5aaa | L1 | PHY / channel mgmt | Notifies unlock of LTE RF database between L1 entities |
| `el1_chmgm_emac_drx_ctrl_req` | 0x902f268e | L1 | PHY↔MAC | Handles a DRX (sleep) control request from MAC |
| `el1_chmgm_emac_host_data_req` | 0x902f2b00 | L1 | PHY↔MAC | Handles host-data request routed from MAC to PHY |
| `el1_ch_sch_send_emac_phy_info` | 0x903033e2 | L1 | PHY↔MAC | Sends PHY scheduling info to MAC |
| `el1_ch_sch_send_emac_sch_update` | 0x90300dce | L1 | PHY↔MAC | Sends scheduler update to MAC |

*(Family is 1799 `el1_*` core + thousands of `el1c*` driver/glue; table is a representative slice
across cell-search, measurement, inter-RAT, timing and the MAC interface.)*

---

## L2 — MAC / RLC / PDCP

### MAC (`emac_*`) — scheduling, RACH, HARQ, DRX

MAC decides *what gets sent when*. It runs the random-access procedure to get on a cell, maps
logical channels onto transport blocks, drives HARQ (fast retransmission), reports buffer status
(BSR) and power headroom (PHR), and controls DRX sleep to save battery.

**Regexes & counts:** `emac` → **827**; `^emac` → **586**; `^mac.*lte` → 0.

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `emac_ert_sec_init` | 0x9043ccb4 | L2 | MAC | Init of the MAC "secondary" (SEC) real-time entity |
| `emac_ert_sec_hbsr_proc` | 0x9043ce80 | L2 | MAC / BSR | Processes high-priority Buffer Status Reporting |
| `emac_ert_sec_hbsr_hdata_report` | 0x9043ccc2 | L2 | MAC / BSR | Reports host-data buffer occupancy for BSR |
| `emac_ert_sec_dl_hdata_ind_ntf` | 0x9043cd0e | L2 | MAC | Notifies arrival of downlink host data |
| `emac_txlisr_active` | 0x9043d316 | L2 | MAC / TX | Activates the transmit low-level ISR path |
| `emac_sec_txlisr_drx_inc_gap_handler` | 0x9043d36e | L2 | MAC / DRX | Handles DRX inactive-gap in the TX ISR |
| `emac_sec_txlisr_volte_pow_enh_req` | 0x9043d4bc | L2 | MAC / power | VoLTE power-enhancement request in TX path |
| `emac_ert_sec_volte_timing_info_proc` | 0x9043cfda | L2 | MAC | Processes VoLTE semi-persistent timing info |
| `emac_sec_rcv_ilm` | 0x9043cd1c | L2 | MAC | Receives inter-layer message into MAC |
| `el1_chmgm_send_emac_ra_gap_stop_cnf` | 0x902f15a0 | L1↔L2 | MAC / RACH | Confirms stop of RA measurement gap to MAC |
| `EVl3EmAccessProcedureEventConvert` | 0x90149c1c | L2 | MAC / RACH | Converts access-procedure events (random access) |
| `dmf_info_collect_emac_rach_finish_handler` | 0x902c3328 | L2 | MAC / RACH | Collects diagnostics when RACH completes |
| `_emac_ert_sec_dyn_feat_raise_bsr_feat_exp` | 0x9043d63e | L2 | MAC / BSR | Dynamic-feature hook to raise a BSR |
| `_emac_ert_sec_dyn_feat_force_sr_feat_exp` | 0x9043d652 | L2 | MAC / SR | Dynamic-feature hook to force a Scheduling Request |

*(Note: several `emac`-matching hits like `RunAlmpStateMachine` belong to the ALMP/access state
machines, and `sp_ps_*_EMAC` are C2K interworking — the `^emac_*` prefix is the clean LTE-MAC set.)*

### RLC (`erlcdl_*` / `erlcul_*`) — reliable delivery, ARQ, reordering

RLC sits above MAC. In **AM** (Acknowledged Mode) it retransmits lost PDUs, reorders out-of-order
PDUs and removes duplicates; in **UM** it segments/reassembles without ARQ. Downlink and uplink are
split into two entities here.

**Regexes & counts:** `erlc` → **255**; `^erlcdl` → **86**; `^erlcul` → **85**. (The `erlc`
count also includes 6 UMTS `AsnDecode/Encode_RRC_*RLC_SizeInfo*` ASN.1 helpers — not LTE RLC.)

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `erlcdl_init_reassemble` | 0x90440c68 | L2 | RLC-DL | Initializes downlink reassembly state |
| `erlcdl_um_reorder_expiry_reasm_start` | 0x90440ad6 | L2 | RLC-DL / UM | Starts reassembly when UM reorder timer expires |
| `erlcdl_am_reord_ticks_check` | 0x90440b92 | L2 | RLC-DL / AM | Checks AM reordering-timer ticks |
| `erlcdl_status_feedback_handler` | 0x904410b4 | L2 | RLC-DL / AM | Generates STATUS PDU feedback (ACK/NACK) |
| `erlcdl_rb_nack_req_hndlr` | 0x904416d4 | L2 | RLC-DL / AM | Handles a NACK request for a radio bearer |
| `erlcdl_discard_invalid_pdu` | 0x90442076 | L2 | RLC-DL | Discards invalid received PDUs |
| `erlcdl_copro_reasm_srb` | 0x90444782 | L2 | RLC-DL | Coprocessor-assisted reassembly of SRB data |
| `erlcdl_send_rlf_ind` | 0x90441bd0 | L2 | RLC-DL | Sends radio-link-failure indication upward |
| `erlcul_status_fdbk_hndlr_errc_vcon` | 0x90445a9e | L2 | RLC-UL / AM | Processes RLC STATUS feedback (virtual-connected) |
| `erlcul_confirm_ul_harq_errc_vcon` | 0x90446128 | L2 | RLC-UL | Confirms UL HARQ result to RLC |
| `erlcul_fill_erlc_desc` | 0x90446210 | L2 | RLC-UL | Fills the RLC descriptor for a UL PDU |
| `erlcul_critical_data_check` | 0x9044607e | L2 | RLC-UL | Checks for critical/priority UL data |
| `erlcul_sdu_return_timer_handler` | 0x90446bfe | L2 | RLC-UL | Handles the SDU-return (discard) timer |

### PDCP (`epdcp_*`) — ciphering, integrity, ROHC, reordering

PDCP is the top of L2. It ciphers/deciphers and integrity-protects data with the AS security keys,
compresses IP headers (ROHC), maintains hyper-frame-number sync, delivers in order, and generates
PDCP status reports on re-establishment.

**Regexes & counts:** `epdcp` → **77**; `^epdcp` → **60**. (Remaining `epdcp` hits are
`dmf_*`/`el2*`/`__el2em_*` diagnostic + power glue.)

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `epdcp_init` | 0x90502490 | L2 | PDCP | Initializes the PDCP entity |
| `epdcp_dl_gen_pdcp_stus_rpt` | 0x9046df80 | L2 | PDCP-DL | Builds a PDCP STATUS report (missing-SN bitmap) |
| `epdcp_dl_move_to_hfn_sync` | 0x9046da76 | L2 | PDCP-DL | Moves DL entity into hyper-frame-number sync |
| `epdcp_dl_write_dcit_entry` | 0x9046dbaa | L2 | PDCP-DL | Writes a decipher-in-transit (DCIT) work entry |
| `epdcp_dl_dcip_vrb_oob_hndlr` | 0x904701f6 | L2 | PDCP-DL / cipher | Handles out-of-band decipher for virtual RB |
| `epdcp_dl_decipher_vrb_va_shortage_hndlr` | 0x90470396 | L2 | PDCP-DL / cipher | Handles buffer shortage during decipher |
| `epdcp_is_ul_integrity_handling_done` | 0x904ffbec | L2 | PDCP-UL / integrity | Tests whether UL integrity processing finished |
| `epdcp_dl_poll_pit_drbum_drbam_rohc_vrb_nro` | 0x9046ad14 | L2 | PDCP-DL / ROHC | Polls DRB (UM+AM) ROHC decompression pipeline |
| `epdcp_dl_drb_switch_to_non_reest_ord_mode` | 0x9046e8a4 | L2 | PDCP-DL | Switches DRB to non-reestablish in-order mode |
| `epdcp_dl_gen_pdcp_stus_rpt` | 0x9046df80 | L2 | PDCP-DL | (status report; see above) |
| `l2_cp_int_epdcp` | 0x902dc606 | L2 | PDCP / integrity | Control-plane PDCP integrity entry |
| `epdcp_rbm_is_drb_for_ims` | 0x9050fc66 | L2 | PDCP / RBM | Tests if a DRB carries IMS (VoLTE) traffic |

---

## L3 — RRC (`errc_*`)

RRC is the control brain of the radio side. **Count: `errc_` → 5719** (by far the biggest family in
the LTE stack). It is too large to list fully, so here is the schema (sub-family → count → job) plus
curated tables for the most security-relevant decoders.

### RRC schema (sub-family regex → count)

| Regex | Count | Sub-family job |
|-------|------:|----------------|
| `^errc_cel` | 1729 | Cell / RRC-entity control (autonomous search, SIB mgmt, paging, connection, PWS) |
| `^errc_mob` | 1427 | Mobility: cell reselection, measurement, priority/deprioritization, handover |
| `^errc_conn` | 435 | Connection control (establish / reconfigure / release) |
| `^errc_l` | 54 | `errc_lsys*` (SI dispatch) + `errc_lcel*` |
| `^errc_lc` | 38 | `errc_lcel*` low-level cell handlers |
| `^errc_lcel` | 26 | Low-level cell / paging bridge |
| `^errc_lsys` | 14 | System/SI dispatch task (main loop, SI raw-data, ASN.1 entry) |
| `^errc_asn` | 4 | ASN.1 codec entry (`errc_asn1_decoder/encoder/mem_free*`) |
| `errc_cel_sib` | 59 | SIB modify/reread FSM |
| `errc_cel_pwsrcv` | 40 | Public-Warning-System receiver (ETWS/CMAS) |
| `errc_cel_paging` | 25 | Paging reception |
| `errc_cel_conn` | 17 | Cell-level connection handling |
| `AsnDecode_SystemInformationBlockType` | 15 | Per-SIB ASN.1 UPER decoders |

### RRC dispatch & ASN.1 codec

The RRC message path: `errc_lsys_main` runs the SI task, `errc_lsys_asn1_decoder` /
`errc_asn1_decoder` hand raw OTA bytes to the ASN.1 UPER engine, which dispatches to the per-message
/ per-SIB decoders. `errc_asn1_decoder` (0x905269be) is a thin dispatcher that validates the input
pointers (`_break(2)` on null) and branches on the first ASN.1 tag byte.

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `errc_lsys_main` | 0x905b6586 | L3 | RRC / dispatch | Main loop of the LTE-RRC system-info task |
| `errc_lsys_asn1_decoder` | 0x906cf4fe | L3 | RRC / dispatch | Entry into ASN.1 decode of received SI |
| `errc_lsys_get_si_raw_data_hdlr` | 0x906cf664 | L3 | RRC / dispatch | Fetches raw SI bytes for decoding |
| `errc_lsys_get_sib1_crc_ng_hdlr` | 0x906cfa4e | L3 | RRC / dispatch | Handles SIB1 CRC-fail case |
| `errc_asn1_decoder` | 0x905269be | L3 | RRC / ASN.1 | UPER decode dispatcher (tag-driven) |
| `errc_asn1_encoder` | 0x90526926 | L3 | RRC / ASN.1 | UPER encode dispatcher |
| `errc_asn1_mem_free` | 0x90526b78 | L3 | RRC / ASN.1 | Frees ASN.1 decode heap blocks |

### RRC system information (SIB decoders)

Each SIB is a separately-coded ASN.1 UPER decoder. These parse **untrusted broadcast bytes**, so
they are prime attack surface. All 15 present:

| function | addr | protocol/sublayer | what it decodes |
|----------|------|-------------------|-----------------|
| `AsnDecode_SystemInformationBlockType1` | 0x9066212e | RRC / SIB | Cell access / PLMN / scheduling (SIB1) |
| `AsnDecode_SystemInformationBlockType2` | 0x9067de7e | RRC / SIB | Common + shared radio resource config |
| `AsnDecode_SystemInformationBlockType3` | 0x90676a5a | RRC / SIB | Intra-frequency reselection |
| `AsnDecode_SystemInformationBlockType4` | 0x9065efdc | RRC / SIB | Intra-freq neighbour cell list |
| `AsnDecode_SystemInformationBlockType5` | 0x9067c47a | RRC / SIB | Inter-freq reselection |
| `AsnDecode_SystemInformationBlockType6` | 0x906737b0 | RRC / SIB | UTRA (3G) reselection |
| `AsnDecode_SystemInformationBlockType8` | 0x9067b586 | RRC / SIB | CDMA2000 reselection |
| `AsnDecode_SystemInformationBlockType13_r9` | 0x9065f298 | RRC / SIB | MBMS (eMBMS) config |
| `AsnDecode_SystemInformationBlockType14_r11` | 0x90675bdc | RRC / SIB | Extended Access Barring (EAB) |
| `AsnDecode_SystemInformationBlockType15_r11` | 0x90662e8c | RRC / SIB | MBMS SAI neighbours |
| `AsnDecode_SystemInformationBlockType18_r12` | 0x906635be | RRC / SIB | Sidelink (D2D) comm config |
| `AsnDecode_SystemInformationBlockType19_r12` | 0x90668f3c | RRC / SIB | Sidelink discovery config |
| `AsnDecode_SystemInformationBlockType20_r13` | 0x9065fdf8 | RRC / SIB | SC-PTM (single-cell MBMS) |
| `AsnDecode_SystemInformationBlockType21_r14` | 0x9067c26e | RRC / SIB | V2X sidelink config |
| `AsnDecode_SystemInformationBlockType24_r15` | 0x90660fea | RRC / SIB | NR (5G) reselection info |

### RRC paging + connection + mobility

| function | addr | protocol/sublayer | what it does |
|----------|------|-------------------|--------------|
| `errc_cel_sib_mod_main` | 0x9055d4b4 | RRC / SIB mgmt | Main of the SIB-modify FSM |
| `errc_cel_sibmr_rx_sib1_success_callback` | 0x9055d89a | RRC / SIB mgmt | Callback on successful SIB1 receipt |
| `errc_cel_autos_evaluate_best_cell` | 0x905273bc | RRC / cell select | Evaluates best cell in autonomous search |
| `errc_cel_autos_main` | 0x90526c06 | RRC / cell select | Autonomous-search FSM main |
| `errc_mob_cctrl_get_lte_candidate_cell` | 0x905b710c | RRC / mobility | Gets candidate LTE cell for reselection |
| `errc_mob_cctrl_set_dedicated_priority` | 0x905b852e | RRC / mobility | Applies RRC dedicated frequency priorities |
| `errc_mob_cctrl_t320_timer_control` | 0x905b8110 | RRC / mobility | Controls T320 (dedicated-priority validity) |
| `errc_mob_cctrl_modify_deprioritization` | 0x905b83ae | RRC / mobility | Modifies cell deprioritization state |

### RRC public warning — ETWS / CMAS (`errc_cel_pwsrcv_*`, 40 fns)

The Public Warning System receiver reassembles broadcast warning messages (earthquake/tsunami =
ETWS, commercial mobile alerts = CMAS) delivered over BCCH/paging, does duplicate detection, and
raises PWS indications to the host. It parses attacker-controllable broadcast content, so it is a
notable attack surface.

| function | addr | protocol/sublayer | what it does |
|----------|------|-------------------|--------------|
| `errc_cel_pwsrcv_main` | 0x90559b3c | RRC / PWS | Main of the PWS receiver FSM |
| `errc_cel_pwsrcv_fsm_idle_init_etws_req` | 0x90559b34 | RRC / PWS(ETWS) | Starts ETWS reception |
| `errc_cel_pwsrcv_fsm_idle_init_cmas_req` | 0x90559b0e | RRC / PWS(CMAS) | Starts CMAS reception |
| `errc_cel_pwsrcv_set_etws_param_primary` | 0x90559fa8 | RRC / PWS(ETWS) | Stores ETWS primary-notification params |
| `errc_cel_pwsrcv_comb_warning_msg_segment` | 0x9055a4e8 | RRC / PWS | Reassembles multi-segment warning message |
| `errc_cel_pwsrcv_check_seg_rx_cmpl` | 0x9055a358 | RRC / PWS | Checks all segments received |
| `errc_cel_pwsrcv_check_dup_msg` | 0x9055a106 | RRC / PWS | Duplicate-message detection (uses msg-id/serial + per-PLMN/Japan-MCC time window) |
| `errc_cel_pwsrcv_send_pws_info_ind` | 0x9055a818 | RRC / PWS | Delivers assembled warning to host |
| `errc_cel_pwsrcv_get_free_seg_buff_from_pool` | 0x9055a88c | RRC / PWS | Allocates a segment buffer from the pool |

---

## L3 — NAS: EMM & ESM

NAS is the conversation between the phone and the core network (MME), carried transparently inside
RRC. **EMM** manages *where you are and who you are* (registration, mobility, identity, security);
**ESM** manages *your data sessions* (bearers, QoS, IP). Both are attack surface because they decode
core-network-supplied OTA messages.

### EMM — EPS Mobility Management (`CEmm*`, `emm_*`)

The bulk of EMM is implemented as C++ classes: **`CEmm*` → 3004** methods. The C-style
`emm_*` prefix adds **81** more (init/glue + `emm_custom_*` policy). Key classes seen:
`CEmmCall` (service-request/CSFB/paging logic), `CEmmReg` (registration), `CEmmConn`
(connection/access-barring), `CEmmPlmnSel` (PLMN selection), `CEmmTimerMng`, `CEmmIntState`,
`CEmmNMSrv` (message decode). Regex `CEmm` → 3004; `^emm_` → 81.

| function | addr | protocol/sublayer | what it does |
|----------|------|-------------------|--------------|
| `emm_main` | 0x904e9ea0 | EMM / task | EMM task main dispatch loop |
| `emm_init` | 0x904e97da | EMM / init | Initializes the EMM entity |
| `emm_rcv_nasmsg_adt_translator` | 0x90486828 | EMM / attach | Receives/translates a NAS message into EMM |
| `emm_rcv_security_cmd_ind_adt_translator` | 0x9048686c | EMM / security | Handles Security-Mode-Command indication |
| `CEmmNMSrv::decodeEMMInformation()` | 0x904a95f6 | EMM / decode | Decodes the EMM INFORMATION message (net name/time) |
| `CEmmNMSrv::decodeEMMStatus()` | 0x904a963c | EMM / decode | Decodes the EMM STATUS message |
| `CEmmCall::sndExtendedServiceRequest()` | 0x90488f4c | EMM / service req | Builds/sends Extended Service Request (CSFB) |
| `CEmmCall::startEstExsr()` | 0x904891b6 | EMM / service req | Starts establishment for extended service request |
| `CEmmCall::chkMobileIdentityOfCsPaging()` | 0x9048795c | EMM / paging | Validates mobile identity in a CS paging |
| `CEmmCall::judgeCSFBprocess()` | 0x904887de | EMM / CSFB | Decides CS-fallback processing |
| `CEmmCall::setEpsUpdateStatus()` | 0x90487ea2 | EMM / TAU | Sets EPS update status (attach/TAU) |
| `CEmmCall::startT3346()` / `stopT3346()` | 0x90487f5c / 0x90487f28 | EMM / backoff | MM back-off timer (congestion) control |
| `CEmmCall::judgeMapEmmCause()` | 0x90488174 | EMM / cause | Maps received EMM cause codes |
| `emm_set_4g5_security_param` | 0x904ef794 | EMM / security | Passes AS security params across 4G↔5G |
| `emm_convert_plmn_string_to_struct` | 0x9049ccc0 | EMM / PLMN | Parses PLMN string → struct |
| `emm_is_in_tai_list` | 0x904c9958 | EMM / TAU | Checks if current TAI is in registered list |

*(Attach / TAU / identity / auth are handled inside `CEmmReg`/`CEmmConn` state machines; the
`emm_attach*` name search returns 5, `emm_auth` 2, `emm_detach` 5 — most logic lives in class
methods rather than free `emm_*` functions.)*

### ESM — EPS Session Management (`esm_*`, 618)

ESM sets up and tears down the data pipes. It parses/builds the IEs that carry QoS, APN-AMBR,
TFT (traffic-flow templates) and **PCO** (protocol configuration options — the field that has
historically hidden parsing bugs). Regex `^esm_` → **618**.

| function | addr | protocol/sublayer | what it does |
|----------|------|-------------------|--------------|
| `esm_event_decode_esm_msg` | 0x906e6a30 | ESM / decode | Top-level decode of a network-sent ESM message (validates length, masks sensitive trace, dispatches by msg type) |
| `esm_pasre_eps_qos_ie` | 0x906dc3fc | ESM / QoS | Parses the EPS QoS IE *(sic: "pasre")* |
| `esm_parse_ext_eps_qos_ie` | 0x906dc4ce | ESM / QoS | Parses the extended EPS QoS IE |
| `esm_parse_apn_ambr_ie` | 0x906dc6c8 | ESM / QoS | Parses APN aggregate-max-bit-rate IE |
| `esm_parse_ext_apn_ambr_ie` | 0x906dc734 | ESM / QoS | Parses extended APN-AMBR IE |
| `esm_decode_bit_rate` | 0x906ddd9a | ESM / QoS | Decodes an encoded bit-rate value |
| `esm_cmn_tftlib_tft_decode` | 0x906de20e | ESM / TFT | Decodes a Traffic Flow Template |
| `esm_cmn_encode_pco` | 0x906de0b0 | ESM / PCO | Encodes Protocol Configuration Options |
| `esm_cmn_encode_pco_ciphered_part` | 0x906dd88a | ESM / PCO | Encodes the ciphered PCO part |
| `esm_cmn_copy_esm_pco_to_pco` | 0x906ddb44 | ESM / PCO | Copies internal PCO struct → wire PCO |
| `esm_cmn_map_esm_cause` | 0x906ddc06 | ESM / cause | Maps ESM cause codes |
| `esm_cmn_copy_apn` | 0x906dd904 | ESM / PDN | Copies the APN string |
| `esm_cmn_copy_ip_addr` | 0x906dd930 | ESM / PDN | Copies assigned IP address |
| `esm_emm_adt_translator_epsbearer_data_ind` | 0x906dc184 | ESM↔EMM | Translates EPS-bearer data indication between ESM and EMM |
| `esm_send_icd_ota_message` | 0x906e6384 | ESM / trace | Emits decoded OTA message to diagnostics |

### The NAS/RRC message codec — `mcd_unpack*` (51)

`mcd_unpack` is a **table-driven decoder engine**: message-codec-descriptor (MCD) tables describe
each protocol message as a sequence of typed IEs, and `mcd_unpack_*` primitives walk those tables to
parse OTA bytes into C structs. It is shared across NAS SM/SMS/SS and CSN.1/BER-coded messages —
so a bug here is reachable from many protocols. Regex `mcd_unpack` → **51**.

| function | addr | protocol/sublayer | what it does |
|----------|------|-------------------|--------------|
| `mcd_unpack` | 0x90d03396 | codec / engine | Core MCD table-walking unpacker |
| `mcd_unpack_run` | 0x90d032f6 | codec / engine | Driver that runs the unpack over a buffer |
| `mcd_unpack_CHOICE` | 0x90d0457c | codec / IE | Decodes an ASN.1/CSN.1 CHOICE |
| `mcd_unpack_BER_SEQUENCE` | 0x90d0419c | codec / IE | Decodes a BER SEQUENCE |
| `mcd_unpack_BER_INTEGER` | 0x90d03a62 | codec / IE | Decodes a BER INTEGER |
| `mcd_unpack_BER_BYTES` | 0x90d0363a | codec / IE | Decodes a BER OCTET-STRING |
| `mcd_unpack_MAXBYTES` | 0x90d04c6c | codec / IE | Decodes a bounded byte field |
| `mcd_unpack_IEI_LIST` | 0x90d046ee | codec / IE | Walks an Information-Element-Identifier list |
| `mcd_unpack_EXT_TI` | 0x90d0462a | codec / IE | Decodes extended transaction identifier |
| `mcd_unpack_OPTIONAL`/`_BER_OPTIONAL` | 0x90d040f8 | codec / IE | Handles optional IE presence |
| `sm_mcd_unpack_and_update_ti_value` | 0x9136b220 | SM (SM/GMM) / codec | ESM/SM wrapper that also updates the TI |
| `cc_mcd_unpack` | 0x901015c0 | CC / codec | Call-Control message unpacker (CS domain) |
| `sms_mcd_unpack` | 0x9137874a | SMS / codec | SMS message unpacker |
| `csmss_mcd_unpack` | 0x90b701de | SMS / codec | CS-SMS message unpacker |

---

## Summary of exact regexes & counts

| Layer | Regex(es) used | Count |
|-------|----------------|------:|
| L1 PHY | `^el1` (limit) · `^el1_` · `^el1_meas` · `^el1_csr` · `^el1_irt` | 4000+ · 1799 · 316 · 77 · 142 |
| L2 MAC | `emac` · `^emac` | 827 · 586 |
| L2 RLC | `erlc` · `^erlcdl` · `^erlcul` | 255 · 86 · 85 |
| L2 PDCP | `epdcp` · `^epdcp` | 77 · 60 |
| L3 RRC | `errc_` · `^errc_cel` · `^errc_mob` · `^errc_conn` · `errc_cel_pwsrcv` · `AsnDecode_SystemInformationBlockType` | 5719 · 1729 · 1427 · 435 · 40 · 15 |
| L3 NAS-EMM | `CEmm` · `^emm_` | 3004 · 81 |
| L3 NAS-ESM | `^esm_` | 618 |
| NAS codec | `mcd_unpack` | 51 |

**Attack-surface highlights for a beginner** (functions that parse attacker-influenced bytes):
the 15 `AsnDecode_SystemInformationBlockType*` SIB decoders and `errc_asn1_decoder`; the
`errc_cel_pwsrcv_*` ETWS/CMAS reassembly (esp. `_comb_warning_msg_segment`, `_check_dup_msg`);
the ESM IE parsers (`esm_pasre_eps_qos_ie`, `esm_cmn_tftlib_tft_decode`, PCO encode/copy); the EMM
message decoders (`CEmmNMSrv::decodeEMM*`); and the shared `mcd_unpack*` engine that underpins them.
</content>
