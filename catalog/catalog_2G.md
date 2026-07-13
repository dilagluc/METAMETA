# 2G (GSM + GPRS/EGPRS) — per-layer function inventory

Target DB: Huawei `MD1IMG_22.img` → `000_md1rom`, symbolized. All counts below come from the
IDA query client:

```
source /workspace/.venv-ida/bin/activate
python /workspace/idaq search "<python-regex>" <limit>     # find functions by name
python /workspace/idaq decompile "<name|0xaddr>"           # sample behavior
python /workspace/idaq xrefs "<name|0xaddr>"               # callers/callees
```

## What "2G" covers here

2G is two stacks that share the same air interface hardware:

- **GSM circuit-switched (CS)** — voice calls, SMS: PHY → **RR** (Radio Resource, L3) → CS NAS (**MM/CC/SMS**).
- **GPRS / EGPRS packet-switched (PS)** — mobile data: PHY → **RLC/MAC** (L2) → **LLC** → **SNDCP** →
  PS NAS (**GMM/SM**).

**Naming conventions discovered in this DB (the anchors used below):**

| Prefix | Meaning |
| --- | --- |
| `l1a_gsm_*`, `L1D_/L1I_/L1T_*` | GSM Layer-1 (PHY) control / RF test / scheduler |
| `FDD_acs_*` | GSM **access** (RACH / immediate assignment) — RR/L2 boundary |
| `FDD_mac_*` (lowercase, 0x907…) | **GPRS/EGPRS MAC** |
| `FDD_rlc_*` (lowercase, 0x907…) | **GPRS/EGPRS RLC** |
| `FDD_RLC_*` / `FDD_MAC_*` (UPPERCASE, 0x915…) | **UMTS/3G** RLC/MAC — *not 2G* (noted to avoid confusion) |
| `FDD_rmpc_*` | GPRS **RLC/MAC packet control** (packet resource / cell-change) |
| `FDD_reasm_*` | RLC **reassembly** of RLC blocks → LLC PDUs |
| `llc_*` | **LLC** (Logical Link Control, GPRS L2) |
| `Csn*` / `csn_*` | **CSN.1** bit-stream codec (used by RR/PSI rest-octets) |
| `FDD_rr_*` / `TDD_rr_*` | GSM **RR** (Radio Resource, L3); TDD = TD-SCDMA sibling reuse |
| `FDD_rmc_*` | RR **radio measurement & cell reselection** (mobility, L3) |
| `FDD_si_*` / `FDD_psi_*` | **System Information** (BCCH) / **Packet SI** decoders |
| `mm_*` / `cc_*` | CS NAS **Mobility Management** / **Call Control** (shared 2G+3G) |
| `smsal_*` | **SMS** abstraction layer (CP/RP + CB); shared 2G+3G |
| `gmm_*` / `sm_*` | PS NAS **GPRS MM** / **Session Management** |
| `ratdm_sndcp_*` | **SNDCP** interface via the RAT data-plane manager |

> **Note — CS NAS (MM / CC / SMS) is shared between 2G and 3G** in this MediaTek/Huawei stack.
> The `mm_*`, `cc_*`, and `smsal_*` functions are the same code whether the phone is camped on GSM
> or UMTS; only the underlying RR/RRC access layer differs. They are listed here because they are the
> 2G CS control-plane, but they are *not* GSM-specific.

---

## Regex → count summary

| Layer | Regex | Count | Notes |
| --- | --- | --- | --- |
| L1 GSM PHY | `l1.*gsm` | 81 | GSM L1 control/RF-test handlers |
| L1 PHY (schedulers) | `cbch` | 94 | CBCH scheduling across L1/RR/SMS (mixed) |
| L2 GPRS MAC | `FDD_mac_` | 380 | GPRS/EGPRS medium access control |
| L2 GPRS RLC | `FDD_rlc_` | 234 | includes ~a few UPPERCASE UMTS RLC — see note |
| L2 RLC/MAC ctrl | `rmpc` | 362 (`FDD_rmpc_`+`TDD_`) | packet resource / cell-change control |
| L2 RLC reassembly | `FDD_reasm_` | 17 | RLC block → LLC PDU reassembly |
| L2 GPRS LLC | `^llc_` | 168 | Logical Link Control |
| L2 SNDCP | `sndcp` | 18 | all `ratdm_sndcp_*` relay handlers |
| L2 CSN.1 codec | `^[Cc]sn` | 14 | bit-stream encode/decode primitives |
| L3 RR (GSM) | `FDD_rr_` | 510 | Radio Resource |
| L3 RR (TDD sibling) | `TDD_rr_` | 469 | TD-SCDMA RR reuse of same code |
| L3 RR reselection | `FDD_rmc_` | 751 | measurement + cell reselection (mobility) |
| L3 access | `FDD_acs_` | 49 | RACH / immediate assignment |
| L3 System Info | `FDD_si` | 231 | BCCH SI 1/2/3/4/13… decoders |
| L3 Packet SI | `FDD_psi` | 20 | GPRS PSI decoders |
| CS NAS MM | `^mm_` | 748 | Mobility Management (shared 2G/3G) |
| CS NAS CC | `^cc_` | 501 | Call Control (shared 2G/3G) |
| CS NAS SMS | `smsal_` | 592 | SMS abstraction layer (shared 2G/3G) |
| Cell Broadcast | `smsal_cb_` | 37 | CBS message handling |
| PS NAS GMM | `^gmm_` | 433 | GPRS Mobility Management |
| PS NAS SM | `^sm_` | 556 | Session Management (PDP contexts) |

(`psi`=242, `cb_`=1333, `sms`=2132, `gmm`=1658, `csn`=36 are broad substring matches that pull in
unrelated 3G/4G/5G symbols; the narrowed regexes above are the accurate 2G anchors.)

---

## L1 — Physical layer (PHY)

The GSM PHY handles the actual radio: TDMA bursts, RACH transmission, BCCH/CCCH/CBCH reception, RSSI
and BSIC measurements. In this image the high-level L1 controller is `l1a_gsm_*` (adaptation) with the
DSP-facing driver in `L1D_/L1I_/L1T_*`. Beginners: this is the layer that tunes the radio and hands raw
decoded blocks up to L2/L3.

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `l1a_gsm_active_data_init` | 0x908f5bf4 | L1 | GSM PHY | Initializes L1 active-mode data structures |
| `l1a_standby_gsm_bsic_read_req` | 0x908f5e22 | L1 | GSM PHY | Requests neighbour BSIC read in standby |
| `l1a_standby_gsm_meas_start_req` | 0x908f5f0e | L1 | GSM PHY | Starts idle-mode signal measurements |
| `l1a_receive_report_gsm_rssi` | 0x908f6292 | L1 | GSM PHY | Consumes RSSI measurement reports from DSP |
| `l1a_receive_report_gsm_bsic` | 0x908f6e56 | L1 | GSM PHY | Consumes decoded BSIC of neighbour cells |
| `l1a_gsm_set_max_tx_power_req_handler` | 0x908ea696 | L1 | GSM PHY | Applies max Tx-power limit to the PA |
| `l1a_temporarily_stop_gsm_gap_req` | 0x908f6214 | L1 | GSM PHY | Pauses GSM measurement gaps (multi-RAT) |
| `L1D_CBChStart` | 0x90966a7e | L1 | GSM PHY | Starts Cell-Broadcast channel reception |
| `L1_CBChStop_Norm` | 0x90920b04 | L1 | GSM PHY | Stops CBCH reception |
| `l1a_ccch_update_cbch_basic_only` | 0x908f14c6 | L1 | GSM PHY | Reconfigures CCCH/CBCH scheduling |
| `GL1D_CDFtoGSM_band_mapping` | 0x908d4d92 | L1 | GSM PHY | Maps calibration/band data to GSM bands |
| `l1a_em_rf_test_gsm_power_scan_req_handler` | 0x908e9fec | L1 | GSM PHY | RF engineering-mode power scan |

---

## L2 — GPRS/EGPRS RLC/MAC

For packet data the L2 splits into **MAC** (owns the shared radio: TBF establishment, uplink/downlink
block scheduling, contention resolution) and **RLC** (segmentation of LLC PDUs into RLC data blocks,
ARQ retransmission, reassembly on receive). `FDD_rmpc_*` sits above them handling packet resource
control and NACC cell change; `FDD_reasm_*` rebuilds LLC PDUs from received RLC blocks.

> Watch out: UPPERCASE `FDD_RLC_*` / `FDD_MAC_*` at 0x915xxxxx are the **UMTS/3G** RLC/MAC — the 2G
> GPRS ones are the lowercase `FDD_rlc_*` / `FDD_mac_*` at 0x907xxxxx.

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `FDD_mac_egprs_pkt_ul_assign` | 0x907a3e16 | L2 | GPRS MAC | Handles EGPRS uplink TBF assignment |
| `FDD_mac_ul_dl_pkt_dl_assignment_handler` | 0x907a9c82 | L2 | GPRS MAC | Processes packet downlink assignment |
| `FDD_mac_resolve_one_phase_contention` | 0x907a9394 | L2 | GPRS MAC | One-phase access contention resolution |
| `FDD_mac_release_ul_tbf` | 0x907a7b1e | L2 | GPRS MAC | Tears down an uplink TBF |
| `FDD_mac_t3168timeout_hdlr` | 0x907a6886 | L2 | GPRS MAC | T3168 (packet-access) timeout handling |
| `FDD_mac_fill_msradio_acc_capability` | 0x907aae5a | L2 | GPRS MAC | Fills MS radio access capability IE |
| `FDD_rlc_seg_gprs_blk` | 0x907cf3f8 | L2 | GPRS RLC | Segments an LLC PDU into GPRS RLC blocks |
| `FDD_rlc_get_egprs_next_blk` | 0x907d0416 | L2 | EGPRS RLC | Builds next EGPRS RLC data block for Tx |
| `FDD_rlc_data_blks_assign` | 0x907cab14 | L2 | GPRS RLC | Assigns data blocks to a TBF |
| `FDD_rlc_check_pdus` | 0x907cd0c6 | L2 | GPRS RLC | Validates queued PDUs before transfer |
| `FDD_rlc_mac_rlc_ul_data_req` | 0x907d52d0 | L2 | GPRS RLC/MAC | RLC→MAC uplink data request primitive |
| `FDD_rlc_main` | 0x907ce17a | L2 | GPRS RLC | RLC task main dispatch loop |
| `FDD_rmpc_mac_dl_assign_result_hdlr` | 0x907e3e14 | L2 | RLC/MAC ctrl | Handles MAC downlink-assign result |
| `FDD_rmpc_nacc_is_in_ccn_mode` | 0x907fd776 | L2 | RLC/MAC ctrl | NACC cell-change (CCN) mode check |
| `FDD_rmpc_extract_and_check_imsi` | 0x907fc43c | L2 | RLC/MAC ctrl | Extracts IMSI from packet paging block |
| `FDD_rmpc_mpal_rr_data_ind_hdlr` | 0x907f3e36 | L2 | RLC/MAC ctrl | Handles RR data indication to packet ctrl |
| `FDD_reasm_start_compose_llc_pdu` | 0x907c6f14 | L2 | RLC reassembly | Reassembles RLC blocks into a GPRS LLC PDU *(decompile confirmed: bit-level block copy into peer buffer)* |
| `FDD_reasm_egprs_llc_pdu_hdlr` | 0x907c7cba | L2 | RLC reassembly | EGPRS-specific LLC PDU reassembly |
| `FDD_reasm_send_llc_pdu_ind` | 0x907c85e0 | L2 | RLC reassembly | Delivers a completed LLC PDU upward |

---

## L2 — LLC (Logical Link Control)

LLC is the reliable link layer between the phone and the SGSN. It runs ABM (acknowledged, like a
mini-LAPB with SABM/UA/I-frames and SACK-based ARQ) and ADM/UI (unacknowledged) modes, negotiates XID
parameters, and multiplexes SAPIs. Beginners: think "TCP-like retransmission but at the GPRS link
layer, between handset and core network."

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `llc_main` | 0x90c82806 | L2 | LLC | LLC task main entry / message dispatch |
| `llc_create` | 0x90c807b6 | L2 | LLC | Creates an LLC entity |
| `llc_check_sabm_collision` | 0x90c7d17c | L2 | LLC ABM | Detects SABM setup collision |
| `llc_receive_ua_response` | 0x90c7da62 | L2 | LLC ABM | Processes UA (link setup ack) |
| `llc_transmit_iframe` | 0x90c7f03e | L2 | LLC ABM | Transmits an acknowledged I-frame |
| `llc_construct_sack_ptr` | 0x90c7eac4 | L2 | LLC ARQ | Builds a selective-ACK (SACK) bitmap |
| `llc_store_in_rx_arq` | 0x90c7ff1a | L2 | LLC ARQ | Buffers received frame for ARQ ordering |
| `llc_rx_ui_frame_hdlr` | 0x90c7f81e | L2 | LLC UI | Handles unacknowledged UI frames |
| `llc_construct_uframe` | 0x90c80356 | L2 | LLC | Builds a U-frame (control) |
| `llc_process_ku_xid_param` | 0x90c84438 | L2 | LLC XID | Parses ciphering-key XID negotiation |
| `llc_validate_n201i` | 0x90c8563e | L2 | LLC XID | Validates N201-I frame-size parameter |
| `llc_unitdata_tx` | 0x90c83e9e | L2 | LLC | Sends LLC-UNITDATA (user data) |
| `llc_lle_rx` / `llc_lle_tx` | 0x90c814a8 / 0x90c819e4 | L2 | LLC | Per-LLE receive / transmit state machines |
| `llc_snd_rlc_rnr_stop` | 0x90c85d5e | L2 | LLC→RLC | Flow control: stop (RNR) toward RLC |

---

## L2 — SNDCP + CSN.1 codec

**SNDCP** sits between LLC and the PS NAS/IP data; it compresses headers/data and maps N-PDUs to LLC.
In this image the SNDCP entity is surfaced mainly through the **RAT data-plane manager** (`ratdm_sndcp_*`,
18 functions) plus `flc2_npdu_*` flow-control/N-PDU callbacks — the data path is managed rather than a
standalone `sndcp_*` task. **CSN.1** is not a protocol layer but the shared bit-field codec that RR/PSI
rest-octet decoders call to read variable-length CSN.1-encoded IEs.

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `ratdm_send_activate_req_to_sndcp` | 0x91234e62 | L2 | SNDCP | Activates an SNDCP context (PDP data path) |
| `ratdm_sndcp_data_ind_hdlr` | 0x91234a90 | L2 | SNDCP | Handles downlink SNDCP data indication |
| `ratdm_sndcp_data_cnf_hdlr` | 0x91234a4a | L2 | SNDCP | Uplink data confirm from SNDCP |
| `ratdm_sndcp_reset_npdu_seq_ind_hdlr` | 0x91234de8 | L2 | SNDCP | Resets N-PDU sequence numbers |
| `ratdm_sndcp_flush_ind_hdlr` | 0x91234bec | L2 | SNDCP | Flushes buffered N-PDUs on context change |
| `ratdm_insert_npdu_queue` | 0x91235df0 | L2 | SNDCP/NPDU | Queues an N-PDU for transfer |
| `Csn_/csn_getLongBits` | 0x9078b1a8 | L2 | CSN.1 codec | Reads N bits from the CSN.1 bit-stream |
| `csn_putLongBits` | 0x9078b1f8 | L2 | CSN.1 codec | Writes N bits into the CSN.1 bit-stream |
| `CsnBitFieldCopy` | 0x9078b07e | L2 | CSN.1 codec | Copies a bit-field during encode/decode |
| `CsnDecodeAlloc` / `CsnDecodeFree` | 0x9078af66 / 0x9078b008 | L2 | CSN.1 codec | Alloc/free of CSN.1 decode buffers |
| `CsnRootEncodeAutoAlloc` | 0x9078b056 | L2 | CSN.1 codec | Root CSN.1 encode with auto memory |

---

## L3 — RR (Radio Resource)

RR is the GSM control-plane brain: it selects and camps on cells, reads System Information, performs the
random-access (RACH) → immediate-assignment handshake, manages dedicated channels and handovers, and
runs cell reselection based on measurements. `FDD_rr_*` is the core; `FDD_rmc_*` is the measurement /
cell-reselection engine; `FDD_acs_*` is the access procedure; `FDD_si_*` / `FDD_psi_*` decode the
broadcast information. Beginners: RR is what decides "which tower am I on and how do I get an air-interface
channel."

### RR core + access

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `FDD_rr_task` | 0x908021b8 | L3 | RR | RR task main entry / dispatch |
| `FDD_rr_calculate_c1` | 0x9080f176 | L3 | RR | Computes C1 path-loss cell-selection criterion |
| `FDD_rr_decode_utran_fdd_descriptions` | 0x9080dade | L3 | RR (inter-RAT) | Decodes 3G neighbour-cell descriptions in SI/MI |
| `FDD_rr_decode_eutran_measurement_control_parameters` | 0x9080b5de | L3 | RR (inter-RAT) | Decodes LTE measurement params |
| `FDD_rr_compose_pkt_nc_meas_report` | 0x90806ec8 | L3 | RR | Builds packet neighbour-cell measurement report |
| `FDD_rr_gsm_prot_error_hdlr` | 0x90811ca4 | L3 | RR | Handles RR protocol errors |
| `FDD_rr_decode_stored_si_for_camping` | 0x9082cc06 | L3 | RR | Decodes stored SI to camp on a cell |
| `FDD_acs_frame_and_send_rach_req_on_ccch` | 0x9078814e | L3 | RR access | Frames and sends a RACH channel request |
| `FDD_acs_imm_asgn_for_dedi_hdlr` | 0x90789700 | L3 | RR access | Handles Immediate Assignment (dedicated) |
| `FDD_acs_imm_asgn_for_tbf_hdlr` | 0x9078a682 | L3 | RR access | Handles Immediate Assignment for a packet TBF |
| `FDD_acs_imm_asgn_rej_hdlr` | 0x90787b82 | L3 | RR access | Handles Immediate Assignment Reject |
| `FDD_acs_decode_ia_rest_octets_for_tbf` | 0x9078a2b4 | L3 | RR access | Decodes IA Rest Octets (CSN.1) for TBF *(decompile confirmed: bit_stream_read of rest-octet fields)* |
| `FDD_acs_decode_pkt_chl_desc` | 0x90789dc2 | L3 | RR access | Decodes Packet Channel Description IE |

### RR measurement / cell reselection (`FDD_rmc_`, 751)

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `FDD_rmc_select_next_c2_resel` | 0x907f8b42 | L3 | RR reselection | Picks next cell by C2 reselection criterion |
| `FDD_rmc_decode_mi_eutran_measurement_para` | 0x907dcb5a | L3 | RR reselection | Decodes LTE meas params from Measurement Info |
| `FDD_rmc_decode_freq_chl_seq` | 0x907de7c2 | L3 | RR reselection | Decodes frequency/channel sequence (ARFCN list) |
| `FDD_rmc_get_nc_params` | 0x907e1ece | L3 | RR reselection | Extracts neighbour-cell (NC) measurement params |
| `FDD_rmc_t3122_timeout_hdlr` | 0x907f9ce4 | L3 | RR reselection | T3122 (access-retry) timeout handling |
| `FDD_rmc_check_abnormal_reselection_status` | 0x907fc2c8 | L3 | RR reselection | Detects abnormal reselection conditions |
| `FDD_rmc_cbch_stop_req_hdlr` | 0x907d730e | L3 | RR | Stops CBCH monitoring on cell change |

### System Information decoders (`FDD_si` 231, `FDD_psi` 20)

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `FDD_si_decode_si3rest_octets` | 0x9083072c | L3 | RR / SI3 | Decodes SI Type 3 rest octets (GPRS/SI2q flags) *(decompile confirmed)* |
| `FDD_si_decode_si3si4common_octets` | 0x9082e0e6 | L3 | RR / SI3-4 | Decodes octets common to SI3 and SI4 |
| `FDD_si_decode_stored_si_2_ter` | 0x9082cee4 | L3 | RR / SI2ter | Decodes SI2ter (3G neighbour list) |
| `FDD_si_si2bis_handler` | 0x9082b9fe | L3 | RR / SI2bis | Handles SI2bis extended BA list |
| `FDD_si_nbr_ctrl_chan_decode` | 0x9082912e | L3 | RR / SI | Decodes neighbour control-channel description |
| `FDD_si_decode_si2q_r11_params` | 0x90830ac4 | L3 | RR / SI2quater | Decodes SI2quater R11 params (LTE/3G reselection) |
| `FDD_si_update_la_identity` | 0x9082d81c | L3 | RR / SI | Updates Location Area Identity from SI |
| `FDD_psi_si_decode_freq_list_bitmap` | 0x907b8806 | L3 | RR / PSI | Decodes GPRS PSI frequency-list bitmap |
| `FDD_psi_extract_gprspwr_ctrl_params` | 0x907e4cd2 | L3 | RR / PSI | Extracts GPRS power-control params from PSI |
| `FDD_psi_extract_arfcnindex_list` | 0x907e44d6 | L3 | RR / PSI | Extracts ARFCN index list from PSI |

Paging (`FDD_rmpc_extract_and_check_imsi`, CS paging in `mm_*`) and immediate-assignment live under the
access/`FDD_acs_*` and `FDD_rmpc_*` groups above; there is no standalone `imm_assign`/`paging` prefix.

---

## CS NAS — MM / CC (shared 2G+3G)

The circuit-switched NAS runs on top of RR (2G) or RRC (3G). **MM** handles registration/location update,
authentication, and TMSI reallocation; **CC** runs the call state machine (setup, alerting, connect,
disconnect, DTMF, hold/multiparty). These are the *same* functions for a GSM or a UMTS call.

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `mm_peer_identity_req_handler` | 0x90d3fb20 | L3 NAS | MM | Handles network IDENTITY REQUEST |
| `mm_sim_authenticate_cnf_handler` | 0x90d44b20 | L3 NAS | MM | Processes SIM authentication result (AKA) |
| `mm_comm_store_security_context` | 0x90d3b672 | L3 NAS | MM | Stores CS security (cipher) context |
| `mm_action_change` | 0x90d3c33c | L3 NAS | MM | Drives MM state-machine transitions |
| `mm_send_broadcast_reg_req` | 0x90d38776 | L3 NAS | MM | Initiates registration / location update |
| `mm_srvcc_est_init` | 0x90d419b6 | L3 NAS | MM | SRVCC (VoLTE→CS handover) establishment |
| `cc_init` | 0x900fea16 | L3 NAS | CC | Initializes Call Control |
| `cc_send_peer_connect` | 0x900fb34c | L3 NAS | CC | Sends CONNECT toward the network |
| `cc_peer_release_complete_hdlr` | 0x900f956e | L3 NAS | CC | Handles RELEASE COMPLETE |
| `cc_initiate_disconnect` | 0x901019be | L3 NAS | CC | Starts call disconnect procedure |
| `cc_form_app_alert_ind` | 0x901002ee | L3 NAS | CC | Builds ALERTING indication to the app |
| `cc_change_support_codec_for_amr_wb` | 0x900fe4f2 | L3 NAS | CC | Negotiates AMR-WB codec set |
| `cc_buffer_stop_dtmf_req_hdlr` | 0x900f9f96 | L3 NAS | CC | Handles stop-DTMF request |
| `cc_peer_retrieve_mpty_rr_hdlr` | 0x900ffedc | L3 NAS | CC | Multiparty (conference) retrieve handling |

---

## CS NAS — SMS + Cell Broadcast (shared 2G+3G)

`smsal_*` (592) is the SMS abstraction layer above CP/RP transport — MO/MT delivery, status reports,
storage in ME/SIM, and CNMI notification config. Cell Broadcast (`smsal_cb_*`, 37, plus the `cbch`
L1/RR scheduling functions) receives broadcast SMS-CB messages on the CBCH.

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `smsal_new_app_data_ind` | 0x90c018a6 | L3 NAS | SMS | Delivers new MT SMS to the application |
| `smsal_send_mo_sms_rej` | 0x90c04898 | L3 NAS | SMS | Rejects a mobile-originated SMS |
| `smsal_status_report_peer_struct_unpack` | 0x90c035f8 | L3 NAS | SMS | Unpacks an SMS-STATUS-REPORT |
| `smsal_decode_mwf` | 0x90c08be2 | L3 NAS | SMS | Decodes Message-Waiting-Flag info |
| `smsal_copy_write_msg_cnf` | 0x90c05a50 | L3 NAS | SMS | Confirms write of SMS to storage |
| `smsal_check_is_me_full` | 0x90c06510 | L3 NAS | SMS | Checks whether ME SMS storage is full |
| `smsal_imcsms_ims_mt_sms_end_ind_hdlr` | 0x90c07bea | L3 NAS | SMS/IMS | Handles MT SMS-over-IMS completion |
| `smsal_cb_send_cbch_req` | 0x90bfc8ba | L3 NAS | Cell Broadcast | Requests CBCH reception from lower layers |
| `smsal_cb_reset_ch_info` | 0x90bfbc9a | L3 NAS | Cell Broadcast | Resets CB channel/message state |
| `smsal_cbch_req_handler` | 0x90bfcbac | L3 NAS | Cell Broadcast | Handles a CBCH configuration request |

---

## PS NAS — GMM / SM (GPRS packet control-plane)

The packet-switched NAS. **GMM** is GPRS Mobility Management: GPRS attach/detach, routing-area update
(RAU), authentication and P-TMSI handling. **SM** is Session Management: PDP context activation/
modification/deactivation (the "data connection" state machine), NSAPI ↔ TI mapping, and QoS. Beginners:
GMM ~ "register for data service," SM ~ "bring up / tear down a data bearer."

| function | addr | layer | protocol/sublayer | what it does |
| --- | --- | --- | --- | --- |
| `gmm_attach_proc` | 0x90d47dd4 | L3 NAS | GMM | Runs the GPRS ATTACH procedure |
| `gmm_ctrl_peer_attach_acc_handler` | 0x90d480b4 | L3 NAS | GMM | Handles ATTACH ACCEPT from network |
| `gmm_rau_init_state` | 0x90d5a430 | L3 NAS | GMM | Initializes routing-area-update state |
| `gmm_rau_abort` | 0x90d650a0 | L3 NAS | GMM | Aborts an in-progress RAU |
| `gmm_ctrl_peer_auth_cipher_rej_handler` | 0x90d48a52 | L3 NAS | GMM | Handles AUTH & CIPHER REJECT |
| `gmm_npdu_list_struct_parse` | 0x90d606ba | L3 NAS | GMM | Parses received N-PDU number list (for RAU) |
| `gmm_peer_detach_acc_handler` | 0x90d5fe94 | L3 NAS | GMM | Handles DETACH ACCEPT |
| `gmm_sm_ps_connection_release_req_handler` | 0x90d63a14 | L3 NAS | GMM↔SM | Handles PS connection release toward SM |
| `sm_peer_activate_req_handler` | 0x9136c326 | L3 NAS | SM | Handles PDP-context ACTIVATE request |
| `sm_compose_peer_deactivate_acc` | 0x9136e9f2 | L3 NAS | SM | Builds DEACTIVATE PDP ACCEPT |
| `sm_send_status_msg_to_peer` | 0x9136f754 | L3 NAS | SM | Sends SM STATUS message |
| `sm_nsapi_to_ctxnum` | 0x913642ba | L3 NAS | SM | Maps NSAPI to internal context number |
| `sm_check_if_a_valid_2G_llc_sapi` | 0x9136d594 | L3 NAS | SM | Validates a 2G LLC SAPI for a context |
| `sm_compose_tcm_activate_sec_ind_msg` | 0x9136dfb8 | L3 NAS | SM | Signals data-plane to activate a secondary context |

---

## Accuracy notes

- Behavior for `FDD_reasm_start_compose_llc_pdu`, `FDD_acs_decode_ia_rest_octets_for_tbf`, and
  `FDD_si_decode_si3rest_octets` was confirmed by decompilation (bit-stream reads / block reassembly);
  the rest are described from their symbol names and are labelled by their evident role.
- `FDD_rmc_*` (751) is the largest 2G group but is RR mobility/measurement, **not** RLC/MAC data —
  the true GPRS L2 data path is `FDD_mac_*` + `FDD_rlc_*` + `FDD_reasm_*`.
- `csn`, `psi`, `cb_`, `sms`, `gmm` as bare substrings over-match into 3G/4G/5G symbols; use the
  narrowed anchors (`^[Cc]sn`, `FDD_psi`, `smsal_cb_`, `smsal_`, `^gmm_`) for accurate 2G counts.
