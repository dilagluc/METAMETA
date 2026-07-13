# 5G (NR + 5G NAS) — function catalog

RAT: **5G** — NR (New Radio) access stratum + 5G NAS (5GMM / 5GSM). Source DB: Huawei
`MD1IMG_22.img` → `000_md1rom`, symbolized. All counts below come from the idaq query
server (port 8799):

```
source /workspace/.venv-ida/bin/activate
python /workspace/idaq search "<python-regex>" <limit>
python /workspace/idaq decompile "<name|0xaddr>"
python /workspace/idaq xrefs "<name|0xaddr>"
```

## Naming conventions discovered

| Prefix | Meaning |
|--------|---------|
| `nl1_*` / `NL1_*` | NR L1 (PHY) — Huawei NR layer-1 firmware. Sub-modules: `nl1_ctrl` (control), `nl1_mpc`, `nl1_rx`/`nl1_tx` (rx/tx chains), `nl1_rfcc`/`nl1_rfd` (RF), `nl1_idc` (in-device coex), `nl1_tpc` (power control) |
| `NL1_CTRL_Nrrc_*` / `nl1_ctrl_nrrc_*` | L1↔RRC glue for **SI (system information) reassembly** and BCCH/paging indications |
| `nmac_*` | NR MAC (L2) |
| `nrlc_*` (`nrlcul_`/`nrlcdl_`) | NR RLC (L2), UL/DL |
| `npdcp_*` | NR PDCP (L2) |
| `sdap_*` / `el2icd_sdap_*` / `enpdcp_*sdap*` | NR SDAP (L2, 5G-only sublayer) |
| `nrrc_*` / `Nrrc_*` | NR RRC (L3 access stratum) |
| `AsnDecode_NR_*` | NR RRC ASN.1 (UPER) decoders |
| `nrrc_asn1_decode` / `nrrc_asn1_encode` | the RRC ASN.1 dispatcher (routes a message-type code to the right top-level decoder) |
| `vgmm_*` | 5G NAS **5GMM** (Mobility Management) — the "v" = 5G/NR NAS-MM |
| `vgsm_*` | 5G NAS **5GSM** (Session Management) |

Note: NR L2 uses its own `n`-prefixed family (`nmac`/`nrlc`/`npdcp`), **distinct** from the LTE
`erlc`/`epdcp` family — but the two interwork (e.g. `npdcp_erlc_dl_offline_pits_handler`,
EN-DC / NR-DC split-bearer paths). SDAP is genuinely NR-only (introduced in 5G) and is small.

---

## L1 / PHY — NR layer 1

The PHY is the radio: it turns bits into OFDM symbols and back, does beam management, RF control,
and cell/SSB acquisition. In this DB it is a very large firmware body under `nl1_*`. The part that
matters for higher layers is `nl1_ctrl` (L1 control) — and specifically the `NL1_CTRL_Nrrc_*`
glue that hands **raw broadcast (SI) octets** up to NR RRC and reassembles multi-segment SI.

Regexes and counts:

| Regex | Count | Note |
|-------|-------|------|
| `^nl1` | 5920 | all NR L1 functions |
| `^nl1_ctrl` (== `NL1_CTRL`) | 852 | L1 control sub-module (890 incl. `j_` thunks) |
| `nl1_mpc` | 332 | modem processing / measurement |
| `nl1_rx` | 277 | receive chain |
| `nl1_tx` | 74 | transmit chain |
| `nl1_idc` | 17 | in-device coexistence |
| `NL1_CTRL_Nrrc_` / `nl1_ctrl_nrrc_` | ~15 | SI reassembly + BCCH/paging glue to RRC |

Representative functions:

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `NL1_CTRL_Nrrc_Reconstruct_Raw_Data` | 0x90ee9e26 | L1 | PHY→RRC SI glue | reassembles segmented SI raw octets (memcpy of partial-control-info parts) before handing to RRC |
| `NL1_CTRL_Nrrc_Read_Broadcast_Buffer_SI_Raw_data` | — | L1 | PHY→RRC SI glue | reads raw BCCH broadcast octets out of the L1 buffer |
| `NL1_CTRL_Nrrc_Check_Raw_Data_SI_Type` | — | L1 | PHY→RRC SI glue | classifies the SI type of a raw broadcast block |
| `nl1_ctrl_nrrc_send_bcch_mod_ind_with_sim_idx` | — | L1 | PHY→RRC | signals RRC that BCCH (SI) has changed |
| `nl1_ctrl_nrrc_send_paging_ind_with_sim_idx` | — | L1 | PHY→RRC | delivers paging indication to RRC |
| `nl1_ctrl_bcch_start_mib_event` | — | L1 | PHY BCCH | schedules MIB reception |
| `nl1_ctrl_bcch_start_sib1_event` | — | L1 | PHY BCCH | schedules SIB1 reception |
| `nl1_ctrl_bcch_rmsi_pre_calculation` | — | L1 | PHY BCCH | pre-computes RMSI (remaining minimum SI) scheduling |
| `nl1_ctrl_xbcch_get_kssb_from_mib` | — | L1 | PHY BCCH | extracts k_SSB from MIB |
| `nl1_ctrl_idc_bwp_updt` | — | L1 | PHY IDC | updates bandwidth-part on in-device-coex event |
| `nl1_ctrl_idc_drx_config_updt` | 0x90d18aa4 | L1 | PHY IDC | updates DRX config for coexistence |

---

## L2 — NR MAC / RLC / PDCP / SDAP

L2 sits between PHY and RRC. **MAC** multiplexes logical channels, builds transport blocks, does
HARQ and buffer-status reporting (BSR). **RLC** does segmentation/reassembly and ARQ (AM/UM
modes). **PDCP** does ciphering/deciphering, integrity, header (de)compression and reordering.
**SDAP** (new in 5G) maps QoS flows to data radio bearers.

Regexes and counts:

| Regex | Count | Sublayer |
|-------|-------|----------|
| `^nmac` | 384 | NR MAC |
| `^nrlc` | 381 | NR RLC (`nrlcul_`/`nrlcdl_`) |
| `^npdcp` | 388 | NR PDCP |
| `sdap` | 27 | NR SDAP (shares `el2icd_`/`enpdcp_` helpers) |
| `erlc` / `epdcp` | 255 / 77 | LTE RLC/PDCP — separate family, but interworks with NR for EN-DC/NR-DC |

Representative functions:

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `nmac_bsr_generation` | — | L2 | MAC | builds a Buffer Status Report MAC CE |
| `nmac_bsr_sr_trigger_check` | — | L2 | MAC | decides whether to trigger a scheduling request |
| `nmac_nl2_read_rlc_bsr_sz` | — | L2 | MAC | reads pending RLC bytes for BSR sizing |
| `nmac_config_ml1s_test_mode_config` | — | L2 | MAC | configures MAC for L1 test mode |
| `nrlcul_serve_rb_am` | — | L2 | RLC (UL) | serves an Acknowledged-Mode radio bearer (build PDU) |
| `nrlcul_serve_rb_um` | — | L2 | RLC (UL) | serves an Unacknowledged-Mode radio bearer |
| `nrlcul_serve_status_pdu` | — | L2 | RLC (UL) | builds an RLC STATUS PDU (ARQ ack/nack) |
| `nrlcul_segment_status_pdu` | — | L2 | RLC (UL) | segments a status PDU to fit the grant |
| `nrlcul_serve_retx_pdu` | — | L2 | RLC (UL) | retransmits a NACKed PDU segment |
| `npdcp_dl_data_ind_handler` | — | L2 | PDCP (DL) | handles a DL PDCP data indication |
| `npdcp_dl_decipher_vrb_va_shortage_hndlr` | — | L2 | PDCP (DL) | deciphering path under virtual-address shortage |
| `npdcp_decipher_done_callback` | — | L2 | PDCP (DL) | callback after HW deciphering completes |
| `npdcp_dl_oow_sn_desync_check` | — | L2 | PDCP (DL) | out-of-window / SN-desync robustness check |
| `npdcp_proc_5g_ctrl_pdu` | — | L2 | PDCP | processes a PDCP control PDU (e.g. ROHC/status) |
| `npdcp_erlc_dl_offline_pits_handler` | — | L2 | PDCP (EN-DC) | NR PDCP over LTE RLC split-bearer path |
| `sdap_ulproc_data_req_handler` | — | L2 | SDAP (UL) | UL SDAP handling — QoS-flow to DRB |
| `sdap_clear_qos_flow_to_drb` | — | L2 | SDAP | tears down a QoS-flow→DRB mapping |
| `sdap_end_marker_bitmap_process` | — | L2 | SDAP | processes end-marker bitmap on flow move |
| `enpdcp_ulproc_send_sdap_end_marker` | — | L2 | SDAP | emits an SDAP end-marker control PDU |
| `_exec_drb_sdap_cfg` | — | L2 | SDAP | applies an SDAP DRB configuration |

---

## L3 — NR RRC (access stratum)

RRC is the control plane of the radio: cell selection/reselection, SI acquisition, connection
setup/reconfig, measurement config/reporting, security activation. It is the largest single L3
body here (`nrrc_*`, ~2664 anchored functions; 3191 including callers/thunks). Below it sits a
set of ~108 `AsnDecode_NR_*` ASN.1 (UPER) decoders — one per RRC IE / message type.

Regexes and counts:

| Regex | Count | What |
|-------|-------|------|
| `^[Nn]rrc` | 2664 | all NR RRC functions (`nrrc`/`Nrrc`) |
| `AsnDecode_NR_` | 108 | NR RRC ASN.1 decoders (per-IE + top-level messages) |
| `nrrc_asn1` | 9 | the ASN.1 decode/encode dispatcher family |
| `nrrc_bg` | 178 | RRC "background" tasks incl. SI receive (`nrrc_bg_sircv_*`) |
| `AsnDecode_NR_SIB` / `AsnDecode_NR_BCCH` | 2 / 2 | SIB1 + BCCH-BCH/BCCH-DL-SCH message decoders |
| `AsnDecode_NR_PCCH` / `AsnDecode_NR_Paging` | 1 / 1 | paging channel decode |
| `Nrrc_Reconstruct` / `Nrrc_Check_Raw` / `Nrrc_Read_Broadcast` | 1 / 1 / 1 | SI reassembly glue (in L1 module, see above) |

`nrrc_functional groups`: `nrrc_config` (562), `nrrc_idle` (320), `nrrc_nconn` (303, "NR
connected"), `nrrc_search` (292), `nrrc_main` (291), `nrrc_si` (233), `nrrc_bg` (167),
`nrrc_meas` (137), `nrrc_scg` (123, secondary cell group / dual-connectivity).

The dispatcher `nrrc_asn1_decode` switches on a one-char message-type code and calls the matching
top-level decoder (verified by decompile):

```
case 'd': AsnDecode_NR_DL_DCCH_Message(...)      // dedicated DL control
case 'm': AsnDecode_NR_BCCH_BCH_Message(...)     // MIB
case 'n': AsnDecode_NR_BCCH_DL_SCH_Message(...)  // SIB / SI
case 'o': AsnDecode_NR_DL_CCCH_Message(...)      // common DL control
case 'p': AsnDecode_NR_PCCH_Message(...)         // paging
case 'g': AsnDecode_NR_RRCReconfiguration_Extern(...)
case 'i': AsnDecode_NR_RadioBearerConfig_Extern(...)
```

Representative functions:

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `nrrc_asn1_decode` | 0x910763ac | L3 | RRC dispatcher | routes a raw RRC message to the right top-level ASN.1 decoder by type code |
| `nrrc_asn1_encode` | — | L3 | RRC dispatcher | encode side (UL RRC messages) |
| `AsnDecode_NR_BCCH_BCH_Message` | — | L3 | RRC / MIB | decodes the MIB (BCCH-BCH) |
| `AsnDecode_NR_BCCH_DL_SCH_Message` | — | L3 | RRC / SI | decodes SIB container (BCCH-DL-SCH) |
| `AsnDecode_NR_SIB1` | 0x9105af5e | L3 | RRC / SIB1 | decodes SIB1 (cell-access + scheduling info) |
| `AsnDecode_NR_PCCH_Message` | — | L3 | RRC / paging | decodes the paging (PCCH) message |
| `AsnDecode_NR_DL_DCCH_Message` | — | L3 | RRC | decodes dedicated DL control (reconfig, security-mode, etc.) |
| `AsnDecode_NR_RRCReconfiguration_criticalExtensions` | — | L3 | RRC | decodes RRCReconfiguration body |
| `AsnDecode_NR_RadioBearerConfig` | — | L3 | RRC | decodes SRB/DRB radio-bearer config (PDCP/SDAP params) |
| `AsnDecode_NR_CellGroupConfig` | — | L3 | RRC | decodes MAC/RLC/logical-channel cell-group config |
| `AsnDecode_NR_MeasConfig` | — | L3 | RRC | decodes measurement configuration |
| `AsnDecode_NR_SecurityAlgorithmConfig` | — | L3 | RRC / security | decodes AS ciphering/integrity algorithm choice |
| `AsnDecode_NR_ServingCellConfigCommon` | — | L3 | RRC | decodes common serving-cell config (PRACH, TDD pattern…) |
| `AsnDecode_NR_UAC_BarringPerCatList` | — | L3 | RRC / access-control | decodes unified access-control barring per category |
| `AsnDecode_NR_DedicatedNAS_Message` | — | L3 | RRC→NAS | extracts the piggybacked NAS PDU from an RRC message |
| `nrrc_bg_sircv_activate_essential_si` | — | L3 | RRC / SI acquisition | activates reception of essential SIBs |
| `nrrc_bg_sircv_bcch_cnf_handler` | — | L3 | RRC / SI acquisition | handles L1 BCCH-read confirmation |

---

## L3 — 5G NAS (5GMM + 5GSM)

NAS is the non-access-stratum control plane exchanged directly with the core network (AMF/SMF),
tunnelled inside RRC. **5GMM** (`vgmm_`, 765 fns) does registration, deregistration, identity,
authentication (5G-AKA + EAP-AKA'), security-mode, service request, and configuration-update
handling (NSSAI, TAI lists, LADN, emergency numbers, access categories). **5GSM** (`vgsm_`,
591 fns) does PDU-session establishment/modification/release and QoS.

Regexes and counts:

| Regex | Count | Sublayer |
|-------|-------|----------|
| `^vgmm_` | 765 | 5GMM |
| `^vgsm_` | 591 | 5GSM |
| `vgmm_sec` | 54 | NAS security (integrity/cipher of NAS PDUs) |
| `vgmm_auth` | 29 | authentication (5G-AKA / EAP-AKA') |
| `vgmm_nssai` | 29 | NSSAI (network-slice selection) |
| `vgmm_uac` | 21 | unified access control |
| `vgmm_reg` | 12 | registration-state handlers (plus `vgmm_registered_*`/`vgmm_dereg*`) |
| `vgmm_decode` | 8 | NAS IE decoders |
| `vgsm_pdu` | 18 | PDU-session message handlers |

The IE decoders (`vgmm_decode_*`) and the message unpack/build glue:

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `vgmm_peer_msg_unpack_handler` | — | L3 | 5GMM codec | top-level unpack of a received 5GMM NAS message |
| `vgmm_construct_nasmsg_struct` | — | L3 | 5GMM codec | builds an outgoing 5GMM NAS message structure |
| `vgmm_encode_struct` | — | L3 | 5GMM codec | encodes a 5GMM message to octets |
| `vgmm_decode_tai_list` | 0x9187ae34 | L3 | 5GMM IE | decodes the TAI (tracking-area identity) list IE |
| `vgmm_decode_ladn_info` | — | L3 | 5GMM IE | decodes LADN (local-area data network) info |
| `vgmm_decode_emergency_number_list` | — | L3 | 5GMM IE | decodes the emergency-number list IE |
| `vgmm_decode_service_area_list` | — | L3 | 5GMM IE | decodes the service-area (allowed/non-allowed TAs) list |
| `vgmm_decode_op_def_access_category_definitions` | — | L3 | 5GMM IE | decodes operator-defined access-category definitions |
| `vgmm_decode_intra_n1_mode_transparent_container` | — | L3 | 5GMM IE | decodes the intra-N1-mode NAS transparent container |
| `vgmm_encode_last_visited_registered_tai` | — | L3 | 5GMM IE | encodes last-visited registered TAI |
| `vgmm_encode_ue_security_capability` | — | L3 | 5GMM IE | encodes UE security capabilities |

5GMM procedures (state machines):

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `vgmm_deregistered_initial_reg_needed` | — | L3 | 5GMM registration | dereg-state entry that triggers initial registration |
| `vgmm_registered_attempting_registration_update` | — | L3 | 5GMM registration | mobility/periodic registration-update handling |
| `vgmm_dereg_attreg_t3511_expiry_ind` | — | L3 | 5GMM registration | T3511 retry timer on failed registration |
| `vgmm_auth_handle_authentication_request` | — | L3 | 5GMM auth | processes an AUTHENTICATION REQUEST (5G-AKA) |
| `vgmm_auth_handle_eap_aka_failure` | — | L3 | 5GMM auth | handles EAP-AKA' authentication failure |
| `vgmm_auth_validate_authentication_reject` | — | L3 | 5GMM auth | validates AUTHENTICATION REJECT |
| `vgmm_auth_suci_ind_received` | — | L3 | 5GMM identity | handles SUCI (concealed identity) indication |
| `vgmm_identity_handle_identity_request` | — | L3 | 5GMM identity | responds to IDENTITY REQUEST (SUCI/5G-GUTI) |
| `vgmm_auth_security_mode_command_received` | — | L3 | 5GMM security | processes SECURITY MODE COMMAND |
| `vgmm_as_access_rcv_security_msg` | — | L3 | 5GMM security | receives an integrity/cipher-protected NAS PDU |
| `vgmm_as_access_security_protect_nas_pdu` | — | L3 | 5GMM security | applies NAS integrity/ciphering to an outgoing PDU |
| `vgmm_uac_derive_access_category` | — | L3 | 5GMM access-ctrl | derives the access category for a request (UAC) |

5GSM procedures:

| function | addr | layer | protocol/sublayer | what it does |
|----------|------|-------|-------------------|--------------|
| `vgsm_decode_peer_msg` | — | L3 | 5GSM codec | decodes a received 5GSM NAS message |
| `vgsm_unpack_message_header` | — | L3 | 5GSM codec | unpacks the 5GSM message header (PDU session id, PTI, type) |
| `vgsm_pdu_session_est_req_handler` | — | L3 | 5GSM | handles PDU SESSION ESTABLISHMENT REQUEST |
| `vgsm_pdu_session_establishment_accept_handler` | — | L3 | 5GSM | processes PDU SESSION ESTABLISHMENT ACCEPT |
| `vgsm_pdu_session_modification_command_handler` | — | L3 | 5GSM | processes PDU SESSION MODIFICATION COMMAND |
| `vgsm_pdu_session_release_command_handler` | — | L3 | 5GSM | processes PDU SESSION RELEASE COMMAND |
| `vgsm_pdu_session_authentication_command_handler` | — | L3 | 5GSM | handles PDU-session-level authentication (secondary auth) |

---

### Sampling notes (decompiles verified)

- `NL1_CTRL_Nrrc_Reconstruct_Raw_Data` (0x90ee9e26): loops over N SI segments, `memcpy`-ing each
  segment body out of the L1 buffer into a contiguous output — confirming it is the multi-segment
  SI reassembler feeding RRC.
- `nrrc_asn1_decode` (0x910763ac): a clean `switch` on a message-type char dispatching to
  `AsnDecode_NR_*` top-level decoders (MIB/SIB/CCCH/DCCH/PCCH/reconfig/bearer-config) — the single
  entry point for parsing received RRC messages, and a prime attack-surface target.
- `vgmm_decode_tai_list` (0x9187ae34) and `AsnDecode_NR_SIB1` (0x9105af5e): both are byte-level
  bit-unpacking parsers over attacker-influenced OTA input (NAS TAI list; broadcast SIB1) — good
  fuzz / manual-audit candidates.
