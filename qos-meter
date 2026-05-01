import json
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4

from rbac import RBACManager
from policy import RBAC_POLICY, QOS_PROFILES


class AuthQoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AuthQoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))

        self.rbac_manager = RBACManager(RBAC_POLICY)
        self.qos_profiles = QOS_PROFILES
        self.meter_cache = {}   # role -> meter_id
        self.meter_installed = set()

    def _load_json_file(self, filename, default):
        file_path = os.path.join(self.base_dir, filename)
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            self.logger.error("File not found: %s", filename)
            return default
        except Exception as e:
            self.logger.error("Error reading %s: %s", filename, e)
            return default

        return data if isinstance(data, dict) else default

    def _load_sessions(self):
        data = self._load_json_file("sessions.json", {})
        sessions = data.get("sessions", {})
        if not isinstance(sessions, dict):
            return {}

        now = time.time()
        active = {}
        for session_id, meta in sessions.items():
            try:
                expires_at = float(meta.get("expires_at", 0))
                if now < expires_at:
                    active[session_id] = meta
            except (TypeError, ValueError, AttributeError):
                continue
        return active

    def _find_session_by_ip(self, ip_addr):
        sessions = self._load_sessions()
        for session_id, meta in sessions.items():
            try:
                if meta.get("client_ip") == ip_addr:
                    return session_id, meta
            except AttributeError:
                continue
        return None, None

    def _get_meter_id_for_role(self, role):
        # stable small IDs
        mapping = {
            "admin": 1,
            "normal": 2,
            "least": 3,
            "guest": 3,
        }
        return mapping.get(role, 3)

    def _get_qos_profile(self, role):
        # expects QOS_PROFILES like:
        # {"admin": {"rate": 100000000, "burst": 1000000}, ...}
        default = {"rate": 1000000, "burst": 100000}
        return self.qos_profiles.get(role, default)

    def _add_meter(self, datapath, meter_id, rate, burst):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        bands = [
            parser.OFPMeterBandDrop(rate=rate, burst_size=burst)
        ]
        req = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS | ofproto.OFPMF_BURST,
            meter_id=meter_id,
            bands=bands,
        )
        datapath.send_msg(req)
        self.logger.info(
            "METER ADD: dpid=%s meter_id=%s rate=%s burst=%s",
            datapath.id, meter_id, rate, burst
        )

    def _ensure_meter(self, datapath, role):
        meter_id = self._get_meter_id_for_role(role)
        if meter_id in self.meter_installed:
            return meter_id

        profile = self._get_qos_profile(role)
        rate = int(profile.get("rate", 1000000))
        burst = int(profile.get("burst", max(rate // 10, 10000)))

        self._add_meter(datapath, meter_id, rate, burst)
        self.meter_installed.add(meter_id)
        return meter_id

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("Installed table-miss flow on datapath=%s", datapath.id)

    def add_flow(self, datapath, priority, match, actions=None, instructions=None,
                 buffer_id=None, hard_timeout=None, idle_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if instructions is None:
            if actions is None:
                actions = []
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow_kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": instructions,
        }

        if hard_timeout is not None:
            flow_kwargs["hard_timeout"] = hard_timeout
        if idle_timeout is not None:
            flow_kwargs["idle_timeout"] = idle_timeout
        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            flow_kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**flow_kwargs)
        datapath.send_msg(mod)

    def _send_packet_out(self, datapath, msg, parser, ofproto, in_port, actions):
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, 0x88CC):
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src_mac = eth.src
        dst_mac = eth.dst
        self.mac_to_port[dpid][src_mac] = in_port

        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Non-IP traffic
        if ip_pkt is None:
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src_mac,
                    eth_dst=dst_mac,
                    eth_type=eth.ethertype,
                )
                self.add_flow(
                    datapath=datapath,
                    priority=1,
                    match=match,
                    actions=actions,
                    buffer_id=msg.buffer_id,
                    idle_timeout=15,
                )
            self._send_packet_out(datapath, msg, parser, ofproto, in_port, actions)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        session_id, session_meta = self._find_session_by_ip(src_ip)

        # Allow reply/non-session traffic
        if session_id is None:
            self.logger.info(
                "ALLOW NON-SESSION OR REPLY: src_ip=%s dst_ip=%s in_port=%s out_port=%s",
                src_ip, dst_ip, in_port, out_port
            )
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                )
                self.add_flow(
                    datapath=datapath,
                    priority=5,
                    match=match,
                    actions=actions,
                    buffer_id=msg.buffer_id,
                    idle_timeout=20,
                )
            self._send_packet_out(datapath, msg, parser, ofproto, in_port, actions)
            return

        role = session_meta.get("role", "least")
        user_id = session_meta.get("user_id", "unknown")
        meter_id = self._ensure_meter(datapath, role)

        self.logger.info(
            "AUTHORIZED: session=%s user=%s role=%s src_ip=%s dst_ip=%s meter_id=%s out_port=%s",
            session_id, user_id, role, src_ip, dst_ip, meter_id, out_port
        )

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_type=0x0800,
                ipv4_src=src_ip,
                ipv4_dst=dst_ip,
            )

            # Meter instruction + output action
            inst = [
                parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER),
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(out_port)]
                )
            ]

            self.logger.info(
                "INSTALL FLOW WITH METER: dpid=%s in_port=%s src_ip=%s dst_ip=%s meter_id=%s out_port=%s",
                dpid, in_port, src_ip, dst_ip, meter_id, out_port
            )

            self.add_flow(
                datapath=datapath,
                priority=10,
                match=match,
                instructions=inst,
                buffer_id=msg.buffer_id,
                hard_timeout=60,
                idle_timeout=30,
            )

        actions = [parser.OFPActionOutput(out_port)]
        self._send_packet_out(datapath, msg, parser, ofproto, in_port, actions)
