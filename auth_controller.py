import json
import os
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4


class AuthController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(AuthController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.session_file = os.path.join(self.base_dir, "sessions.json")

    def _load_json_file(self, filename, default):
        file_path = os.path.join(self.base_dir, filename)
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            return default
        except Exception as e:
            self.logger.error("Error reading %s: %s", filename, e)
            return default

        return data if isinstance(data, dict) else default

    def _load_sessions(self):
        data = self._load_json_file("sessions.json", {})
        sessions = data.get("sessions", {})
        return sessions if isinstance(sessions, dict) else {}

    def _find_session_by_ip(self, ip_addr):
        sessions = self._load_sessions()
        now = time.time()
        for session_id, meta in sessions.items():
            try:
                if meta.get("client_ip") == ip_addr and now < float(meta.get("expires_at", 0)):
                    return session_id, meta
            except (TypeError, ValueError, AttributeError):
                continue
        return None, None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None, idle_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst,
        }

        if hard_timeout is not None:
            flow_kwargs["hard_timeout"] = hard_timeout

        if idle_timeout is not None:
            flow_kwargs["idle_timeout"] = idle_timeout

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            flow_kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**flow_kwargs)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst_mac = eth.dst
        src_mac = eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src_mac] = in_port

        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        session_active = False

        if pkt_ipv4:
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst
            session_id, session_meta = self._find_session_by_ip(src_ip)

            if session_id is None:
                self.logger.info("UNAUTHORIZED: %s -> %s no active session.", src_ip, dst_ip)
                return

            session_active = True
            self.logger.info(
                "AUTHORIZED: session=%s user=%s role=%s src=%s -> %s",
                session_id,
                session_meta.get("user_id"),
                session_meta.get("role"),
                src_ip,
                dst_ip,
            )

        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if pkt_ipv4:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=pkt_ipv4.src,
                    ipv4_dst=pkt_ipv4.dst,
                    eth_dst=dst_mac,
                    eth_src=src_mac,
                )
                flow_hard_timeout = 60 if session_active else None
                flow_idle_timeout = 30
                self.add_flow(
                    datapath,
                    1,
                    match,
                    actions,
                    msg.buffer_id,
                    hard_timeout=flow_hard_timeout,
                    idle_timeout=flow_idle_timeout,
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=eth.ethertype,
                    eth_dst=dst_mac,
                    eth_src=src_mac,
                )
                self.add_flow(
                    datapath,
                    1,
                    match,
                    actions,
                    msg.buffer_id,
                    idle_timeout=15,
                )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
