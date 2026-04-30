import json
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4

from rbac import RBACManager
from qos_manager import QoSManager
from policy import RBAC_POLICY, QOS_PROFILES


class RBACQoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    SESSION_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "sessions.json"))

    def __init__(self, *args, **kwargs):
        super(RBACQoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.rbac_manager = RBACManager(RBAC_POLICY)
        self.qos_manager = QoSManager(QOS_PROFILES)

    def load_sessions(self):
        try:
            with open(self.SESSION_FILE, "r") as f:
                data = json.load(f)
        except Exception as e:
            self.logger.error("Failed to load sessions.json: %s", e)
            return {}

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

    def find_session_by_ip(self, src_ip):
        sessions = self.load_sessions()
        for session_id, meta in sessions.items():
            if meta.get("client_ip") == src_ip:
                return session_id, meta
        return None, None

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = {
            "datapath": datapath,
            "priority": priority,
            "match": match,
            "instructions": inst,
        }

        if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
            kwargs["buffer_id"] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if eth is None:
            return

        if eth.ethertype == 0x88CC:
            return

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        src = eth.src
        dst = eth.dst
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        if ip_pkt is None:
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

            data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=data,
            )
            datapath.send_msg(out)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        session_id, session_meta = self.find_session_by_ip(src_ip)
        if session_id is None:
            self.logger.warning("Drop unauthenticated traffic: %s -> %s", src_ip, dst_ip)
            return

        role = session_meta.get("role", "least")
        user_id = session_meta.get("user_id", "unknown")
        queue_id = self.qos_manager.get_queue_id(role)

        self.logger.info(
            "Authenticated session=%s user=%s role=%s src_ip=%s dst_ip=%s queue_id=%s",
            session_id, user_id, role, src_ip, dst_ip, queue_id
        )

        actions = []
        if out_port != ofproto.OFPP_FLOOD:
            actions.append(parser.OFPActionSetQueue(queue_id))
            actions.append(parser.OFPActionOutput(out_port))
        else:
            actions.append(parser.OFPActionOutput(out_port))

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip,
            ipv4_dst=dst_ip,
            eth_src=src
        )
        self.add_flow(datapath, 1, match, actions)

        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out)
