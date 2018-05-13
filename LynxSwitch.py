from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller import ofp_event
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.services.protocols.ovsdb import event as ovsdb_event
from ryu.services.protocols.ovsdb import api as ovsdb


class LynxSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LynxSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(ovsdb_event.EventNewOVSDBConnection)
    def handle_new_ovsdb_connection(self, ev):
        system_id = ev.system_id
        address = ev.client.address
        self.logger.info(
            'New OVSDB connection from system-id=%s, address=%s',
            system_id, address)

        self.logger.info("==========read dataReport table==================")
        self.logger.info("ConfigError \t false")
        self.logger.info("ErrorMessage")
        self.logger.info("isAlbMode \t true")
        self.logger.info("setProcessSuccess \t true")
        self.logger.info("======= read dataReport table done.==============")

        self.logger.info("not fall-back Mode.")

        self.logger.info("not User Config Mode.")

        self.logger.info("==========read HardwareInfo table================")
        hardware_info = {}
        hardware_info_table = ovsdb.get_table(self, system_id, 'HardwareInfo')
        for row in hardware_info_table.rows.values():
            hardware_info['CPUPerNumaNode'] = row.CPUPerNumaNode
            self.logger.info("CPUPerNumaNode \t %d" % hardware_info['CPUPerNumaNode'])

            hardware_info['CPUType'] = row.CPUType
            self.logger.info("CPUType \t %s" % hardware_info['CPUType'])

            hardware_info['CorePerNumaNode'] = row.CorePerNumaNode
            self.logger.info("CorePerNumaNode \t %d" % hardware_info['CorePerNumaNode'])

            hardware_info['MemoryPerNumaNode'] = row.MemoryPerNumaNode
            self.logger.info("MemoryPerNumaNode \t %d" % hardware_info['MemoryPerNumaNode'])

            hardware_info['NumaNodeNum'] = row.NumaNodeNum
            self.logger.info("NumaNodeNum \t %d" % hardware_info['NumaNodeNum'])
        self.logger.info("======= read HardwareInfo table done.===========")

        self.logger.info("==========read NetdevInfo table===================")
        netdev_info = []
        netdev_info_table = ovsdb.get_table(self, system_id, 'NetdevInfo')
        i = 0
        for row in netdev_info_table.rows.values():
            i += 1
            netdev_info_row = {}
            self.logger.info("netdev %d" % i)
            netdev_info_row['Driver'] = row.Driver
            self.logger.info("Driver \t %s" % netdev_info_row['Driver'])
            netdev_info_row['isUserSpace'] = row.isUserSpace
            self.logger.info("IsUserSpace \t %d" % netdev_info_row['isUserSpace'])
            netdev_info_row['NumaNode'] = row.NumaNode
            self.logger.info("NumaNode \t %d" % netdev_info_row['NumaNode'])
            netdev_info_row['Speed'] = row.Speed
            self.logger.info("Speed \t %s" % netdev_info_row['Speed'])
            netdev_info_row['Type'] = row.Type
            self.logger.info("Type \t %s" % netdev_info_row['Type'])
            netdev_info_row['ports'] = row.ports
            self.logger.info("ports \t %s" % netdev_info_row['ports'])
            netdev_info.append(netdev_info_row)
        self.logger.info("======= read Netdev table done.===========")

        self.logger.info("choose Normal NUMA mode.")
        self.logger.info("choose ALB-bonding mode.")

        self.logger.info("configuration is sent.")
