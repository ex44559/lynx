from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3


class LynxSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __int__(self, *args, **kwargs):
        super(LynxSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

