from scapy.all import Raw

class RawWlskPingPacket:
    """
        Object to store packets parsed by sniffing the interface
        Can represent either an outgoing or an incoming ping.
        self.successfully_parsed is set to true if it is a valid WLSK ping
    """
    def __init__(self, raw_packet = None):
        self.channel = 0
        self.index = 0
        self.timestamp = 0
        self.raw_data = None
        self.successfully_parsed = False
        if raw_packet is not None:
            self.parse(raw_packet)

    def parse(self, packet):
        if packet.haslayer(Raw) and packet[Raw].load.decode()[0:4] == "wlsk":
            try:
                payload_params = packet[Raw].load.decode().split("_")
                # print(payload_params)
                self.channel = int(payload_params[1])
                self.index = int(payload_params[2])
                self.timestamp = packet.time
                self.raw_data = packet

                self.successfully_parsed = True
            except:
                print("Error Parsing Ping: {}".format(packet[Raw].load.decode()))