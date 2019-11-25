import pyshark
import datetime

class pcapHandler:
    def __init__(self,file):
        self.auxArray = []
        self.file = file
        
    ## Add all packets to the object's array    
    def appendPackets(self,*args):
        self.auxArray.append(args[0])
        
    ## Iterate all packets in a pcap
    def iteratePcap(self):
        cap = pyshark.FileCapture(self.file, only_summaries=True)
        cap.apply_on_packets(self.appendPackets, timeout=10000)
        return True
    
    ## Get basic information of a packet
    def getPacket(self,index):
        pkt = self.auxArray[index]
        print('Source IP:', pkt.source,'Destination IP:', pkt.destination, 'Protocol', pkt.protocol)
        print('Payload:', pkt.info)
        return True
    
    ## Find any string in the payload of the packets
    def findString(self,keyword):
        for packet in self.auxArray:
            if keyword in packet.info:
                print(packet.no,packet.info)
            else:
                pass
        return True


if __name__ == '__main__':
    start = datetime.datetime.now() ## set start time to review performance
    handler = pcapHandler('<FILENAME>') ## Set pcap file to examine
    handler.iteratePcap() ## interate all packets in a pcap
##    index = 0
##    while index < len(handler.auxArray):
####        handler.getPacket(index) ## read each packet
##        index +=1
    handler.findString('<STRINGTOFIND>') ## find a specific string in all packets
    end = datetime.datetime.now() ## set end time to review performance
    print(end-start)
