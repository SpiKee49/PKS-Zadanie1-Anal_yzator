import json
from scapy.all import *
from binascii import *
import ruamel.yaml
import math
import argparse

# -------------------FUNCTIONS-------------------


def getFrameType(hex):
    if (int(hex[12]+hex[13], 16) >= 1536):
        return 'ETHERNET II'

    if ((hex[14]+hex[15]) == 'ffff'):
        return 'IEEE 802.3 RAW'

    if ((hex[14]+hex[15]) == 'aaaa'):
        return 'IEEE 802.3 LLC & SNAP'
    else:
        return 'IEEE 802.3 LLC'


def formatAddress(address):
    mac = ':'.join(address).upper()
    return ruamel.yaml.scalarstring.DoubleQuotedScalarString(mac)


def getEtherType(hex):
    file = open("./protocols/ethernet-protocols.json", "r")
    ether_types = json.load(file)

    try:
        return ether_types[hex]
    except:
        return 'unknown'


def getIp(hex):
    ip_parts = []

    for i in hex:
        ip_parts.append(str(int(i, 16)))

    return '.'.join(ip_parts)


def getIpProtocol(dec):
    file = open("./protocols/ipv4-protocols.json", "r")
    protocols = json.load(file)
    try:
        return protocols[str(dec)]
    except:
        return 'null'


def getArpOp(dec):
    arp_codes = {
        1: 'REQUEST',
        2: 'REPLY'
    }
    return arp_codes[dec]


def getAppProtocol(dec, protocol):

    if 'UDP' in protocol:
        udp = open("./protocols/udp-protocols.json")
        udp_ports = json.load(udp)
        try:
            return udp_ports[str(dec)]
        except:
            return False
    elif 'TCP' in protocol:
        tcp = open("./protocols/tcp-protocols.json")
        tcp_ports = json.load(tcp)
        try:
            return tcp_ports[str(dec)]
        except:
            return False
    else:
        return False


def getSap(hex):
    sap = open("./protocols/saps.json")
    saps = json.load(sap)

    return saps[hex]


def getPid(hex):
    pids = {
        '2000': 'CDP',
        '2004': 'DTP',
        '010b': 'PVSTP+',
        '809b': 'AppleTalk',
    }

    return pids[hex]


def analyzeArp(packets):
    complete_comms = []
    partial_comms = []
    passed_frame_numbers = []
    arp_packets = list(
        filter(lambda packet: packet['ether_type'] == 'ARP', packets))
    # get only ARP packets

    for packet1 in arp_packets:

        for packet2 in arp_packets:
            if packet1['frame_number'] == packet2['frame_number']:
                continue

            if packet1['arp_opcode'] == 'REQUEST' and packet2['arp_opcode'] == 'REPLY' and packet1['dst_ip'] == packet2['src_ip'] and packet2['dst_ip'] == packet1['src_ip']:
                comm = {}
                if len(complete_comms) == 0:
                    comm['number_comm'] = 1
                    comm['src_comm'] = packet1["src_ip"]
                    comm['dst_comm'] = packet1["dst_ip"]
                    comm['packets'] = []
                   
                else:
                    for complete_comm in complete_comms:
                        if (complete_comm['src_comm'] == packet1['src_ip'] and complete_comm['dst_comm'] == packet1['dst_ip']) or (complete_comm['src_comm'] == packet2['src_ip'] and complete_comm['dst_comm'] == packet2['dst_ip']):
                            comm = complete_comm
                            break
                        else: 
                            continue  
                    
                    if 'number_comm' not in comm:
                        comm['number_comm'] = len(complete_comms) + 1
                        comm['src_comm'] = packet1["src_ip"]
                        comm['dst_comm'] = packet1["dst_ip"]
                        comm['packets'] = []
                    
                comm['packets'].append(packet1)
                comm['packets'].append(packet2)
                passed_frame_numbers.append(packet1['frame_number'])
                passed_frame_numbers.append(packet2['frame_number'])
                complete_comms.append(comm)
            
            else:
                
        

        

    data = {
        'complete_comms': complete_comms,
        'partial_comms': partial_comms
    }
    return data


def analyzeTftp(packets):
    comms = []
    # get only UDP packets
    udp_packets = list(filter(
        lambda packet: packet['ether_type'] == 'IPv4' and packet['protocol'] == 'UDP', packets))

    for packet in udp_packets:
        comm = {}
        # find packet with port of TFTP com. start point
        if packet['dst_port'] == 69:
            # format new communication header
            comm['number_comm'] = len(comms) + 1
            comm['src_comm'] = packet['src_ip']
            comm['dst_comm'] = packet['dst_ip']
            comm['packets'] = []
            comm['packets'].append(packet)
            udp_packets.remove(packet)

            for pair in udp_packets:
                # find packet responding to first packets source IP
                if pair['dst_port'] == packet['src_port'] and packet['src_ip'] == pair['dst_ip'] and packet['dst_ip'] == pair['src_ip']:
                    comm['packets'].append(pair)
                    udp_packets.remove(pair)
                    flip = False
                    # cycle the rest of the packets to find all remaining packets of communication when we know the source and dest ports
                    for rest in udp_packets:
                        # if statements to handle if we looking for req or respond
                        if (not flip and pair['dst_port'] == rest['src_port'] and rest['src_ip'] == pair['dst_ip'] and rest['dst_ip'] == pair['src_ip']):
                            comm['packets'].append(rest)
                            udp_packets.remove(rest)
                            flip = True

                        if (flip and pair['src_port'] == rest['src_port'] and rest['src_ip'] == pair['src_ip'] and rest['dst_ip'] == pair['dst_ip']):
                            comm['packets'].append(rest)
                            udp_packets.remove(rest)
                            flip = False

        if comm:
            comms.append(comm)

    data = {
        'comms': comms
    }
    return data


def getHexdump(hex):
    hexCopy = hex
    frameParts = []

    for i in range(0, math.ceil(len(hex)/16)):

        hexCopy[0+(i*16)] = '\n'+hexCopy[0+(i*16)] 
        
        if i != 0 else hexCopy[0+(i*16)]

        if i == (len(hex)//16):
            frameParts.append(' '.join(hexCopy[0+(i*16):]))
            break

        frameParts.append(' '.join(hexCopy[0+(i*16):16+(i*16)]))

    frameParts.append("\n")
    return ''.join(frameParts)


def filterRip(packets):
    rips = []
    udp_packets = list(filter(
        lambda packet: packet['ether_type'] == 'IPv4' and packet['protocol'] == 'UDP', packets))
    for item in udp_packets:
        try:
            if (item['app_protocol'] == 'RIP'):
                rips.append(item)
        except:
            continue
    data = {
        'packets': rips,
        'number_frames': len(rips)
    }
    return data


# -------------------Main function----------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--destination",
                        help="Path to source .pcap file", default="./vzorky/eth-1.pcap")
    parser.add_argument("-p", "--protocol",
                        help="Select specific protocol to analyze")
    args = parser.parse_args()

    getScapy = rdpcap(args.destination)

    # output header
    data = {
        'name': 'PKS2022/23',
        'pcap_name': args.destination.split('/')[-1],
    }

    ip_send = {}
    packets = []
    for idx, item in enumerate(getScapy, start=1):
        # decode every frame and make and array of every byte in frame
        hexDecoded = hexlify(raw(item), " ").decode().split()

        # check if we have ISL header
        if ''.join(hexDecoded[0:6]) == "01000c000000" or ''.join(hexDecoded[0:6]) == "03000c000000":
            hexDecoded = hexDecoded[26:-1]

        # create package dictionary to store all information
        pkt = {
            'frame_number': idx,
            'len_frame_pcap': len(hexDecoded),
            'len_frame_medium': 64 if len(hexDecoded) < 60 else len(hexDecoded) + 4,
            'frame_type': getFrameType(hexDecoded),
            'src_mac': formatAddress(hexDecoded[6:12]),
            'dst_mac': formatAddress(hexDecoded[0:6]),
        }

       # analyzing ethernet II frames
        if 'ETHERNET II' in pkt['frame_type']:
            # find ether_type on 13th and 14th byte
            pkt['ether_type'] = getEtherType(hexDecoded[12]+hexDecoded[13])

            if 'IPv4' in pkt['ether_type']:
                ihl = int(hexDecoded[14][1], 16)
                pkt['src_ip'] = getIp(hexDecoded[26:30])
                pkt['dst_ip'] = getIp(hexDecoded[30:34])
                pkt['protocol'] = getIpProtocol(int(hexDecoded[23], 16))
                # find source ports with ihl to know we need to look for them
                pkt['src_port'] = int(
                    hexDecoded[14+ihl*4]+hexDecoded[14+ihl*4+1], 16)
                pkt['dst_port'] = int(
                    hexDecoded[14+ihl*4+2]+hexDecoded[14+ihl*4+3], 16)
                # check to see if one of found ports is known port to protocol IPv4 protocol
                if type(getAppProtocol(pkt['src_port'], pkt['protocol'])) == str or type(getAppProtocol(pkt['dst_port'], pkt['protocol'])) == str:
                    pkt['app_protocol'] = getAppProtocol(pkt['src_port'], pkt['protocol']) if type(getAppProtocol(
                        pkt['src_port'], pkt['protocol'])) == str else getAppProtocol(pkt['dst_port'], pkt['protocol'])
                # ipv4_senders counter
                if pkt['src_ip'] in ip_send:
                    ip_send[pkt['src_ip']] += 1
                else:
                    ip_send[pkt['src_ip']] = 1

            elif 'ARP' in pkt['ether_type']:
                pkt['arp_opcode'] = getArpOp(
                    int(hexDecoded[20]+hexDecoded[21], 16))
                pkt['src_ip'] = getIp(hexDecoded[28:32])
                pkt['dst_ip'] = getIp(hexDecoded[38:42])

        if 'LLC' in pkt['frame_type'] and not 'SNAP' in pkt['frame_type']:
            pkt['sap'] = getSap(hexDecoded[15])

        if 'SNAP' in pkt['frame_type']:
            pkt['pid'] = getPid(hexDecoded[20]+hexDecoded[21])

        # set hexa_frame format from multiline string to be in spec
        pkt['hexa_frame'] = ruamel.yaml.scalarstring.LiteralScalarString(
            getHexdump(hexDecoded))

        packets.append(pkt.copy())

    if args.protocol:
        if (args.protocol == 'TFTP'):
            data['filter_name'] = 'TFTP'
            data.update(analyzeTftp(packets=packets))
        elif (args.protocol == 'ARP'):
            data['filter_name'] = 'ARP'
            data.update(analyzeArp(packets=list(
                filter(lambda packet: packet['frame_type'] == 'ETHERNET II', packets))))
        elif (args.protocol == 'RIP'):
            data.update(filterRip(packets=list(
                filter(lambda packet: packet['frame_type'] == 'ETHERNET II', packets))))
        else:
            print('Protocol unknown')
            sys.exit(2)
    else:
        data['packets'] = packets
        data['ipv4_senders'] = []

        # format counted ips to spec
        for key, i in ip_send.items():
            data['ipv4_senders'].append({
                'node': key,
                'number_of_sent_packets': i
            })

        data['max_send_packets_by'] = []
        # get ip with the most packets sent
        data['max_send_packets_by'].append(max(ip_send, key=ip_send.get))

    f = open("pks-output-{}.yaml".format(args.protocol), "w")
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.dump(data, f)
