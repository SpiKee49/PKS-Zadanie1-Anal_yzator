import json
from scapy.all import *
from binascii import *
import ruamel.yaml
import math
import argparse

# -------------------FUNCTIONS-------------------


def getFrameType(hex):
    if (int(hex[12]+hex[13], 16) >= 1500):
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
        print("Uknown port: {}".format(dec))
        return 'unknown'


def getArpOp(dec):
    arp_codes = {
        1: 'REQUEST',
        2: 'REPLY'
    }
    return arp_codes[dec]


def getIcmpType(dec):
    file = open("./protocols/icmp-types.json", "r")
    types = json.load(file)
    try:
        return types[str(dec)]
    except:
        print("Uknown type: {}".format(dec))
        return 'unknown'


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

    try:
        return saps[hex]
    except:
        return "unknown"


def getPid(hex):
    pid = open("./protocols/pids.json")
    pids = json.load(pid)
    try:
        return pids[hex]
    except:
        return "unknown"


def commExists(comms, packet1, packet2):
    for comm in comms:
        if (comm['src_comm'] == packet1['src_ip'] and comm['dst_comm'] == packet1['dst_ip']) or (comm['src_comm'] == packet2['src_ip'] and comm['dst_comm'] == packet2['dst_ip']):
            # we found matching comm but it is not ICMP
            if "icmp_id" not in packet1 or packet1 == packet2:
                return comm

            # if it is ICMP we need to compare comms 'icmp_id' with 'icmp_id' of one of the packets, since pair has same 'icmp_id'
            if comm['icmp_id'] == packet1['icmp_id'] and comm['ip_id'] == packet1['id']:
                return comm
            else:
                continue

        else:
            continue
    # comm doesn't exists yet
    return {}


def analyzeIcmp(packets):
    complete_comms = []
    partial_comms = []
    passed_frame_numbers = []
    icmp_packets = list(
        filter(lambda packet:  packet['protocol'] == 'ICMP', packets))

    # get only ICMP packets
    for request in icmp_packets:

        # if we already passed the frame, we continue to next one
        if request["frame_number"] in passed_frame_numbers:
            continue

        # go through all packages, except passed one's and find reply to request
        for reply in icmp_packets:
            if request['frame_number'] == reply['frame_number'] or reply['frame_number'] in passed_frame_numbers:
                continue

            if request['icmp_type'] == 'ECHO REQUEST' and (reply['icmp_type'] == 'ECHO REPLY' or reply['icmp_type'] == 'TIME EXCEEDED') and request['dst_ip'] == reply['src_ip'] and reply['dst_ip'] == request['src_ip'] and request['icmp_id'] == reply['icmp_id']:
                comm = commExists(complete_comms, request, reply)
                new_comm = False

                if 'number_comm' not in comm:  # initializing new communication if it doesnt exist yet
                    new_comm = True
                    comm['number_comm'] = 1 if len(
                        complete_comms) < 0 and 'number_comm' not in comm else len(complete_comms) + 1
                    comm['src_comm'] = request["src_ip"]
                    comm['dst_comm'] = request["dst_ip"]
                    comm['icmp_id'] = request['icmp_id']
                    comm['ip_id'] = request['id']
                    comm['packets'] = []

                # now we need to find corensponding fragments to REQUEST
                comm['packets'].append(request)
                if 'flag_mf' in request:
                    # filter all fragments except request, add packet info to last fragment and then remove info request, same goes for reply later
                    fragments = sorted(list(filter(lambda packet: packet != request and 'flag_mf' in packet and packet['src_ip'] == request[
                                       'src_ip'] and packet['dst_ip'] == request['dst_ip'] and packet['id'] == request['id'], icmp_packets)), key=lambda pkt: pkt['frame_number'])

                    last_frag = fragments[-1]
                    last_frag['protocol'] = request['protocol']
                    last_frag['icmp_type'] = request['icmp_type']
                    last_frag['icmp_id'] = request['icmp_id']
                    last_frag['icmp_seq'] = request['icmp_seq']

                    # remove packet info from first fragment
                    for k in ['protocol', 'icmp_type', 'icmp_id', 'icmp_seq']:
                        request.pop(k, None)
                    # append fragments to comm
                    for f in fragments:
                        passed_frame_numbers.append(f['frame_number'])
                        comm['packets'].append(f)

                comm['packets'].append(reply)
                if 'flag_mf' in reply:
                    fragments = sorted(list(filter(lambda packet: packet != reply and 'flag_mf' in packet and packet['src_ip'] == reply[
                                       'src_ip'] and packet['dst_ip'] == reply['dst_ip'] and packet['id'] == reply['id'], icmp_packets)), key=lambda pkt: pkt['frame_number'])

                    last_frag = fragments[-1]
                    last_frag['protocol'] = reply['protocol']
                    last_frag['icmp_type'] = reply['icmp_type']
                    last_frag['icmp_id'] = reply['icmp_id']
                    last_frag['icmp_seq'] = reply['icmp_seq']

                    # remove packet info from first fragment
                    for k in ['protocol', 'icmp_type', 'icmp_id', 'icmp_seq']:
                        reply.pop(k, None)
                    # append fragments to comm
                    for f in fragments:
                        comm['packets'].append(f)
                        passed_frame_numbers.append(f['frame_number'])

                passed_frame_numbers.append(request['frame_number'])
                passed_frame_numbers.append(reply['frame_number'])

                if new_comm:  # appending only if the comm is new
                    complete_comms.append(comm)
                break

        if request["frame_number"] in passed_frame_numbers:
            continue

        comm = commExists(partial_comms, request, request)
        if 'packets' not in comm:
            comm['number_comm'] = 1 if len(
                partial_comms) < 0 and 'number_comm' not in comm else len(partial_comms) + 1
            comm['src_comm'] = request["src_ip"]
            comm['dst_comm'] = request["dst_ip"]
            comm['packets'] = []

        comm['packets'].append(request)
        passed_frame_numbers.append(request['frame_number'])

        if len(comm['packets']) < 2:
            partial_comms.append(comm)

    data = {
        "complete_comms": complete_comms,
        "partial_comms": partial_comms
    }

    return data


def analyzeArp(packets):
    complete_comms = []
    partial_comms = []
    passed_frame_numbers = []
    arp_packets = list(
        filter(lambda packet: packet['ether_type'] == 'ARP', packets))
    # get only ARP packets
    for packet1 in arp_packets:

        # if we already passed the frame, we continue to next one
        if packet1["frame_number"] in passed_frame_numbers:
            continue

        # go through all packages, except passed one's and find reply to request
        for packet2 in arp_packets:
            if packet1['frame_number'] == packet2['frame_number'] or packet2['frame_number'] in passed_frame_numbers:
                continue

            if packet1['arp_opcode'] == 'REQUEST' and packet2['arp_opcode'] == 'REPLY' and packet1['dst_ip'] == packet2['src_ip'] and packet2['dst_ip'] == packet1['src_ip']:
                comm = commExists(complete_comms, packet1, packet1)

                if 'number_comm' not in comm:
                    comm['number_comm'] = 1 if len(
                        complete_comms) < 0 and 'number_comm' not in comm else len(complete_comms) + 1
                    comm['src_comm'] = packet1["src_ip"]
                    comm['dst_comm'] = packet1["dst_ip"]
                    comm['packets'] = []

                comm['packets'].append(packet1)
                comm['packets'].append(packet2)
                passed_frame_numbers.append(packet1['frame_number'])
                passed_frame_numbers.append(packet2['frame_number'])
                if len(comm['packets']) == 2:
                    complete_comms.append(comm)
                break

        if packet1["frame_number"] in passed_frame_numbers:
            continue

        comm = commExists(partial_comms, packet1, packet1)
        if 'packets' not in comm:
            comm['number_comm'] = 1 if len(
                partial_comms) < 0 and 'number_comm' not in comm else len(partial_comms) + 1
            comm['src_comm'] = packet1["src_ip"]
            comm['dst_comm'] = packet1["dst_ip"]
            comm['packets'] = []

        comm['packets'].append(packet1)
        passed_frame_numbers.append(packet1['frame_number'])

        if len(comm['packets']) < 2:
            partial_comms.append(comm)

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

        hexCopy[0+(i*16)] = '\n'+hexCopy[0+(i*16)
                                         ] if i != 0 else hexCopy[0+(i*16)]

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
        'name': 'PKS2023/24',
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
                pkt['id'] = int(''.join(hexDecoded[18:20]), 16)

                # Fragments checks
                flag_value = int(hexDecoded[20], 16) >> 5
                offset = int(
                    ''.join(hexDecoded[20:22]), 16) & (2**3-1)  # https://stackoverflow.com/a/74338975/19510795

                if (flag_value == 1):  # this means packet is fragment
                    pkt['flag_mf'] = True
                    pkt['frag_offset'] = offset
                elif (flag_value == 0 and offset > 0):
                    pkt['flag_mf'] = False
                    pkt['frag_offset'] = offset

                ###

                pkt['protocol'] = getIpProtocol(int(hexDecoded[23], 16))
                # find source ports with ihl to know we need to look for them
                if pkt['protocol'] == 'UDP' or pkt['protocol'] == 'TCP':
                    pkt['src_port'] = int(
                        hexDecoded[14+ihl*4]+hexDecoded[14+ihl*4+1], 16)
                    pkt['dst_port'] = int(
                        hexDecoded[14+ihl*4+2]+hexDecoded[14+ihl*4+3], 16)
                    # check to see if one of found ports is known port to protocol IPv4 protocol
                    if type(getAppProtocol(pkt['src_port'], pkt['protocol'])) == str or type(getAppProtocol(pkt['dst_port'], pkt['protocol'])) == str:
                        pkt['app_protocol'] = getAppProtocol(pkt['src_port'], pkt['protocol']) if type(getAppProtocol(
                            pkt['src_port'], pkt['protocol'])) == str else getAppProtocol(pkt['dst_port'], pkt['protocol'])

                elif 'ICMP' == pkt['protocol']:
                    pkt['icmp_type'] = getIcmpType(
                        int(
                            hexDecoded[14+ihl*4], 16))

                    if pkt['icmp_type'] in ['ECHO REQUEST', 'ECHO REPLY', 'TIME EXCEEDED']:
                        pkt['icmp_id'] = int(
                            hexDecoded[14+ihl*4+4]+hexDecoded[14+ihl*4+5], 16)
                        pkt['icmp_seq'] = int(
                            hexDecoded[14+ihl*4+6]+hexDecoded[14+ihl*4+7], 16)

                    # predefine dict keys to be filled in last fragment
                    if flag_value == 0 and offset > 0:
                        pkt['icmp_id'] = ''
                        pkt['icmp_seq'] = ''

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
        elif (args.protocol == 'ICMP'):
            data['filter_name'] = 'ICMP'
            data.update(analyzeIcmp(packets=list(
                filter(lambda packet: packet['frame_type'] == 'ETHERNET II' and packet['ether_type'] == 'IPv4', packets))))
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

    if args.protocol:
        f = open("pks-output-{}.yaml".format(args.protocol), "w")
    else:
        f = open("pks-output-all.yaml", "w")
    yaml = ruamel.yaml.YAML()
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.dump(data, f)
