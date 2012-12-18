
class Extractor(object):
    """Used for extraction of various attributes of raw data. """

    @staticmethod
    def ip2int(ip):
        """convert string IPv4 address to int"""
        from util import ip2int
        return ip2int(ip)
    @staticmethod
    def int2ip(ip):
        """convert int to string IPv4 address"""
        from util import int2ip
        return int2ip(ip)
    def __init__(self, fields):
        """construct Extrator callable that return fields."""
        self.fields = tuple(fields)

class PcapExtractor(Extractor):
    """Used for extraction of attributes from PCAP data. """
    def __call__(self, pkt):
        from impacket.ImpactPacket import IP,TCP,UDP,ICMP,Data
        #from numpy import int64
        if (IP not in pkt) or (TCP not in pkt and UDP not in pkt):
            return None
        ip = pkt[IP]
        result = {
            'time':int(pkt.get_timestamp()*1e6),
            'src': Extractor.ip2int(ip.get_ip_src()),
            'dst': Extractor.ip2int(ip.get_ip_dst()),
            'paylen': ip.get_ip_len() - 4*ip.get_ip_hl(),
            'sport': 0,
            'dport': 0,
            'proto': ip.get_ip_p(),
            'seq': 0,
            'flags': 0,
            'flow': 0
        }

        if TCP in pkt:
            t = pkt[TCP]
            result['paylen'] -=  4*t.get_th_off()
            result['sport'] = t.get_th_sport()
            result['dport'] = t.get_th_dport()
            result['seq'] = t.get_th_seq()
            result['flags'] = t.get_th_flags() & 0x1ff
        elif UDP in pkt:
            u = pkt[UDP]
            result['paylen'] -=  8
            result['sport'] = u.get_uh_sport()
            result['dport'] = u.get_uh_dport()
        return tuple(result[f] for f in  self.fields)

class TraceExtractor(Extractor):
    """Used for extraction of attributes from TCP and UDP packet trace data. """
    def __call__(self, p):
        from scapy.all import IPv6,IP,TCP,UDP
        from numpy import int64
        if (IP not in p) or (TCP not in p and UDP not in p):
            return None
        ip = p[IP] if IP in p else p[IPv6]
        result = {
            'time':int(p.time*1e6),
            'src': Extractor.ip2int(ip.src),
            'dst': Extractor.ip2int(ip.dst),
            'paylen': 0,
            'sport': 0,
            'dport': 0,
            'proto': 0,
            'seq': 0,
            'flags': 0,
            'flow': 0
        }
        if IP in ip:
            result['paylen'] = ip.len - 4*ip.ihl
            result['proto'] = ip.proto
        elif IPv6 in ip:
            result['paylen'] = ip.plen
            result['proto'] = ip.nh
        if TCP in ip:
            t = ip[TCP]
            result['paylen'] -=  4*t.dataofs
            result['sport'] = t.sport
            result['dport'] = t.dport
            result['seq'] = t.seq
            result['flags'] = t.flags
        elif UDP in ip:
            u = ip[UDP]
            result['paylen'] -=  8
            result['sport'] = u.sport
            result['dport'] = u.dport
        return tuple(result[f] for f in  self.fields)

class FlowExtractor(Extractor):
    """Used for extraction of attributes from netflow data. """
    def __init__(self, fields, pattern=None):
        super(FlowExtractor, self).__init__(fields)
        if pattern:
            if not hasattr(pattern,'match'):
                raise ValueError('Unexcpeted pattern object')
            self.pt = pattern
        else:
            import re
            self.pt = re.compile(r'([0-9\-]+\s[0-9:.]+)\s+([0-9.]+)\s+([A-Z]+)\s+((?:[0-9]+[.]?){4}):([0-9.]+)\s+->\s+((?:[0-9]+[.]?){4}):([0-9.]+)\s+([.A-Z]+|0x[0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9.]+(?:\s[mMkK])?)\s+([0-9]+)')
    @staticmethod
    def _conv_size(size):
        """Convert size to the in. Decode K and M as well."""
        try: return int(size)
        except ValueError:
            mult = ' kmg' # none, kilo, mega, giga
            v = size.split()
            v,m = v if len(v) == 2 else v+[' ']
            return int(float(v)*pow(1024,mult.index(m.lower())))
    @staticmethod
    def _conv_flags(flags):
        """Convert flags int."""
        try: return int(flags,16) # hexa digit
        except ValueError: # decode 'UAPRSF'
            flags = list(reversed(flags))
            return sum(pow(2,i) if flags!='.' else 0 for i in range(len(flags)))
    @staticmethod
    def _conv_proto(proto):
        """Convert protocol int."""
        protos = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1
        }
        return protos.get(proto) if proto in protos else 0
    @staticmethod
    def _conv_time(time):
        """Convert timestamp to int in microsecond."""
        from datetime import datetime
        from time import mktime
        return int(mktime(datetime.strptime(time,'%Y-%m-%d %H:%M:%S.%f').timetuple())*1e6)
    @staticmethod
    def _conv_duration(duration):
        """Convert duration to int in microsecond."""
        return int(float(duration)*1e6)
    def __call__(self, line):
        """Invoke extrat on one line returning field containting tuple of fields.
        """
        try:
            time,dur,proto,src,sport,dst,dport,flags,tos,packets,size,flows = self.pt.match(line).groups()
            data = {
                ## temporal atributes
                'time': self._conv_time(time),'duration':self._conv_duration(dur), #microseconds
                ## spatial atributes
                'src': self.ip2int(src), 'dst':self.ip2int(dst),
                'sport':int(float(sport)),'dport':int(float(dport)),
                ## other atributes
                'proto':self._conv_proto(proto),'flags':self._conv_flags(flags), 'tos':int(tos),
                ## behavioral attributes
                'packets':int(packets),'size':self._conv_size(size),'flows':int(flows),
                'flow': 0
            }
            return tuple(data[f] for f in self.fields)
        except Exception as e:
            return None

