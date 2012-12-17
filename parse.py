#!/usr/bin/python -u

from util import timedrun

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

class Flowizer(object):
    def __init__(self, fields = ('time', 'paylen', 'flow'), fflow=('src','sport','dst','dport'), bflow=('dst','dport','src','sport')):
        self.fields = fields
        self.fflow = fflow
        self.bflow = bflow
    @staticmethod
    def _quad2str(d, fields):
        if 'src' not in fields or 'dst' not in fields:
            raise ValueError('items "src" and "dst" are expected to identify flow')
        x = [ ((d[fields.index(s)]) if s in fields else '*') for s in ('src','sport','dst','dport') ]
        reverse = fields.index('src') > fields.index('dst')
        for i in (0,2):
            if x[i] != '*':
                x[i] = Extractor.int2ip(x[i])
        return '\033[32m%s\033[0m:\033[33m%s\033[0m > \033[32m%s\033[0m:\033[33m%s\033[0m' % tuple(x)
    def __call__(self, data, usesyns = True):
        from numpy import array,abs
        from dataset import Variable,Dataset
        from sys import stdout
        variables = dict((k,Variable(k))for k in ('src','sport','dst','dport'))

        paylen =  Variable('paylen')
        flags =  Variable('flags')
        proto =  Variable('proto')
        time =  Variable('time')

        pay = data.select((proto==6),order='time',retdset=True)
        hashes = {}
        scalar = lambda x : x.item() if  hasattr(x,'item') else x
        negate = lambda x: -abs(x)
        l = 0
        dropped = 0
        droppedips = set()
        for x in pay:
            t = tuple(scalar(x[f]) for f in self.fflow)
            h = hash(t)
            tr = tuple(scalar(x[f]) for f in self.bflow)
            hr = hash(tr)
            negative = False
            if h in hashes:
                if hashes[h] != t:
                    stdout.write('\r****** collision in %s (hash: %d)\n' %(Flowizer._quad2str(t, self.fflow),h))
                    stdout.flush()
                    dropped += 1
                    continue
            elif hr in hashes:
                if hashes[hr] != tr:
                    stdout.write( '\r****** collision in %s (hash: %d)\n' %(Flowizer._quad2str(tr, self.bflow),hr))
                    stdout.flush()
                    dropped += 1
                    continue
                negative = True
            else:
                #print scalar(x['flags'])&18
                if usesyns:
                    if 'packets' in pay:  # we deal with netflow data and thus we demand SYN
                        syn = scalar(x['flags'])&2 == 2
                    else: # we deal with pcap data, so SYN packet is distinguishable
                        # we don`t care about SYN+ACK
                        syn = scalar(x['flags'])&18 == 2
                    if not syn:
                        stdout.write( '\r****** no syn packet in %s (hash: %d)\n' % (Flowizer._quad2str(t, self.fflow),hr))
                        stdout.write( '\rprogress: \033[33;1m%0.1f %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        ' % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                        stdout.flush()
                        dropped += 1
                        droppedips.add((scalar(x['dst']),scalar(x['dport'])))
                        continue
                stdout.write( '\r###### new flow %s (hash: %d)\n' % (Flowizer._quad2str(t, self.fflow),hr))
                stdout.write( '\rprogress: \033[33;1m%0.1f %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        ' % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                stdout.flush()
                hashes[h] = t
            x['flow'] = h
            if negative:
                for i in ('paylen','size'):
                    if i in x:
                        x[i] = negate # broadcasting lambda
            l += 1
            if l%1000 == 0 :
                stdout.write( '\rprogress: \033[33;1m%0.1f %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        ' % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                stdout.flush()
        stdout.write( '\rprogress: \033[33;1m100 %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        \n' % (dropped,(l+dropped)))
        stdout.write( '\n%s\n'% [(Extractor.int2ip(d),pd) for d,pd in droppedips])
        stdout.flush()
        if 'paylen' in pay:
            pay = pay.select((paylen!=0),order=('time',),retdset=True, fields=self.fields)
        qd = Dataset(data=array(tuple((j,)+k for j,k in hashes.items())),fields=('flow',)+self.fflow)
        return  qd, pay

class Sampler(object):
    """ Generates samples of the packet traces
    """
    def __init__(self, epochsize = 300000000, srate = 100, slice = None):
        self.epochsize = epochsize # default 5 minutes
        self.srate = srate # default 10 ms
        self.slice = slice #

    @staticmethod
    @timedrun
    def fnc1(fdata,flows,intervals):
        import numpy as np
        m = np.zeros((intervals.shape[0],flows.shape[0]),dtype=int)
        ftime = fdata[...,0]
        for i in range(intervals.shape[0]):
            k,l = intervals[i]
            m[i,...] = ((ftime>=k) & (ftime<l)).sum(1)
            #if not i%50000: print '%d of %d' %(i, intervals.shape[0])
        return m

    @staticmethod
    @timedrun
    def fnc2(fdata,flows,intervals):
        import numpy as np
        m = np.zeros((intervals.shape[0],flows.shape[0],3),dtype=int)
        ftime = fdata[...,0]
        foutgoing = fdata[...,1]>=0
        for i in range(intervals.shape[0]):
            k,l = intervals[i]
            m[i,...,0] = ((ftime>=k) & (ftime<l)).sum(1)
            a = ((ftime>=k) & (ftime<l) & foutgoing)
            b = ((ftime>=k) & (ftime<l) & (~foutgoing))
            m[i,a.any(0),1] = fdata[a,1].sum(1)
            m[i,b.any(0),2] = fdata[b,1].sum(1)
        return m

    def __call__(self, flows, flow=None, epochs = None):
        import numpy as np
        from dataset import Variable

        time = Variable('time')

        print '## Sampling data: epoch=%dsec, srate=%dHz, slice=(%dsec,%dsec)' %\
                (self.epochsize*1e-6, self.srate, self.slice[0]*1e-6,self.slice[1]*1e-6)

        epochsize = self.epochsize
        mintime = flows.data[...,0].min()
        maxtime = flows.data[...,0].max()

        if self.slice:
            if len(self.slice) != 2 or any(s>(maxtime-mintime) or s<0 for s in self.slice ):
                raise ValueError('slice (%d, %d) is out of bounds (%d,%d)'%(self.slice[0],self.slice[1],mintime,maxtime))
            sel  = flows.select ((time>=mintime+self.slice[0])&(time<mintime+self.slice[1]), order='time',retdset=True)
        else:
            sel = flows

        sel.data[...,0] -= sel.data[...,0].min()
        selmaxtime = sel.data[...,0].max()

        # show time histogram of selected slice
        #try:
        #    (bins,counts,a),f = fig(lambda a: a.hist(1e-6*sel.data[...,0],bins= 100), lambda x, p : '%d'% x, show = False) #datetime.fromtimestamp(x).strftime('%H:%M')
        #    if hist: f.show()
        #except Exception:
        #    bins,counts = None,None
        #if hist: return (bins,counts),None

        r = np.array(range(0,selmaxtime,epochsize))
        r = np.vstack((r[:-1],r[1:])).transpose()

        speriod = int(1e6/self.srate)

        for e in epochs if epochs  else  range(r.shape[0]):
            mi,ma = r[e]
            fdata = sel.select((time >= mi) & (time < ma))
            fid = np.unique( fdata[...,2] )
            print '## epoch: %d of %d, packets: %d, flows: %d' % (e, r.shape[0], fdata.shape[0], fid.shape[0])
            fdata2 = fdata[np.newaxis,...].repeat(fid.shape[0],axis=0)
            fid2 = fid[...,np.newaxis].repeat(fdata2.shape[1],axis=1)
            fdata2[(fdata2[...,2] != fid2),...] = -1

            s = np.array(range(mi,ma+1,speriod))
            s = np.vstack((s[:-1],s[1:])).transpose()
            yield e,fid,self.fnc1(fdata2,fid,s)

