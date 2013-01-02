
try:
    from fabulous.color import bold,italic,underline,strike,blink,flip, \
                                black,red,green,yellow,blue,magenta,cyan,white ,\
                                highlight_black,highlight_red,highlight_green,highlight_yellow,highlight_blue,\
                                highlight_magenta,highlight_cyan,highlight_white
    from functional import *
    boldblack = combinator(bold ,black)
    boldred = combinator(bold ,red)
    boldgreen = combinator(bold ,green)
    boldyellow = combinator(bold ,yellow)
    boldblue = combinator(bold ,blue)
    boldmagenta = combinator(bold ,magenta)
    boldcyan = combinator(bold ,cyan)
    boldwhite = combinator(bold ,white)
    eraserest = lambda x:'\033[K'
except ImportError:
    print 'fabulous not found, colors are disabled'
    highlight_black=highlight_red=highlight_green=highlight_yellow=highlight_blue=\
    highlight_magenta=highlight_cyan=highlight_white=bold=italic=underline=strike=\
    blink=flip=black=red=green=yellow=blue=magenta=cyan=white =\
    boldblack,boldred,boldgreen,boldyellow,boldblue,boldmagenta,boldcyan,boldwhite = lambda x:x
    


class colorize(object):
    def __init__(self,*colors):
        import re
        self.colors = colors
        # format mini-language
        self.fml = re.compile(r'(?:(##)|#([^#]+)#|(%(?:[^{}]?(?:<|>|\+|^))?(?:\+|-|\s)?#?0?(?:[0-9]+)?,?(?:[.][0-9]+)?(?:b|c|d|e|E|f|F|g|G|n|o|s|x|X)))')
    def __iter__(self):
        return iter(self.colors)
    def _rainbow(self):
        class Rainbow:
            def __init__(self,iter):
                self.iter = iter
            def _apply_color(self,s):
                try:
                    color = self.iter.next()
                    return unicode(color(s)) if callable(color) else s
                except StopIteration:
                    return s
            def __call__(self, matcher):
                return self._apply_color(reduce(lambda a,x:x,filter(None,matcher.groups()),None))


        return Rainbow(iter(self))

    def __mul__(self, s):
        return self.fml.sub(self._rainbow(),s)

def flowiddataset(opt):

    if opt.flowid == '2a':
        fflow=('src','dport')
        bflow=('dst','sport')
        flowid = 'flows2a'
    elif opt.flowid == '3':
        fflow=('src','dst','dport')
        bflow=('dst','src','sport')
        flowid = 'flows3'
    elif opt.flowid == '4':
        fflow=('src', 'sport','dst','dport')
        bflow=('dst', 'dport','src','sport')
        flowid = 'flows4'
    else:
        raise NotImplementedError('flowid')
    return  fflow, bflow, flowid


def opts(args=None):
    """ User interface features
    """
    from argparse import ArgumentParser
    from sys import argv
    from info import __description__,__version__,__prog__,__date__,__author__

    if not args: args = argv[1:]

    actions = ('raw','flow','sample','model','filter', 'load', 'annotate')
    flowids  = ('2a', '3','4')
    transforms  = ('csd','psd')
    filetypes  = ('pcap','netflow')

    parser = ArgumentParser(description=__description__)


    parser.add_argument('--version', action='version', version='%s v%s\nCopyright (C) %s %s'%(__prog__,__version__,__date__.split('-',1)[0],__author__), help= 'show version information')

    parser.add_argument('action',choices=actions, metavar='(%s)'%('|'.join(actions)), help= ''\
                                                                                            'action to execute; raw stores "pcap" or netflow data in h5 database, "flow" marks flows and extracts attributes, '\
                                                                                            '"sample" computes sampling at given sample rate and tranformations at given windowing, "model" fits '\
                                                                                            'model to data stored in database, filter converts XML Ip filters to JSON format and "load" loads'\
                                                                                            ' database into memory')
    parser.add_argument('database', metavar='<database file>', help='hdf5 array database')
    parser.add_argument('file', nargs='*', metavar='<input file>', help='input files to process')

    parser.add_argument('-f', dest='in_format',choices=filetypes, metavar='(%s)'%('|'.join(filetypes)), help='input file format')
    parser.add_argument('-o', dest='out_file', metavar='<output file>', help='output file')
    parser.add_argument('-m', dest='min_packets', metavar='<min packets>', type=int, help='min packets per flow')
    parser.add_argument('-n', dest='reverse_dns', action='store_false', help='don`t do reverse dns')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-v', '--verbose', dest='verbosity', action='count', help='increase verbosity')
    group.add_argument('-q', '--quiet', dest='verbose', action='store_false', help='do not dump to terminal')

    group= parser.add_argument_group('Flow extraction options', 'Required for "flow", "sample" and "model" actions')
    group.add_argument('-i', dest='flowid',choices=flowids, metavar='(%s)'%('|'.join(flowids)), help='flow identification (3-tuple or 4-tuple)')
    group.add_argument('-u', dest='usesyns', action='store_true', help='don`t use SYN packets to distinguish flow start')
    group.add_argument('-p', dest='protocol', metavar='<protocol>', type=int, help='protocol to take in account, default = 6 (TCP)')

    group = parser.add_argument_group('Sampling options', 'Required for "sample" and "model" actions')
    group.add_argument('-s', dest='srate', metavar='<sample rate>',action='append',type=float,help='sample rate to use, can be specified multiple times')
    group.add_argument('-w', dest='window', metavar='<window length>',action='append',type=int,help='window lengths to use, can be specified multiple times')
    group.add_argument('-t', dest='transform', metavar='(%s)'%('|'.join(transforms)), choices=transforms,help=''\
                                                                                                              'tranformation to use, can be: "csd" for cross spectral density or "psd" for power spectral density')

    group = parser.add_argument_group('Model estimation options', 'Required for "model" action')
    group.add_argument('-a', dest='annotations', metavar='<file>', help='annotation file')
    group.add_argument('--legit', dest='legit', metavar='<int>,<int>,..', help='comma-separated list of classes considered legitimate')
    group.add_argument('--malicious', dest='malicious', metavar='<int>,<int>,..', help='comma-separated list of classes considered malicious')
    group.add_argument('--model', dest='model', metavar='<int>,<int>,..', help='comma-separated list of classes included in model')
    group.add_argument('--sample', dest='sample', metavar='<pattern>', help='regex to filter sampleset by name')
    group.add_argument('--computation', dest='computations', metavar='<step>,<step>,...',action='append', help='computation to evaluate')
    group.add_argument('--tex', dest='tex', metavar='<file>', help='append tex-like tables into <file>')
    #group.add_argument()

    parser.set_defaults(verbose=True,verbosity=0,reverse_dns=True,usesyns=True,protocol=6,tex=False)

    #parser.print(_help())
    longopts =  dict((v.dest,k) for k,v in  parser._option_string_actions.iteritems() if k.startswith('--'))
    shortopts =  dict((v.dest,k) for k,v in  parser._option_string_actions.iteritems() if not k.startswith('--'))
    opt =  parser.parse_args(args)

    if opt.action in ('raw','flow') and not opt.in_format:
        parser.error('input file format (--input-format) not specified for "raw" or "flow" action')

    if opt.action in ('flow', 'sample') and not opt.flowid:
        parser.error('flow identification (--flowid) not specified for "flow" or "sample" action')

    if opt.action in ('sample') and not opt.srate:
        parser.error('sample rate (--srate) not specified for "sample" action')

    if opt.action in ('sample') and not opt.window:
        parser.error('window (--window) not specified for "sample" action')

    if opt.action in ('sample') and not opt.transform:
        parser.error('transform (--transform) not specified for "sample" action')

    return opt, longopts, shortopts




def isString(val):
    return isinstance(val,str)

def isListLike(val):
    return not isString(val) and isSequenceType(val)

def ip2int(ip):
    """convert string IPv4 address to int"""
    from ipaddr import IPAddress
    from operator import mul
    a = map(ord,IPAddress(ip).packed)
    b = [pow(256,i)for i in range(len(a)-1,-1,-1)]
    return int(sum ( map (mul , a,b) ))

def int2ip(ip):
    """convert int to string IPv4 address"""
    from ipaddr import IPAddress
    return IPAddress(ip).compressed

def opengzip(fn,cb):
    from tempfile import NamedTemporaryFile
    from gzip import GzipFile
    gzip = GzipFile(fn,'rb')
    try:
        tmp = NamedTemporaryFile('w+b')
        try:
            tmp.writelines(gzip)
            tmp.flush()
            cb(tmp.name)
        finally:
            tmp.close()
    except IOError:
        cb(fn)
    except KeyboardInterrupt:
        raise
    finally:
        gzip.close()

def get_netflow(fn, extractor):
    def cb(data):
        e = extractor(data)
        if e is not None:
            result.append(e)
    def pcapopen(fn):
        f = open(fn,'r')
        try:
            for line in f.readlines():
                cb(line)
        finally:
            f.close()

    result = []
    try:
        opengzip(fn,pcapopen)
    except KeyError:
        pass

    return result


def get_packets(fn,extractor):
    """Exctracts information from packets given by file name - 'fn'
    """
    class PacketWrapper(object):
        @classmethod
        def decode(cls,data):
            """
            Because  ImpactDecoder has crappy suport for automatic detection of the packet format
            we must detect the most stable decoder. for linux cooked capture files it allways chooses
            LinuxSLLDecoder but for the other protocols or mixed captures we must do magic.
            """
            from impacket.ImpactDecoder import LinuxSLLDecoder,EthDecoder,IPDecoder,ARPDecoder
            from impacket.ImpactPacket import  Data
            # set up the hit rate mapping
            if not hasattr(cls,'hits'):
                cls.hits = {LinuxSLLDecoder:0,EthDecoder:0,IPDecoder:0,ARPDecoder:0}
            # sotr the decoder using the hitrates
            decoders = sorted(cls.hits.keys(),key=cls.hits.get)
            # and start with most reliable one
            i = len(decoders) - 1
            while True:
                try:
                    decoder = decoders[i]
                    result = decoder().decode(data)
                    if isinstance(result.child(),Data):
                        # we do not accept this sollution -
                        # maybe the packet is malformed or decoder is inappropiate
                        raise
                    # okay update the hit rate and return
                    cls.hits[decoder] += 1
                    return  result
                except:
                    i -= 1
                    if i < 0: raise
        def __init__(self, pktlen, data, timestamp):
            from impacket.ImpactPacket import PacketBuffer
            self.pktlen = pktlen
            self.timestamp = timestamp
            self.decoded = data if isinstance(data,PacketBuffer) else PacketWrapper.decode(data)
        def __contains__(self, item):
            if isinstance(item,object):
                p = self
                while p is not None:
                    if isinstance(p,item):
                        return True
                    p = p.child()
                return False
        def __getitem__(self, item):
            if isinstance(item,object):
                p = self
                while p is not None:
                    if isinstance(p,item):
                        return p
                    p = p.child()
                return None
        def get_timestamp(self):
            return self.timestamp
        def get_pktlen(self):
            return self.pktlen
        def child(self):
            return self.decoded
    def cb(ppktlen, data, timestamp):
        #from impacket.ImpactPacket import ImpactPacketException
        try:
            pkt = PacketWrapper(ppktlen, data, timestamp)
        except :
            return
        e = extractor(pkt)
        if e is not None:
            result.append(e)
    def pcapopen(fn = None):
        from pcap import pcapObject
        p = pcapObject()
        try:
            if fn: p.open_offline(fn)
            else: p.open_live('any' , 200, False, 100)
            p.dispatch(-1,cb)
        except Exception as e:
            print bold(red('error:')),red(str(e))
            pass

    result = []
    try:
        if fn:
            opengzip(fn,pcapopen)
        else:
            pcapopen()

    except KeyError:
        pass

    return result

def fig(plt_fnc, name=None, show=True):
    """fig( plt_fnc, [name=None, show=False] ) -> figure,result
    It is convience function for matplotlib figures.
    Creates an figure and axes and executes plot function(s) (plt_fnc) on axes.
    count of axes is same as number of plot function(s). If name is is given it must be
    list-like object of same size as plt_fnc then each axes is named accordingly.
    If show is true figure is showed.

    Parameters
    ----------
    plt_fnc : callable
        callable or list of callables that receive argument ax, which axes.
    name :  string or sequence of string
        names, must be same shape as plt_fnc
    show : boolean
        show an figure

    Returns
    -------
    figure : figure object
        can be used to show figure is show=False
    result : -
        result of plt_fnc invocation(s)

    """
    from matplotlib.pyplot import figure
    import numpy as np

    if hasattr(plt_fnc,'__len__') and len(plt_fnc)==1:
        plt_fnc, = plt_fnc

    fig = figure()
    if callable(plt_fnc):
        ax = a = fig.add_subplot(111)
        result = plt_fnc(a)
        if name: a.set_title(name)
    else:
        l = len(plt_fnc)
        result = []
        #subimgs = np.ceil(np.sqrt(l))
        rows = 3
        cols = np.ceil(l/3.)
        ax = []
        for i in range(l):
            a = fig.add_subplot(rows,cols,1+i)
            ax += a,
            result += plt_fnc[i](a),
            if name and len(name) > i: a.set_title(name[i])
        result = tuple(result)
        #if callable(xfmt_fnc): a.axes.xaxis.set_major_formatter(ticker.FuncFormatter(xfmt_fnc))
    #if callable(yfmt_fnc): a.axes.yaxis.set_major_formatter(ticker.FuncFormatter(yfmt_fnc))
    if show: fig.show()
    return (fig,ax),result

def leakage(length,periods,fnc=None,notitle=True):
    import numpy as np
    from scipy.signal import correlate
    from scipy.fftpack import fftfreq,fft
    n = int(1e7)
    x = np.sin(np.linspace(0,2*periods*np.pi,length))
    if callable(fnc):
        x *= fnc(length)
        name = fnc.__name__
    else: name = 'rectangular'
    f = fftfreq(int(n),1./length)
    dB = lambda x:10*np.log10(x/x.max())
    psd =  lambda x,n: np.abs(fft(correlate(x,x,'full'),n=int(n)) )
    positive = lambda x,f:x[f>0]
    integers = lambda x,f:x[(np.ceil(f)-f<1e-4)&(f>0)]
    def plt(ax):
        ax.plot (positive(f,f)-periods, positive(dB(psd(x,n)),f))
        ax.plot (integers(f,f)-periods, integers(dB(psd(x,n)),f),'ro')
    (fg,ax),dumy = fig( plt, show=False )
    if not notitle: ax.set_title('Spectral leakage (%s window, %d samples)'%(name,length))
    ax.set_xlabel('DFT bins')
    ax.set_ylabel('Relative Magnitude [dB]')
    ax.set_xlim((-periods,14-periods))
    ax.set_ylim((-70,1))
    ax.set_xticks(range(-periods,14-periods+1,1))
    fg.show()

def scatter(ax, X, y, normalization=None, transform=None, labeling=None):
    """Convience method for scatter plotting of samples.
        Input:
            ax - axes object
            X - sample set [n_samples,n_dim]
            y - classes of samples [n_dim]
            normalisation - callable used to normalization of X or None
            transform - callable used to transform of X to lower dimensional space or None
            labeling - callable used to determine text labels of y or None
        Output:
            scatter plot instance
    """
    import numpy as np
    from matplotlib.patches import Patch
    Xnew = normalization(X) if callable(normalization) else X
    Xnew = transform(Xnew) if callable(transform) else Xnew
    labeling = labeling if callable(labeling) else lambda x:x
    def split(x):
        if len(x.shape) == 1:
            a,b = x[...,np.newaxis]
            return a,b
        else:
            a,b = np.split(x,2,1)
            return a.squeeze(),b.squeeze()
    color = (list('gbrycmgbrycmgbrycmgbrycm'))
    colors = dict((i,color.pop(0)) for i in np.unique(y))
    r = ax.scatter(*split(Xnew),c=[colors.get(i) for i in y.squeeze()], marker='+')
    l = [labeling(i) for i in np.unique(y)]
    p = [Patch(facecolor=colors.get(i)) for i in np.unique(y)]
    ax.legend(p,l)
    return r

def timedrun(fnc):
    """decorate function to print time of execution in seconds on standard input
        Input:
            fnc - function to decorate
        Output
            decorated function
        example:
            In [1]:
                @timedrun
                def test():
                    <invoke time consuming actions>
                test()
            Out[1]:
            ## function <test>: started
            <output messages of function test>
            ## function <test>: elapsed time: ...
    """
    class TimedRun(object):
        def __init__(self, fnc):
            self.fnc = fnc
        def _get_name(self):
            if hasattr(self.fnc,'__name__'):
                return self.fnc.__name__
        def __call__(self, *args, **kwargs):
            from datetime import datetime
            print '## function <%s>: started' % self._get_name()
            start = datetime.now()
            result = self.fnc.__call__(*args,**kwargs)
            print '## function <%s>: elapsed time: %f' % (self._get_name() ,(datetime.now() - start).total_seconds())
            return result
    return TimedRun(fnc)

def reverseDns(ip):
    """ execute reverse lookup of given address
    """
    try:
        import socket
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip

class TcpServices(object):
    @classmethod
    def get_srv_reverse_map(cls):
        if not hasattr(cls,'TCP_REVERSE'):
            cls.TCP_REVERSE = dict((v,k) for k,v in cls.get_srv_map().iteritems())
        return cls.TCP_REVERSE
    @classmethod
    def get_srv_map(cls):
        if not hasattr(cls,'TCP_SERVICES'):
            try:
                from scapy.all import TCP_SERVICES
                cls.TCP_SERVICES = dict((k,'%d'%TCP_SERVICES[k]) for k in TCP_SERVICES.keys())
            except ImportError:
                cls.TCP_SERVICES = {}
        return cls.TCP_SERVICES
    @classmethod
    def get_proto_reverse_map(cls):
        if not hasattr(cls,'IP_REVERSE'):
            cls.IP_REVERSE = dict((v,k) for k,v in cls.get_proto_map().iteritems())
        return cls.IP_REVERSE
    @classmethod
    def get_proto_map(cls):
        if not hasattr(cls,'IP_PROTOS'):
            try:
                from scapy.all import IP_PROTOS
                cls.IP_PROTOS = dict((k,'%d'%IP_PROTOS[k]) for k in IP_PROTOS.keys())
            except ImportError:
                cls.IP_PROTOS = {'udp':17, 'tcp': 6}
        return cls.IP_PROTOS
    @classmethod
    def get_service(cls,port):
        return cls.get_srv_reverse_map().get('%s'%port)
    @classmethod
    def get_port(cls,service):
        return cls.get_srv_map().get('%s'%service)

def flow2str(flow, fields = None, dns=False, services=False, color=True):
    if color:
        template = colorize(green,yellow,green,yellow) * '%s:%s > %s:%s'
    else:
        template = '%s:%s > %s:%s'
    if isinstance(flow,tuple):
        if 'src' not in fields or 'dst' not in fields:
            raise ValueError('items "src" and "dst" are expected to identify flow')
        x = [ ((flow[fields.index(s)]) if s in fields else '*') for s in ('src','sport','dst','dport') ]
        reverse = fields.index('src') > fields.index('dst')
    else:
        if 'src' not in flow or 'dst' not in flow:
            raise ValueError('items "src" and "dst" are expected to identify flow')
        x = [ (scalar(flow[s]) if s in flow else '*') for s in ('src','sport','dst','dport') ]
    for i in (0,2):
        if x[i] != '*':
            if dns:
                x[i] = reverseDns(int2ip(x[i]))
            else:
                x[i] = int2ip(x[i])
    if services:
        for i in (1,3):
            p = TcpServices.get_service(x[i])
            if p:
                x[i] = p
    return template % tuple(x)


def scalar(x):
    """ convert to scalar if possible """
    if (hasattr(x,'size') and x.size == 1) or (hasattr(x,'shape') and sum(x.shape)==1) or (hasattr(x,'__len__') and len(x)==1):
        try:
            from numpy import squeeze
            return squeeze(x).item()
        except ValueError:
            pass
        except IndexError:
            pass
    return x

def get_filter(f):
    from xml.dom.minidom import parse, parseString
    dom = parse(f)
    filt = dom.firstChild
    if filt.nodeName != 'filter': raise ValueError('Fooka!!')
    child = filt.firstChild
    r = {}
    while child is not None:
        if child.nodeType == filt.ELEMENT_NODE:
            name = child.nodeName
            items = child.getElementsByTagName('item')
            if len(items) > 0:
                r[name] = [ i.firstChild.nodeValue for i in items ]
                try:
                    r[name] = [ int(i) for i in r[name] ]
                except ValueError:
                    pass
            else:
                r[name] = child.firstChild.nodeValue
                try:
                    r[name] = int(r[name])
                except ValueError:
                    pass
        try:
            child = child.nextSibling
        except AttributeError:
            break

    for key in ['type', 'annotation' ]:
        if key not in r:
            r[key] = ''
    for key in ['srcPorts', 'dstPorts', 'protocols', 'srcIPs', 'dstIPs']:
        if key not in r:
            r[key] = []
    r['fileName'] = f

    return r