

def ip2int(ip):
    """convert string IPv4 address to int"""
    from ipaddr import IPAddress
    a = map(ord,IPAddress(ip).packed)
    b = [pow(256,i)for i in range(len(a)-1,-1,-1)]
    return int(sum ( map (lambda x,y: x*y , a,b) ))

def int2ip(ip):
    """convert int to string IPv4 address"""
    from ipaddr import IPAddress
    return IPAddress(ip).compressed

def get_packets(fn,extractor):
    """Exctracts information from packets given by file name - 'fn'

    """


    class PacketWrapper(object):
        def __init__(self, pktlen, data, timestamp):
            from impacket.ImpactDecoder import LinuxSLLDecoder as Decoder
            from impacket.ImpactPacket import PacketBuffer
            self.pktlen = pktlen
            self.timestamp = timestamp
            self.decoded = data if isinstance(data,PacketBuffer) else Decoder().decode(data)
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
        try:
            pkt = PacketWrapper(ppktlen, data, timestamp)
        except Exception as e:
            print e
            return
        e = extractor(pkt)
        if e is not None:
            result.append(e)
    def pcapopen(fn = None):
        from pcap import pcapObject
        p = pcapObject()
        if fn: p.open_offline(fn)
        else: p.open_live('any' , 200, False, 100)
        try:
            p.dispatch(-1,cb)
        except Exception as e:
            print e
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
        finally:
            gzip.close()

    result = []
    try:
        if fn:
            try:
                pcapopen(fn)
            except:
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
        Input:
              plt_fnc - callable or list of callables that receive argument ax, which axes.
              name - string or list of names, must be same shape as plt_fnc
              show - show an figure if true
        Returns:
              figure - figure object (can be used to show figure is show=False)
              result - result of plt_fnc invocation(s)
    """
    from matplotlib.pyplot import figure
    import numpy as np

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
    """ execute dig to reverse lookup of given address
    """
    try:
        import socket
        return socket.gethostbyaddr(ip)[0]
    except:
        pass

def scalar(x):
    return x.item() if hasattr(x,'item') else x

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