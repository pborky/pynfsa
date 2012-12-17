


def psd(w, bounds):
    """auto-correlation of packet process"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    from dataset import Variable
    import numpy as np
    paylen =  Variable('paylen')
    allpkts = w['time'][np.newaxis,...]
    amp = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    if 'packets' in w:
        packets = w['packets'][np.newaxis,...]
        #amp = (((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))*packets).sum(1)
        amp = (amp*packets[...,0]).sum(1)
    else:
        #amp = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...])).sum(1)
        amp = amp.sum(1)
    # power spectral density
    return amp,np.abs(fft(correlate(amp,amp,mode='same')))
def csd(w, bounds):
    """auto-correlation of packet process"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    from dataset import Variable
    import numpy as np
    if len(w)>100: raise Exception()
    size =  'size' if 'size' in w else 'paylen'
    allpkts = w['time'][np.newaxis,...][...,w[size][...,0] >= 0,...]
    ampout = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    allpkts = w['time'][np.newaxis,...][...,w[size][...,0] < 0,...]
    ampin = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    if 'packets' in w:
        packets = w['packets'][np.newaxis,...][...,w[size][...,0] >= 0,...]
        ampout = (ampout*packets[...,0]).sum(1)
        packets = w['packets'][np.newaxis,...][...,w[size][...,0] < 0,...]
        ampin = (ampin*packets[...,0]).sum(1)
    else:
        ampout = ampout.sum(1)
        ampin = ampin.sum(1)
    # power spectral density
    return np.vstack((ampout,ampin)),np.abs(fft(correlate(ampin,ampout,mode='same')))
def xsd1(w, bounds):
    """cross-correlation of in-/out-bound packet process"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    from dataset import Variable
    import numpy as np
    paylen =  Variable('paylen')
    inbound = w.select(paylen<0,fields=('time',))[np.newaxis,...]
    outbound = w.select(paylen>=0,fields=('time',))[np.newaxis,...]
    # in-/out-bound packet process
    icount = ((inbound[...,0] >= bounds[:-1,...]) & (inbound[...,0] < bounds[1:,...])).sum(1)
    ocount = ((outbound[...,0] >= bounds[:-1,...]) & (outbound[...,0] < bounds[1:,...])).sum(1)
    amp = np.vstack((ocount,icount))
    # cross spectral density
    return amp,fft(correlate(abs(icount),abs(ocount),mode='same'))
def xsd2(w, bounds):
    """cross-correlation of in-/out-bound packet volume"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    from dataset import Variable
    import numpy as np
    paylen =  Variable('paylen')
    inbound = w.select(paylen<0,fields=('time','paylen'))[np.newaxis,...]
    outbound = w.select(paylen>=0,fields=('time','paylen'))[np.newaxis,...]
    imask = (inbound[...,0] >= bounds[:-1,...]) & (inbound[...,0] < bounds[1:,...])
    omask = (outbound[...,0] >= bounds[:-1,...]) & (outbound[...,0] < bounds[1:,...])
    # packet process
    amp = np.vstack(((outbound[...,1].repeat(wndsize-1,0)* omask).sum(1),(inbound[...,1].repeat(wndsize-1,0)* imask).sum(1)))
    # cross spectral density
    return amp,fft(correlate(abs(amp[1]),abs(amp[0]),mode='same'))

def get_labeling(id3):
    from dataset import Variable
    import json
    from itertools import product
    from util import scalar,ip2int,int2ip

    flow = Variable('flow')
    src = Variable('src')
    dst = Variable('dst')
    dport = Variable('dport')
    sport = Variable('sport')

    # some heuristics
    f = open('flows/filters.json')
    filters = json.load(f)
    labeling2 = {}
    labeling = {}
    for f in filters:
        if f['type'] not in labeling2:
            if f['type'] == 'FILTER_LEGITIMATE':
                labeling2[f['type']] = 1
            elif f['type'] == 'FILTER_MALICIOUS':
                labeling2[f['type']] = 2
            else: labeling2[f['type']] = None
        a = labeling2[f['type']]
        if f['dstIPs'] and f['dstPorts'] and f['srcIPs']:
            for d,dp,s in product(f['dstIPs'],f['dstPorts'],f['srcIPs']):
                for r in id3.select((src==ip2int(s))&(dst==ip2int(d))&(dport==dp),fields=('flow',)):
                    labeling[scalar(r)] = a
        elif f['dstIPs'] and f['dstPorts']:
            for d,dp in product(f['dstIPs'],f['dstPorts']):
                for r in id3.select((dst==ip2int(d))&(dport==dp),fields=('flow',)):
                    labeling[scalar(r)] = a
        elif f['dstIPs']:
            for d in f['dstIPs']:
                for r in id3.select((dst==ip2int(d)),fields=('flow',)):
                    labeling[scalar(r)] = a
        elif f['srcIPs']:
            for d in f['srcIPs']:
                for r in id3.select((src==ip2int(d)),fields=('flow',)):
                    labeling[scalar(r)] = a
    return labeling,dict( (v,k) for k,v in labeling2.items() )
def get_pcap(pcapfns, callback, keys=()):
    from parse import PcapExtractor
    from os.path import isfile,basename
    from util import get_packets
    extract = PcapExtractor( ('time','src','sport','dst','dport','proto','paylen','flags', 'flow') )
    for fn in pcapfns:
        if isfile(fn) and basename(fn) not in keys:
            print '## Getting %s...' % fn
            ## load file
            pkts = get_packets(fn,extract)
            print '\t%d packets captured'%len(pkts)
            #print '## Exctracting features...'
            ## convert to matrix
            data = Dataset(pkts, extract.fields)
            print '\t%d packets extracted, %d packets discarded'% (data.data.shape[0],len(pkts)-data.data.shape[0])
            del pkts
            callback(data,basename(fn))

if __name__=='__main__':
    from util import ip2int,int2ip,reverseDns,fig
    from sys import argv
    import numpy as np
    from h5py import File
    from dataset import Dataset

    if argv[1] == 'filters':
        import json
        from os.path import isfile
        from util import get_filter
        f = open(argv[2],'w')
        try:
            print json.dump([get_filter(f.strip()) for f in argv[3:] if isfile(f)], f)
        finally:
            f.close()
    elif argv[1] == 'pcap':
        from parse import PcapExtractor
        #from scapy.all import sniff,TCP,UDP,IP
        from os.path import isfile,basename
        from util import get_packets
        h5 = File(argv[2],'a')
        tr = h5.require_group('traces')
        extract = PcapExtractor( ('time','src','sport','dst','dport','proto','paylen','flags', 'flow') )
        for fn in argv[3:]:
            if isfile(fn) and basename(fn) not in tr.keys():
                print '## Getting %s...' % fn
                ## load file
                #pkts = sniff(offline=fn,lfilter=lambda x: TCP in x or UDP in x)
                #pkts = sniff(offline=fn)
                pkts = get_packets(fn,extract)
                print '\t%d packets captured'%len(pkts)
                #print '## Exctracting features...'
                ## convert to matrix
                data = Dataset(pkts, extract.fields)
                print '\t%d packets extracted, %d packets discarded'% (data.data.shape[0],len(pkts)-data.data.shape[0])
                del pkts
                print '## Storing matrix in %s...' % argv[2]
                data.save(tr.require_group(basename(fn)))
    if argv[1] == 'netflow':
        from parse import FlowExtractor
        from os.path import isfile,basename
        h5 = File(argv[2],'a')
        fl = h5.require_group('netflows')
        extractf = FlowExtractor( ('time', 'duration','src','sport','dst','dport','proto', 'packets', 'size','flags', 'flows', 'flow') )
        for fn in argv[3:]:
            if isfile(fn) and basename(fn) not in fl.keys():
                print '## Getting %s...' % fn
                ## load file
                #pkts = sniff(offline=fn,lfilter=lambda x: TCP in x or UDP in x)
                f = open(fn,'r')
                try: flows = f.readlines()
                finally: f.close()
                print '\t%d flows captured'%len(flows)
                print '## Exctracting features...'
                ## convert to matrix
                data = Dataset(extractf, flows)
                print '\t%d flows extracted, %d flows discarded'% (data.data.shape[0],len(flows)-data.data.shape[0])
                del flows
                print '## Storing matrix in %s...' % argv[2]
                data.save(fl.require_group(basename(fn)))
    elif argv[1] == 'flows3':
        from util import timedrun
        from parse import Flowizer

        def process(data,flowize,id):
            print '## Extracting flows using triple'
            fl = h5.require_group('flows3')
            q,f = flowize(data, Dataset(h5=fl['flowid'])) if 'flowid' in fl else flowize(data)
            for i in ('data%s'%id,'flowid'):
                if i in fl:
                    del fl[i]
            print '## Storing matrices in %s...' % argv[2]
            f.save(fl.require_group('data%s'%id))
            q.save(fl.require_group('flowid'))

        h5 = File(argv[2],'a')
        if 'traces' in h5:
            tr = h5['traces']
            flowize = timedrun(Flowizer(fflow=('src','dst','dport'),bflow=('dst','src','sport')))  # group flow using triple
        elif 'netflows' in h5:
            tr = h5['netflows']
            flowize = timedrun(Flowizer(fields = ('time', 'size', 'packets', 'flow'), fflow=('src','dst','dport'),bflow=('dst','src','sport')))  # group flow using triple
        else:
            tr = None
            flowize = timedrun(Flowizer(fflow=('src','dst','dport'),bflow=('dst','src','sport')))  # group flow using triple

        if not tr:
            fl = h5.require_group('flows3')
            keys = [ i[1] for i in (k.split('_',1) for k in fl.keys()) if len(i) > 1 ]
            get_pcap(argv[3:],lambda x,fn:process(x,flowize,'_%s'%fn),keys=keys)
        else:
            try:
                data = reduce(lambda x,y:x+y,(Dataset(h5=tr[k]) for k in sorted(tr.keys()))  )
                process(data,flowize,'')
            except MemoryError:
                for k in sorted(tr.keys()):
                    data = Dataset(h5=tr[k])
                    process(data,flowize,'_%s'%k)

    elif argv[1] == 'flows4':
        from util import timedrun
        from parse import Flowizer
        h5 = File(argv[2],'a')
        if 'traces' in h5:
            tr = h5['traces']
        elif 'netflows' in h5:
            tr = h5['netflows']
        else:
            raise Exception('missing traces or flows')
        data = Dataset(data=np.vstack(tr[k] for k in sorted(tr.keys()) if k!='.fields'),fields=tuple(tr['.fields']))
        ## extract flows
        print '## Extracting flows using quad'
        if 'paylen' in data:
            flowize = timedrun(Flowizer(fflow=('src', 'sport','dst','dport'),bflow=('dst', 'dport','src','sport')))  # group flow using triple
        elif 'size' in data and 'packets' in data:
            flowize = timedrun(Flowizer(fields = ('time', 'size', 'packets', 'flow'), fflow=('src', 'sport','dst','dport'),bflow=('dst', 'dport','src','sport')))  # group flow using triple
        else:
            raise Exception('dataset not usable')
        q,f = flowize(data)
        fl = h5.require_group('flows4')

        for i in ('flowdata','flowfields','flowid','flowidfields'):
            if i in fl:
                del fl[i]

        print '## Storing matrices in %s...' % argv[2]
        fl.create_dataset('flowdata',data = f.data,compression='gzip')
        fl.create_dataset('flowid',data = q.data,compression='gzip')
        print '## Storing fields in %s...' % argv[2]
        fl.create_dataset('flowfields',data = f.fields,compression='gzip')
        fl.create_dataset('flowidfields',data = q.fields,compression='gzip')

    elif argv[1] == 'samples':
        from dataset import Variable
        from scipy.signal import  correlate
        from scipy.fftpack import fftfreq,fft
        from sys import stdout

        if argv[4] == 'psd':
            xsdfnc = psd
        elif argv[4] == 'csd':
            xsdfnc = csd
        else:
            raise Exception('transformation not specified')

        for arg in argv[5:]:
        #for srate in (100,200,500,1000,2000):
            srate = float(arg)
            if srate<=0:
                continue

            wndsize = 200

            speriod = 1./ srate # sampling period in seconds
            wndspan = int(1e6 * wndsize * speriod) # window span in microseconds

            flow =  Variable('flow')
            time =  Variable('time')

            h5 = File(argv[2],'a')

            if argv[3] in h5:
                fl3 = h5[argv[3]]
            elif 'flows3' in h5:
                fl3 = h5['flows3']
            else:
                raise Exception('flows3 or %s not found'%argv[3])

            sampl = h5.require_group('samples_%s_%f'%(xsdfnc.__name__,srate))

            if ( '.srate' in sampl or '.wndsize' in sampl ) and ( sampl['.srate'] != srate or sampl['.wndsize'] != wndsize ):
                raise Exception('already processed for different srate and wndsize')

            if 'data' in fl3:
                flows3 = Dataset(h5=fl3['data'])
            else:
                flows3 = reduce(lambda x,y:x+y,(Dataset(h5=fl3[k]) for k in fl3.keys() if k.split('_',1)[0] == 'data') )
            id3 = Dataset(h5=fl3['flowid'])

            #flows4 = Dataset(data=fl4['flowdata'].value,fields=fl4['flowfields'].value)
            #id4 = Dataset(data=fl4['flowid'].value,fields=fl4['flowidfields'].value)

            spectrums = {}
            amplitudes = {}
            wids = {}
            ips = {}

            # some colorful sugar
            scalar = lambda x: x.item() if hasattr(x,'item') else x
            ipfmt = lambda i: '%s:* > %s:%d [%s]' % (int2ip(i[1]),int2ip(i[2]),i[3],reverseDns(int2ip(i[2])))
            ipfmt2 = lambda i: '%s:%d [%s]' % (int2ip(i[2]),i[3],reverseDns(int2ip(i[2])))
            ipfmtc = lambda i: '\033[32m%s\033[0m:\033[33m*\033[0m > \033[32m%s\033[0m:\033[33m%d\033[0m [\033[1;32m%s\033[0m]' % (int2ip(i[1]),int2ip(i[2]),i[3],reverseDns(int2ip(i[2])))

            stdout.write('\n')
            stdout.flush()

            flows = {}
            for f in flows3['flow']:
                f = scalar(f)
                if f not in flows:
                    flows[f] = 0
                else:
                    flows[f] += 1
            flows = dict((k,v) for k,v in flows.items() if v>100)

            l = 1
            #for f in flid[:chooseflows,0]:
            for id3row in id3:
                f = scalar(id3row['flow'])
                if f not in flows:
                    continue

                ip = tuple(scalar(id3row[i]) for i in ('flow', 'src','dst','dport'))
                ips[f] = ipfmt(ip)

                stdout.write('\rprogress: \033[33;1m%0.2f %%\033[0m, srate= \033[33;1m%f\033[0m Hz, \033[36mprocessing flow\033[0m: %s  '%(100.*l/len(flows),srate,ipfmtc(ip)))
                stdout.flush()
                l += 1

                # select related packets
                #fl =  flows[(flows[...,2] == f ),...]
                fl =  flows3.select(flow==f,retdset=True)
                tm = fl['time']
                mi = tm.min()
                ma = tm.max()

                k = mi
                i = 0
                spectrum = []
                amplitude = []
                wid = []
                unused = 0

                while k<ma:
                    # 10 dots progressbar
                    if (ma-mi)>=(10*wndspan) and  not ((k-mi)/wndspan) % (((ma-mi)/(10*wndspan))):
                        stdout.write('\033[36m.\033[0m')
                        stdout.flush()

                    #w = fl.data[(tm>=k) & (tm<k+wndsize*srate),...]
                    if 'paylen' in fl:
                        w = fl.select((time>=k)&(time<k+wndspan),retdset=True,fields=('time','paylen'))
                    else:
                        w = fl.select((time>=k)&(time<k+wndspan),retdset=True,fields=('time','packets','size'))

                    if not len(w)>0:
                        unused += np.sum(w['packets']) if 'packets' in w else len(w)
                        k += wndspan
                        i += 1
                        continue

                    # sampling intervals
                    bounds = np.linspace(k, k+wndspan, wndsize, endpoint=True)[...,np.newaxis]

                    amp,xsd = xsdfnc(w,bounds)

                    if not xsd.any():
                        unused += np.sum(w['packets']) if 'packets' in w else len(w)
                        k += wndspan
                        i += 1
                        continue

                    wid.append(i)
                    spectrum.append(xsd)
                    amplitude.append(amp)

                    k += wndspan
                    i += 1

                pkts = np.sum(fl['packets']) if 'packets' in fl else len(fl)

                if  len(amplitude):
                    amplitude = np.vstack(a[np.newaxis,...] for a in amplitude)
                    spectrum = np.vstack(a[np.newaxis,...] for a in spectrum)
                    #amplitudes[f] = amplitude
                    spectrums[f] = spectrum
                    wids[f] = np.array(wid)
                    if unused:
                        stdout.write('\r%s: unused \033[1;31m%d\033[0m of \033[1;34m%d\033[0m packets\033[K\n' %(ipfmtc(ip),unused,pkts))
                    else:
                        stdout.write('\r%s: used \033[1;34m%d\033[0m packets\033[K\n' %(ipfmtc(ip),pkts))
                else:
                    stdout.write('\r%s: unused \033[1;31m%d\033[0m packets\033[K\n' %(ipfmtc(ip),pkts))
                stdout.write('\rprogress: \033[33;1m%0.2f %%\033[0m, srate= \033[33;1m%f\033[0m Hz   '%(100.*l/len(flows),srate))
                stdout.flush()

            stdout.write('\rprogress: \033[33;1m100 %%\033[0m, srate= \033[33;1m%f\033[0m Hz    '% srate)
            stdout.flush()

            flows = list(spectrums.keys())

            X = np.vstack(spectrums[f] for f in flows) # spectrums
            #ampl = np.vstack(amplitudes[f] for f in flows) # amplitudes
            y = np.vstack(np.array([[f]]).repeat(spectrums[f].shape[0],0) for f in flows) # flows
            #wnds = np.vstack(wids[f][...,np.newaxis] for f in flows) # windows kept

            sampl.create_dataset('.srate',data=srate)
            sampl.create_dataset('.wndsize',data=wndsize)

            sampl.create_dataset('X',data=X)
            #sampl.create_dataset('A',data=ampl)
            sampl.create_dataset('y',data=y)
            #sampl.create_dataset('wnds',data=wnds)
            sampl.create_dataset('id',data=id3.data)
            sampl.create_dataset('idfields',data=id3.fields)
            sampl.create_dataset('freqs', data = fftfreq(wndsize-1,d=1./srate))

    elif argv[1] == 'model':
        h5 = File(argv[2],'a')
        def get_sampl(i):
            from dataset import Variable
            dport =  Variable('dport')
            sampl = h5[i]

            srate = sampl['.srate'].value
            wndsize = sampl['.wndsize'].value

            X = sampl['X'].value
            y = sampl['y'].value
            freqs = sampl['freqs'].value

            id3 = Dataset(data=sampl['id'].value,fields=sampl['idfields'].value)

            #web = (id3.select((dport==80)|(dport==443), fields=('flow',))).squeeze().tolist()
            #ssh = (id3.select((dport==22), fields=('flow',))).squeeze().tolist()
            #web.remove(4776559292263195127)
            #vpn = [4776559292263195127]
            #rtmp = [8380189417275335324]
            # some heuristics

            labeling,labeling2 = get_labeling(id3)

            print labeling2

            #labeling2 = {2:'ssh',4:'vpn',1:'web',3:'rtmp', None: 'unknown'}
            #labeling = dict((i,k) for k,v in {2 : [-552256902917098113,2247007671922456841],4:[4776559292263195127],1:[8380160408752905696,8380189416172033921,8410733012134650723,-469218773793942506,-2499874899238919737,-5041250675964824658,8580894899495251662,-4947266290287076305,-6617676552486822384,3553172765770232670,4958930730188020726,8698986197344828920,-2289429955555002898,-7120599107837071846,-8123220270916674052,3968969310196917918],3:[8380189417275335324]}.items() for i in v)
            #labeling = dict((i,k) for k,v in {2 :ssh,4:vpn,1:web, 3:rtmp}.items() for i in v)

            labels = np.array([[labeling.get(f) for f in y.squeeze()]]) # annotations

            return X,np.array([[labeling.get(f) for f in y.squeeze()]]),freqs

        class FitError(Exception):
            pass
        class base:
            def __init__(self, **kwargs):
                self.__dict__.update(kwargs)
            def _process(self, X, y, freqs):
                return X, y, freqs
            def fit(self, X, y, freqs):
                return self._process(X, y, freqs)
            def score(self,X,y, freqs):
                return self._process(X, y, freqs)
        class scale(base):
            def __init__(self, mean=True, std=True, **kwargs):
                base.__init__(self, mean=mean, std=std, **kwargs)
                self.scaler = None
            def fit(self, X, y, freqs):
                from sklearn.preprocessing import Scaler
                self.scaler = Scaler(with_mean=self.mean,with_std=self.std,copy=True)
                self.scaler.fit(X)
                return self.scaler.transform(X),y,freqs
            def score(self,X,y, freqs):
                return self.scaler.transform(X),y,freqs
        class freq_treshold(base):
            def __init__(self, f_thresh,  **kwargs):
                base.__init__(self, f_thresh=f_thresh, **kwargs)
            def _process(self, X, y, freqs):
                import numpy as np
                i = freqs.squeeze()>self.f_thresh
                return X[...,i],y,freqs[...,i]
        class freq_bands(base):
            def __init__(self, n_bands, **kwargs):
                base.__init__(self, n_bands=n_bands, **kwargs)
            def _process(self, X, y, freqs):
                import numpy as np
                n_samples = X.shape[0]
                bands = np.linspace(freqs.min(),freqs.max(),num=self.n_bands+1, endpoint=True)[np.newaxis,...]
                Xm = X[...,np.newaxis].repeat(self.n_bands,2)
                mask = (((bands[...,:-1]<=freqs[...,np.newaxis]) & (bands[...,1:]>=freqs[...,np.newaxis])))[np.newaxis,...].repeat(n_samples,0)
                return (Xm * mask).sum(1), y, bands
        class freq_low_hi(base):
            def __init__(self, f_thresh, **kwargs):
                base.__init__(self, f_thresh=f_thresh, **kwargs)
            def _process(self, X, y, freqs):
                import numpy as np
                n_samples = X.shape[0]
                Xm = X[...,np.newaxis].repeat(2,2)
                mask = np.hstack((freqs[...,np.newaxis] > self.f_thresh,freqs[...,np.newaxis] <= self.f_thresh))[np.newaxis,...].repeat(n_samples,0)
                #mask = (((bands[...,:-1]<=freqs[...,np.newaxis]) & (bands[...,1:]>=freqs[...,np.newaxis])))[np.newaxis,...].repeat(n_samples,0)
                return (Xm * mask).sum(1), y, None
        class freq_sdev(base):
            def __init__(self, dummy, **kwargs):
                base.__init__(self, **kwargs)
            def _process(self, X, y, freqs):
                import numpy as np
                return X.std(1), y, None
        class pca(base):
            def __init__(self, ndim, **kwargs):
                base.__init__(self, ndim=ndim, **kwargs)
                self.pca = None
            def fit(self, X, y, freqs):
                from sklearn.decomposition import PCA
                from scipy.linalg import LinAlgError
                self.pca = PCA(self.ndim)
                try:self.pca.fit(X)
                except LinAlgError: raise FitError()
                return self.pca.transform(X),y,freqs
            def score(self,X,y, freqs):
                return self.pca.transform(X),y,freqs
        class gmm(base):
            def __init__(self, lbl, **kwargs):
                from sklearn.mixture import DPGMM as GMM
                base.__init__(self, lbl=lbl, **kwargs)
                self.model = GMM(5, covariance_type='full', n_iter=100, params='mc', init_params='mc')
            def _process(self, X, y, freqs):
                y = np.copy(y)
                i = y.squeeze() == self.lbl
                y[...,i] = 1
                y[...,~i] = -1
                return X, y, freqs
            def fit(self, X, y, freqs):
                X, y, freqs = self._process(X, y, freqs)
                self.model.fit(X[y.squeeze() == 1,...])
                return X,y,freqs
            def score(self,X,y, freqs):
                from sklearn.metrics import roc_curve,auc
                X, y, freqs = self._process(X, y, freqs)
                score_raw = self.model.score(X)
                fpr, tpr, thresholds = roc_curve(y.squeeze(), score_raw)
                return (auc(fpr, tpr), (fpr, tpr,thresholds)),y,freqs
        class pipeline(base):
            def __init__(self, *args, **kwargs):
                base.__init__(self,**kwargs)
                self.callables = args
            def _process(self,X,y,freqs,**kwargs):
                callables = kwargs.get('callables') if 'callables' in kwargs else self.callables
                for c in callables:
                    X, y, freqs = c.fit(X, y, freqs)
                return X, y, freqs
            def fit(self, X, y, freqs):
                for c in self.callables:
                    X, y, freqs = c.fit(X, y, freqs)
                return X, y, freqs
            def score(self, X, y, freqs):
                for c in self.callables:
                    X, y, freqs = c.score(X, y, freqs)
                return X, y, freqs

        def iterate(name, *args):
            from itertools import product
            cmds = [arg[0] for arg  in args]
            params = product(*[arg[1] for arg  in args])
            return [ (tuple((cmds[i].__name__,param[i]) for i in range(len(cmds))),pipeline(*[cmds[i](param[i]) for i in range(len(cmds))])) for param in params ]


        def crossval(method, X, y, freqs, folds = 10):
            from sklearn.cross_validation import StratifiedKFold
            s = []
            d = []
            for train, test in StratifiedKFold(y.squeeze(), folds, indices=False):
                try:
                    method.fit(X[train,...],y[...,train],freqs)
                    (score,data),dummy,dummy = method.score(X[test,...], y[...,test], freqs)
                    s += score,
                    d += data,
                except FitError:
                    s+=-np.inf,
            return np.array(s),d
        try:
            methods = {}
            methods.update(iterate( 'bands', ( freq_treshold, (0,)) , ( freq_bands, (2,3,5,10,20,30)) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            methods.update(iterate( 'bands', ( freq_treshold, (0,)) , ( freq_sdev, (0,)) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            #methods.update(iterate( 'lowhi', ( freq_treshold, (0,)) ,( freq_low_hi, (5,10,20,40)) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            methods.update(iterate( 'pca', ( freq_treshold, (0,)) ,  ( pca, (3,5,7)) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            for k in (k for k in h5.keys() if k.startswith('samples_')):
            #for srate in (0.0033,):#(200,500,1000):
                srate= float(k.split('_')[1])
                print 'srate=%fHz'%srate
                X, y, freqs = get_sampl(k)
                f = []
                n = []
                scores = []
                for p,meth in methods.items():
                    s,d = crossval(meth, X, y, freqs)
                    name = '\t%s: score (mean=%f, std=%f)' % (','.join('%s(%d)'%n for n in p), s.mean(), s.std())
                    f += d[0],
                    n += 'srate=%f, %s' % (srate,'%s(%d)' % p[1]),
                    scores += s,
                    print name
                def plotline(x,y):
                    return lambda ax: ax.plot(x, y, '-')
                fig(list(plotline(fpr, tpr) for fpr, tpr, t in f),name=n,show=True)
        finally:
            h5.close()
    elif argv[1] == 'feature':
        from dataset import Variable,Dataset
        from scipy.fftpack import fftfreq,fft
        from sys import stdout
        from util import scatter,scalar

        flow = Variable('flow')
        src = Variable('src')
        dst = Variable('dst')
        dport = Variable('dport')
        sport = Variable('sport')

        h5 = File(argv[2],'a')

        if len(argv)>3:
        #for grp in (k for k in h5.keys() if k.startswith('samples_')):
        #for i in (100,200,500,1000,2000):
            grp = argv[3]
            #if grp not in h5:
            #    exit() # continue

            sampl = h5[grp]

            srate = sampl['.srate'].value
            wndsize = sampl['.wndsize'].value

            X = sampl['X'].value
            y = sampl['y'].value
            freqs = sampl['freqs'].value

            id3 = Dataset(data=sampl['id'].value,fields=sampl['idfields'].value)
            labeling,labeling2 = get_labeling(id3)
            labels = np.array([[labeling.get(f) for f in y.squeeze()]]) # annotations

            def pcatransform(ndim=2):
                from sklearn.decomposition import PCA
                t = PCA(ndim)
                def fnc(X):
                    t.fit(X[labels.squeeze().nonzero()[0],...])
                    return t.transform(X)
                return fnc
            def lowhitransform(srate, wndsize, fthresh=50):
                from scipy.fftpack import fftfreq
                freqs = fftfreq(wndsize-1,d=1./srate)
                return lambda X: np.vstack((X[...,freqs<=fthresh].sum(1),X[...,freqs>fthresh].sum(1))).transpose()
            def varnorm(X):
                return (X - X.mean(0).reshape((1,X.shape[1])) )/X.std(0).reshape((1,X.shape[1]))
            def logistnorm(X):
                from scipy.special import expit
                return expit(varnorm(X))
            def scatter1(ax):
                return scatter(ax, X, labels, varnorm, pcatransform(ndim=2), labeling2.get)
            def scatter1a(ax):
                return scatter(ax, X, labels, varnorm, pcatransform(ndim=2), labeling2.get)
            def scatter1b(ax):
                return scatter(ax, X, labels, logistnorm, pcatransform(ndim=2), labeling2.get)
            def scatter2a(ax):
                return scatter(ax, X, labels, None, lowhitransform(srate,wndsize,fthresh=10), labeling2.get)
            def scatter2b(ax):
                return scatter(ax, X, labels, varnorm, lowhitransform(srate,wndsize,fthresh=10), labeling2.get)
                #fignames =  'spectral features (srate=%dHz, wnd=%ds), %%s, %%s' %(srate,wndsize/srate)
            #fignames = [fignames%('variance normalization','2D pca projection'),fignames%('logistic normalization','2D pca projection')]
            #fig([scatter1a,scatter1b], fignames,show=True)
            #fignames =  'spectral features (srate=%dHz, wnd=%fs), %%s, %%s' %(srate,1.*wndsize/srate)
            #fignames = [fignames%('no normalization','low-pass/hi-pass energy'),fignames%('variance normalization','low-pass/hi-pass energy')]
            fig(scatter1,show=True)
