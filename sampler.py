
from util import *


def psd(w, bounds, filter=None):
    """power spectral density of packet process"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    import numpy as np
    if filter:
        allpkts = w[filter,'time'][np.newaxis,...]
    else:
        allpkts = w['time'][np.newaxis,...]
    amp = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    if 'packets' in w:
        if filter:
            packets = w[filter,'packets'][np.newaxis,...]
        else:
            packets = w['packets'][np.newaxis,...]
        amp = (amp*packets[...,0]).sum(1)
    else:
        amp = amp.sum(1)
    return amp,np.abs(fft(correlate(amp,amp,mode='same')))
def csd(w, bounds):
    """auto-correlation of packet process"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    import numpy as np
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
    return np.vstack((ampout,ampin)),np.abs(fft(correlate(ampout,ampin,mode='same')))
def psd1(w, bounds):
    """power spectral density of sum packet volume"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    import numpy as np
    allpkts = w['time'][np.newaxis,...]
    amp = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    if 'size' in w:
        size = w['size'][np.newaxis,...]
        amp = (amp*size[...,0]).sum(1)
    elif 'paylen in w':
        size = w['paylen'][np.newaxis,...]
        amp = (amp*size[...,0]).sum(1)
    return amp,np.abs(fft(correlate(amp,amp,mode='same')))

def psd2(w, bounds):
    """power spectral density of average packet volume"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    import numpy as np
    allpkts = w['time'][np.newaxis,...]
    amp = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    if 'packets' in w:
        packets = w['packets'][np.newaxis,...]
        packets = (amp*packets[...,0]).sum(1)
    else:
        packets = amp.sum(1)
    if 'size' in w:
        size = w['size'][np.newaxis,...]
        amp = (amp*size[...,0]).sum(1) / packets
    elif 'paylen' in w:
        size = w['paylen'][np.newaxis,...]
        amp = (amp*size[...,0]).sum(1) / packets
    return amp,np.abs(fft(correlate(amp,amp,mode='same')))

class Sampler(object):
    """ Generates samples of the packet traces
    """
    def __init__(self, opt):
        self.opt = opt
        self.srate = opt.srate # default 10 ms
        self.wndsize = opt.wndsize #
        if opt.transform == 'psd':
            self.xsdfnc = psd
        elif opt.transform == 'csd':
            self.xsdfnc = csd
        else:
            raise NotImplementedError('transform')

    def __call__(self, h5grp, flowdata, flowids):
        from itertools import product
        from sys import stdout
        from scipy.fftpack import fftfreq
        import numpy as np

        for srate,wndsize in product(self.srates,self.windows) : #srates:
            if srate<=0 :
                continue


            speriod = 1./ srate # sampling period in seconds
            wndspan = int(1e6 * wndsize * speriod) # window span in microseconds

            sampl = h5grp['data_%s_%f_%d'%(self.xsdfnc.__name__,srate,wndsize)]

            if '.srate' in sampl or '.wndsize' in sampl :
                if scalar(sampl['.srate']) != srate or scalar(sampl['.wndsize']) != wndsize:
                    raise Exception('already processed for different srate (%s) and wndsize (%s)' %(scalar(sampl['.srate']),scalar(sampl['.wndsize'])))
                print '## already processed for same srate and wndsize - overwriting '
                for k in sampl.keys():
                    del sampl[k]


            spectrums = {}
            amplitudes = {}
            wids = {}
            ips = {}

            # some colorful sugar
            ipfmt = lambda i: flow2str(i,dns=self.opt.reverse_dns,services=self.opt.reverse_dns, color=False)
            ipfmtc = lambda i: flow2str(i,dns=self.opt.reverse_dns,services=self.opt.reverse_dns, color=True)

            stdout.write('\n')
            stdout.flush()

            flows = {}
            for f in flowdata['flow'].squeeze():
                f = scalar(f)
                if f not in flows:
                    flows[f] = 0
                else:
                    flows[f] += 1
            flows = dict((k,v) for k,v in flows.items() if v>100)

            l = 1
            #for f in flid[:chooseflows,0]:
            for id3row in flowids:
                f = scalar(id3row['flow'])
                if f not in flows:
                    continue

                ips[f] = ipfmt(id3row)

                progress_tmpl = colorize(boldyellow,boldyellow,boldyellow,cyan,None,eraserest) * '\rprogress: %0.2f %%, srate= %f Hz, wndsize= %d, #processing flow#: %s#.#'
                stdout.write(progress_tmpl % (100.*l/len(flows),srate,wndsize,ipfmtc(id3row)))
                stdout.flush()
                l += 1

                # select related packets
                #fl =  flows[(flows[...,2] == f ),...]
                fl =  flowdata[flowdata.flow==f]
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
                        stdout.write(str(cyan('.')))
                        stdout.flush()

                    #w = fl.data[(tm>=k) & (tm<k+wndsize*srate),...]
                    if 'paylen' in fl:
                        w = fl[(fl.time>=k)&(fl.time<k+wndspan),'time','paylen']
                    else:
                        w = fl[(fl.time>=k)&(fl.time<k+wndspan),'time','packets','size']

                    if not len(w)>0:
                        unused += np.sum(w['packets']) if 'packets' in w else len(w)
                        k += wndspan
                        i += 1
                        continue

                    # sampling intervals
                    bounds = np.linspace(k, k+wndspan, wndsize, endpoint=True)[...,np.newaxis]

                    amp,xsd = self.xsdfnc(w,bounds)

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
                        stdout.write(colorize(None, boldred,boldblue,eraserest) *'\r%s: unused %d of %d packets#.#\n' %(ipfmtc(id3row),unused,pkts))
                    else:
                        stdout.write(colorize(None, boldblue,eraserest) *'\r%s: used %d packets#.#\n' %(ipfmtc(id3row),pkts))
                else:
                    stdout.write(colorize(None, boldred,eraserest) *'\r%s: unused %d  packets#.#\n' %(ipfmtc(id3row),pkts))

                progress_tmpl2 = colorize(boldyellow,boldyellow,boldyellow,eraserest) * '\rprogress: %0.2f %%, srate= %f Hz, wndsize= %d#.#'
                stdout.write(progress_tmpl2 %(100.*l/len(flows),srate,wndsize))
                stdout.flush()
            progress_tmpl3 = colorize(boldyellow,boldyellow,boldyellow,eraserest) * '\rprogress: #100# %%, srate= %f Hz, wndsize= %d#.#\n'
            stdout.write(progress_tmpl3 %(srate,wndsize))
            stdout.flush()

            if len(spectrums):
                flows = list(spectrums.keys())

                X = np.vstack(spectrums[f] for f in flows) # spectrums
                #ampl = np.vstack(amplitudes[f] for f in flows) # amplitudes
                y = np.vstack(np.array([[f]]).repeat(spectrums[f].shape[0],0) for f in flows) # flows
                #wnds = np.vstack(wids[f][...,np.newaxis] for f in flows) # windows kept

                sampl['.srate'] = srate
                sampl['.wndsize'] = wndsize

                sampl['X'] = X
                sampl['y'] = y
                sampl['freqs'] = fftfreq(wndsize-1,d=1./srate)

                flowids.save(sampl['flowids'])