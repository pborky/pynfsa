

from util import timedrun


def psd(w, bounds, filter=None):
    """power spectral density of packet process"""
    from scipy.signal import  correlate
    from scipy.fftpack import fft
    import numpy as np
    if callable(filter):
        allpkts = w['time'][np.newaxis,...][...,filter(w),...]
    else:
        allpkts = w['time'][np.newaxis,...]
    amp = ((allpkts[...,0] >= bounds[:-1,...]) & (allpkts[...,0] < bounds[1:,...]))
    if 'packets' in w:
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
    def __init__(self, epochsize = 300000000, srate = 100, slice = None):
        self.epochsize = epochsize # default 5 minutes
        self.srate = srate # default 10 ms
        self.slice = slice #

    def __call__(self, opt):
        pass