#!/usr/bin/python


from __future__ import print_function
from util import *

def annotate(opt, h5=None):
    """ Crappy feature allowing to create annotation file
    """
    from labeling import Labeler
    labeler = Labeler(opt)
    labeler.prepare()

    if 'samples' not in h5:
        return
    samples = h5['samples']
    opt.srate
    opt.window
    for k,sampl in samples.iteritems():

        if  '.srate' not in sampl or  '.wndsize' not in sampl :
            continue

        srate = scalar(sampl['.srate'])
        wndsize = scalar(sampl['.wndsize'])

        if opt.srate and  srate not in opt.srate or opt.window and wndsize not in opt.window:
            continue

        print(colorize(None,boldblue,green ) * '\n\n## #labeling sampleset# %s' % k)
        labeler(sampl)

def show_spectra(opt,h5=None):
    #TODO -> model.py
    from models import pipeline,freq_bands,freq_treshold
    from dataset import H5File
    if not h5:
        h5 = H5File(opt.database,'a')
    if 'samples' not in h5:
        raise Exception('no samples found')
    samples = h5['samples']
    for k in samples.keys():
        if k.startswith('data'):
            if  '.srate' not in samples[k] or '.wndsize' not in samples[k]:
                continue
            if samples[k]['.srate'].value !=  opt.srate  or  samples[k]['.wndsize'].value != opt.window:
                continue
            X = samples[k]['X'][:]
            y = samples[k]['y'][:].squeeze()
            freqs = samples[k]['freqs'][:].squeeze()
            id = samples[k]['flowids']
            labeling,labeling2,labeling3 =  get_annotations(opt,id)
            lab  = np.array([labeling.get(f) for f in y.squeeze()])
            fnc = pipeline(freq_treshold(0), freq_bands(50))
            for i in  labeling2:
                if not (lab==i).any():
                    continue
                Xr,yr,freqr = fnc.fit(X[(lab==i) ,...],lab[(lab==i)],freqs)
                freqr = freqr.squeeze()
                fig(lambda ax: ax.bar(left=freqr[:-1],width=freqr[1:]-freqr[:-1],height=Xr.mean(0)),name=labeling2[i])
def show_mahal(opt,h5=None):
    #TODO -> model.py
    from models import pipeline,freq_bands,freq_treshold
    if not h5:
        h5 = H5File(opt.database,'a')
    if 'samples' not in h5:
        raise Exception('no samples found')
    samples = h5['samples']
    for k in samples.keys():
        if k.startswith('data'):
            if  '.srate' not in samples[k] or '.wndsize' not in samples[k]:
                continue
            if samples[k]['.srate'].value !=  opt.srate  or  samples[k]['.wndsize'].value != opt.window:
                continue
            X = samples[k]['X'][:]
            y = samples[k]['y'][:].squeeze()
            freqs = samples[k]['freqs'][:].squeeze()
            id = samples[k]['flowids']
            labeling,labeling2,labeling3 =  get_annotations(opt,id)
            lab  = np.array([labeling.get(f) for f in y.squeeze()])
            fnc = pipeline(freq_treshold(0), freq_bands(50))
            for i in  labeling2:
                if not (lab==i).any():
                    continue
                Xr,yr,freqr = fnc.fit(X[(lab==i) ,...],lab[(lab==i)],freqs)
                freqr = freqr.squeeze()
                fig(lambda ax: ax.bar(left=freqr[:-1],width=freqr[1:]-freqr[:-1],height=Xr.mean(0)),name=labeling2[i])
def get_raw(opt, callback=None, keys=(), h5=None):
    from extractor import PcapExtractor,FlowExtractor
    from os.path import isfile,basename

    if opt.in_format == 'pcap':
        extract = PcapExtractor( ('time','src','sport','dst','dport','proto','paylen','flags', 'flow') )
        tr = h5['traces'] if h5 else None
        praser = get_packets
    elif opt.in_format == 'netflow':
        extract = FlowExtractor( ('time', 'duration','src','sport','dst','dport','proto', 'packets', 'size','flags', 'flows', 'flow') )
        tr = h5['netflows']  if h5 else None
        praser = get_netflow
        #def praser(fn, extract):
        #    f = open(fn,'r')
        #    try: flows = f.readlines()
        #    finally: f.close()
        #    return filter(None,map(extract,flows))
    else:
        raise NotImplementedError('in_format')

    if tr is not None:
        if not callable(callback):
            callback = lambda data,fn: data.save(tr[fn])
        if not keys:
            keys = tr.keys()
    else:
        if not callable(callback):
            raise Exception('h5 file needed')

    for fn in opt.file:
        if isfile(fn) and basename(fn) not in keys:
            print('## Extracting features from file %s...' % fn)
            pkts = praser(fn,extract)
            print('\t%d records captured' % len(pkts))
            data = Table(pkts, extract.fields)
            del pkts
            print('## Storing matrix in %s...' % opt.database)
            callback(data,basename(fn))

def get_flow(opt, h5 = None):
    from flowizer import Flowizer
    from operator import add
    from dataset import H5Node

    result = [[],None]
    def process(data,flowize,postfix='',flowids=None):
        print('## Extracting flows using %s-tuple'%opt.flowid)
        fl = h5[flowid]
        print('## flows count: %d' % (len(flowids) if flowids else 0))
        q,f = flowize(data, flowids=flowids if flowids else None)
        dataname= 'data_%s'%postfix if postfix else 'data'
        for i in (dataname,'flowids'):
            if i in fl:
                del fl[i]
        print('## Storing matrices in %s...' % opt.database)
        f.save(fl[dataname])
        q.save(fl['flowids'])
        result[0].append(f)
        result[1] = q

    if not h5 :
        h5 = H5Node(opt,'a')

    fflow, bflow, flowid = flowiddataset(opt)

    if opt.in_format == 'pcap':
        fields = ('time', 'paylen', 'flow')
        tr = h5['traces'] if 'traces' in h5 else None
    elif opt.in_format == 'netflow':
        fields = ('time', 'size', 'packets', 'flow')
        tr = h5['netflows'] if 'netflows' in h5 else None
    else:
        raise NotImplementedError('in_format')

    flowize = timedrun(Flowizer(fields = fields,fflow=fflow,bflow=bflow,opt=opt))

    fl = h5[flowid]
    if 'flowids' in fl:
        result[1] = fl['flowids']
        result[1].data = result[1].data[:]
    if not tr:
        keys = [ i[1] for i in (k.split('_',1) for k in fl.keys()) if len(i) > 1 ]
        get_raw(opt,lambda x,fn:process(x,flowize,fn,flowids=result[1]),keys=keys)
    else:
        try:
            data = reduce(add,(tr[k] for k in sorted(tr.keys()))  )
            process(data,flowize,flowids=result[1])
        except MemoryError:
            print(colorize(boldred,red) * '#out of memory:# #trying conservative approach..#')
            for k in sorted(tr.keys()):
                data = tr[k]
                process(data,flowize,k,flowids=result[1])
    return tuple(result)

def get_samples(opt, h5= None):
    #TODO -> sampler.oy
    from sampler import Sampler
    from dataset import Table,H5Node
    from scipy.fftpack import fftfreq
    from sys import stdout
    from itertools import product
    from operator import add

    _, _, flowid = flowiddataset(opt)

    sampler = Sampler(opt)

    if flowid in h5:
        fl3 = h5[flowid]
        if 'data' in fl3:
            flows3 = fl3['data']
        else:
            keys = [k for k in fl3.keys() if k.startswith('data_')]
            if keys:
                flows3 = reduce(add,(fl3[k] for k in keys) )
            else:
                print('## no flow data in h5 database, trying to get it from raw files')
                if not opt.file:
                    raise Exception('No flow data specified. Try to specify some pcap or netflow files on command line.')
                flows3,id3 = get_flow(opt,h5 = h5)
                flows3 = reduce(add, flows3 )
        id3 = fl3['flowids']
        if 'data' not in fl3:
            stdout.write('## storing \'data\' in database %s..' % opt.database)
            try:
                flows3.save(fl3['data'])
            except Exception as e:
                stdout.write(colorize(boldred,red) * '\t#error:# %s\n' % str(e))
            else:
                stdout.write(colorize(green) * '\t#OK#\n')
    else:
        flows3,id3 = get_flow(opt,h5 = h5)
        flows3 = reduce(add, flows3 )

    samples = h5['samples']

    sampler(samples,flows3,id3)

def get_models(opt, h5= None):
    from models import evaluate,plot_roc,fapply,Mahalanobis,Momentum,FreqThresh,FreqBands
    from sklearn.preprocessing import Scaler
    from sklearn.decomposition import PCA
    from sklearn.mixture import GMM,DPGMM
    from sklearn.manifold import LocallyLinearEmbedding,Isomap
    from labeling import Labeler
    import re

    if not h5:
        h5 = H5Node(opt)
    samples = h5['samples']

    print(colorize(boldblue,green) * '#datasets found in database# %s:' %opt.database)
    datasets = []
    i = 0
    for k,sampl in samples.iteritems():
        if  '.srate' not in sampl or  '.wndsize' not in sampl :
            continue

        srate = scalar(sampl['.srate'])
        wndsize = scalar(sampl['.wndsize'])

        if opt.srate and  srate not in opt.srate or opt.window and wndsize not in opt.window:
            continue

        if opt.sample and not re.findall(opt.sample, k):
            continue

        print(colorize(boldyellow,green) * '[%d] %s : (srate=%f, wndsize=%d)'%(i,k,srate,wndsize))

        datasets.append((i,(k,sampl,srate,wndsize)))
        i+=1
    datasets = dict(datasets)

    if len(datasets)>1:
        selected = []
        while not selected:
            s = raw_input('datasets to use:')
            selected = [datasets[int(i.strip())] for i in s.split(',')]
    else:
        selected = datasets.values()

    steps = {
        #'Scaler': fapply( Scaler ),
        'Bands': fapply( FreqBands, 2,5,10 ),
        #'BandsLg': fapply( FreqBands, 2,5,10, log_scale=True ),
        'Threshold': fapply( FreqThresh, 0 ),
        'Momentum': fapply( Momentum, 'vks'),
        #'GMM' : fapply( GMM, 1, 5, covariance_type='diag', n_iter=40 ),
        'DPGMM' : fapply( DPGMM, covariance_type='diag', n_iter=40 ),
        'Mahal': fapply( Mahalanobis, False ),
        'PCA': fapply( PCA, 1, 3 ),
        'PCA2': fapply( PCA  ),
        #'PCAw': fapply( PCA, 3, 10 , whiten=True )
    }
    if not opt.computations : opt.computations = [
        #('Bands', 'DPGMM'),
        ('Bands', 'Mahal'),
        #('BandsLg', 'DPGMM'),
        #('Threshold','DPGMM'),
        #('Threshold', 'Mahal'),
        ('Threshold','Momentum', 'Mahal' ),
        #('Threshold','MomentumMVKS',  'DPGMM' ),
        ('Threshold', 'PCA', 'Mahal' ),
        #('Threshold', 'PCA', 'DPGMM' ),
        #('Threshold', 'PCAw', 'DPGMM' )
    ]

    for k,sampl,srate,wndsize in selected:

        print('## processing %s'%k)

        if not 'annot' in sampl:
            labeler = Labeler(opt)
            labeler.prepare()
            labeler(sampl)

        fit, binarize = None, None
        #sampl, = [ h5[s] for s in ('/samples/data_psd_0.003300_200_simulated/', '/samples/data_psd_100.000000_200_simulated/') if s in h5 ]

        splitToInts = lambda x: [ int(i) for i in (m.strip() for m in x.split(',') if isString(m)) if i.isdigit() ]

        model = splitToInts(opt.model) if opt.model is not None else None
        legit = splitToInts(opt.legit) if opt.legit is not None else None
        malicious = splitToInts(opt.malicious) if opt.malicious is not None else None

        m,((fit, binarize, classes), res) = evaluate(opt, None, sampl,steps=steps,model=model,legit=legit,malicious=malicious)
        plot_roc(res,'ROC curves')

        if opt.tex:
            f = open(opt.tex,'a')
            try:
                f.write('\n')
                f.write(r'''
\begin{table}[h]
    \begin{center}
        \begin{tabular}{c|cc}
            Method & $\overline{\mu_{auc}}$ & $\overline{\sigma_{auc}}$ \\ \hline

%s

        \end{tabular}
    \end{center}
    \caption{Mean and standard deviation of the area under ROC curve.}
\end{table}
''' % '\\\\ \hline\n'.join(('%s & %.3f & %.3f' % (name.replace('_','\_'),np.mean(auc),np.std(auc))) for name,auc,_ in res))
                f.write('\n')
            finally:
                f.close()

        return m,((fit, binarize, classes), res)

if __name__=='__main__':
    from dataset import Table,H5Node
    from info import __graphics__
    from sys import stdout

    import numpy as np
    import functional
    import models
    import logging

    logging.captureWarnings(True)
    logging.basicConfig(level='ERROR')

    stdout.write(__graphics__)

    opt, longopts, shortopts = opts()
    NotImplementedError = lambda s: ValueError('Choice %s %s not implemented'%(longopts.get(s) or shortopts.get(s),getattr(opt,s)))


    if opt.action == 'filters':

        import json
        from os.path import isfile
        from sys import stdout
        f = open(opt.out_file,'w') if opt.out_file else stdout
        try:
            print(json.dump([get_filter(f.strip()) for f in opt.file if isfile(f)], f))
        finally:
            f.close()

    elif opt.action == 'load':

        h5 = H5Node(opt)
        try:
            get_ipython
        except NameError:
            banner=exit_msg=''
            # First import the embed function
            from IPython.config.loader import Config
            from IPython.frontend.terminal.embed import InteractiveShellEmbed
            # Now create the IPython shell instance. Put ipshell() anywhere in your code
            # where you want it to open.
            ipshell = InteractiveShellEmbed(banner1=banner, exit_msg=exit_msg)
        else:
            banner = '*** Nested interpreter ***'
            exit_msg = '*** Back in main IPython ***'
            def ipshell():pass
        ipshell()

    elif opt.action == 'raw':

        H5Node(opt).handle_exit(get_raw)

    elif opt.action == 'annotate':

        H5Node(opt).handle_exit(annotate)

    elif opt.action == 'flow':

        H5Node(opt).handle_exit(get_flow)

    elif opt.action == 'sample':

        H5Node(opt).handle_exit(get_samples)

    elif opt.action == 'model':

        H5Node(opt).handle_exit(get_models)
