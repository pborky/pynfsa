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

    if opt.flowid == '3':
        fflow=('src','dst','dport')
        bflow=('dst','src','sport')
        flowid = 'flows3'
    elif opt.flowid == '4':
        fflow=('src', 'sport','dst','dport')
        bflow=('dst', 'dport','src','sport')
        flowid = 'flows4'
    else:
        raise NotImplementedError('flowid')

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

    if opt.flowid == '3':
        flowid = 'flows3'
    elif opt.flowid == '4':
        flowid = 'flows4'
    else:
        raise NotImplementedError('flowid')

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
        'Scaler': fapply( Scaler ),
        'Bands': fapply( FreqBands, 2,5,10 ),
        'BandsLg': fapply( FreqBands, 2,5,10, log_scale=True ),
        'Threshold': fapply( FreqThresh, 0 ),
        'MomentumMVKS': fapply( Momentum, 'mvks'),
        'GMM' : fapply( GMM, 1, 5, covariance_type='diag', n_iter=40 ),
        'DPGMM' : fapply( DPGMM, 1, 5, covariance_type='diag', n_iter=40 ),
        'Mahal': fapply( Mahalanobis, False ),
        'PCA': fapply( PCA, 3, 10 ),
        'PCAw': fapply( PCA, 3, 10 , whiten=True )
    }
    computations = [
        ('Bands', 'DPGMM'),
        #('BandsLg', 'DPGMM'),
        #('Bands','DPGMM'),
        #('Bands', 'Mahal'),
        ('Threshold','DPGMM'),
        #('Threshold','Scaler','DPGMM'),
        #('Threshold', 'Scaler','Mahal'),
        #('Threshold', 'Mahal'),
        #('Threshold', 'DPGMM'),
        ('Threshold','MomentumMVKS', 'Mahal' ),
        #('Threshold','MomentumMVKS', 'Scaler', 'Mahal' ),
        ('Threshold','MomentumMVKS',  'DPGMM' ),
        #('Threshold','PCA', 'Scaler', 'Mahal' ),
        #('Threshold', 'PCA', 'Mahal' ),
        ('Threshold', 'PCA', 'DPGMM' ),
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

        intornone = lambda x: int(x) if x.isdigit() else None

        model= filter(None,map(intornone,(m.strip() for m in opt.model.split(',')))) if opt.model else None  #[33, 34, 67, 82, 85]   #http
        legit= filter(None,map(intornone,(m.strip() for m in opt.legit.split(',')))) if opt.legit else None  #[33, 34, 67, 82, 85]
        malicious= filter(None,map(intornone,(m.strip() for m in opt.malicious.split(',')))) if opt.malicious else None  #[80]              # woodfucker
        if opt.computations:
            computations = [tuple(m.strip() for m in comp.split(',')) for comp in opt.computations]

        m,((fit, binarize, classes), res) = evaluate(opt, computations, sampl, fit=fit, binarize=binarize,steps=steps,model=model,legit=legit,malicious=malicious)
        plot_roc(res,'ROC curves')

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

    elif None:
        #TODO -> model.py
        from models import freq_treshold,freq_bands,freq_momentum,freq_sdev,freq_low_hi,pca,Scaler,gmm,pipeline,FitError,mahal
        h5 = H5Node(opt)

        def fapply(fnc, *args):
            from functional import partial
            if len(args):
                return [ (fnc(a),a) for a in args ]
            else:
                return (fnc(),None),

        def iterate( *args):
            from itertools import product
            return [( ','.join('%s(%s)'%(c.__name__,str(a)) for c,a in cmds) , pipeline(*[c for c,a in cmds])) for cmds in product(args)]

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
            #methods.update(iterate( 'bands', ( freq_treshold, (0,)) , ( freq_bands, (2,5,10,25))  , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            methods.update(iterate( fapply( freq_treshold, 0 ) , fapply( freq_bands, 5, 10 ) ,  fapply( mahal, 0 ) ))
            methods.update(iterate( fapply( freq_treshold, 0 ) ,  fapply( mahal, 0 ) ))
            methods.update(iterate( fapply( freq_treshold, 0 ) , fapply( freq_bands, 2,10 )  ,  fapply( gmm, 5, ) ))
            #methods.update(iterate( 'sdev', ( freq_treshold, (0,)) , ( freq_sdev, (0,)) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            methods.update(iterate( fapply( freq_treshold, 0 ) , fapply( freq_momentum, 14 ) , fapply( Scaler ) ,  fapply( gmm, 1 ) ))
            methods.update(iterate( fapply( freq_treshold, 0 ) , fapply( freq_momentum, 14 )  ,  fapply( mahal, 1 ) ))
            #methods.update(iterate( 'lowhi', ( freq_treshold, (0,)) ,( freq_low_hi, (5,10,20,40)) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            methods.update(iterate( fapply( freq_treshold, 0 ) , fapply( pca, 5 ) , fapply( Scaler ) ,  fapply( gmm, 1 ) ))
            #methods.update(iterate( 'lowhi', ( freq_treshold, (0,)) ,( freq_low_hi, (5e-6,6e-5,1.1e-4,1.6e-4,2.2e-4, 2.7e-4, 3.2e-4, 3.8e-4, 4.4e-4, 5e-5 )) , ( scale, (True,)) ,  ( gmm, (1,) ) ))
            samples = h5['samples']

            print(colorize(boldblue,green) * '#datasets found in database# %s:' %opt.database)
            datasets = []
            i = 0
            for k in samples.keys():
                if not k.startswith('data'):
                    continue
                sampl = samples[k]

                if  '.srate' not in sampl or  '.wndsize' not in sampl :
                    continue

                srate = scalar(sampl['.srate'])
                wndsize = scalar(sampl['.wndsize'])

                if srate not in opt.srate or wndsize not in opt.window:
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

            for k,sampl,srate,wndsize in selected:
            #for k in samples.keys():
                try:
                    #if not k.startswith('data'):
                    #    continue
                    #sampl = samples[k]

                    #srate = sampl['.srate'].value
                    #wndsize = sampl['.wndsize'].value

                    #if srate not in opt.srate or wndsize not in opt.window:
                    #    continue

                    print('## processing %s'%k)

                    X = sampl['X'][:]
                    y = sampl['y'][:]
                    freqs = sampl['freqs'][:]

                    id3 = sampl['flowids']

                    labeling,labeling2,labeling3 = get_labeling(opt,id3)

                    y =  np.array([[labeling.get(f) if f in labeling else 0 for f in y.squeeze()]])
                    print('## please hold on')

                    f = []
                    n = []
                    scores = []
                    results = []
                    for p,meth in methods.items():
                        s,d = crossval(meth, X, y, freqs)
                        results.append('\t%s: score (mean=%f, std=%f)' % (','.join('%s(%d)'%n for n in p), s.mean(), s.std()))
                        f += d[0],
                        n += 'srate=%f, %s' % (srate,'%s(%d)' % p[1]),
                        scores += s,
                    print('srate=%fHz, wndsize=%dsamps'%(srate,wndsize))
                    print('\n'.join(results))
                    def plotline(x,y):
                        return lambda ax: ax.plot(x, y, '-')
                    fig(list(plotline(fpr, tpr) for fpr, tpr, t in f),name=n,show=True)
                except Exception as e:
                    print(e)
                    raise
        finally:
            pass
            #h5.close()
    elif None:
        #TODO -> model.py
        from dataset import Variable,Table
        from scipy.fftpack import fftfreq,fft
        from sys import stdout

        flow = Variable('flow')
        src = Variable('src')
        dst = Variable('dst')
        dport = Variable('dport')
        sport = Variable('sport')

        h5 = File(opt.database,'a')

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

            id3 = Table(data=sampl['id'].value,fields=sampl['idfields'].value)
            labeling,labeling2 = get_labeling(id3)
            labels = np.array([[labeling.get(f) for f in y.squeeze()]]) # annotations

            def pcatransform(ndim=2):
                from sklearn.decomposition import PCA
                t = PCA(ndim)
                def fnc(X):
                    t.fit(X[labels.squeeze()==1,...])
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
