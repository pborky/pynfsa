
from __future__ import print_function
from util import *

import numpy as np
import scipy.stats as st
from functional import *

def evaluate(opt, computations, h5grp, model=None, legit=None, malicious=None, model_legit=None,steps=None):
    m = Modeler(opt,computations,steps=steps)
    if 'annot' not in h5grp:
        raise Exception('expecting annotated dataset')
    fit,binarize,classes = m._get_labeling(h5grp['annot'],model=model, legit=legit, malicious=malicious, model_legit=model_legit)
    return m,m(fit=fit, binarize=binarize, h5grp=h5grp)

def plot_roc(res, title=''):
    from matplotlib.pylab import plt
    from math import ceil
    from functional import add
    colors = [ 'r-','g-', 'b-', 'c-', 'm-', 'rx-','gx-', 'bx-', 'cx-', 'mx-', 'ro-','go-', 'bo-', 'co-', 'mo-', 'r.', 'g.', 'b.', 'c.', 'm.'   ]
    colors*=int(1+ceil(20 / len(colors) ))
    idx = list( np.argsort([np.mean(auc) for _, auc, _ in res]) )
    values = reduce(add,( [fpr,tpr,colors.pop(0)] for fpr, tpr, thr in (d[0] for _, _, d in (res[i] for i in reversed(idx))) ),[])
    names =  list( u'%s [auc=%.2f\u00b1%.2f]'%(n,np.mean(auc),np.std(auc)) for n, auc, _ in (res[i] for i in reversed(idx)) )
    plt.subplots_adjust(left=.05, bottom=.05, right=.95, top=.95, wspace=.4, hspace=.4)
    ax1 = plt.subplot2grid((5,1), (1, 0), rowspan=4)
    ax2 = plt.subplot2grid((5,1), (0, 0),frameon=False,xticks=[],yticks=[])
    ln = ax1.plot( *values )
    ax1.fill_between( [0,1],[0,0],[0,1],facecolor='red',alpha=0.15 )
    ax1.set_xlabel('false positive rate')
    ax1.set_ylabel('true positive rate')
    ax2.legend(ln, names, loc=10, ncol = 1, mode='expand', prop={'size': 10})
    plt.show()


def fapply(fnc, *args, **kwargs):
    """Function application over list of arguments.
    Applies function to each positional argument and returns list of result.
    If the particular arguemtn is iterable, it is ufloded before in invocation.
    Keyword arguments are passed in all invocations.

    """
    kwstr = ['%s=%s'%i for i in  kwargs.iteritems()]
    fkey = lambda fnc: '%s' % fnc.__name__
    fargs = lambda arg: arg if isListLike(arg) else (arg,)
    fstring = lambda fnc,arg: '%s(%s)' %(fkey(fnc), ','.join([str(s) for s in fargs(arg)]+list(kwstr)))
    if len(args):
        return [ (fkey(fnc), fstring(fnc,a), fnc(*fargs(a))) for a in args ]
    else:
        return  (fkey(fnc), fstring(fnc,()) ,fnc()),

def fiterate( *args):
    """Generate pipeline compising all of the arguments. Particular arguments ought to be iterable
    and Cartesian product of them is computed. Each value in iterables must comform to Pipeline specs.

    """
    from itertools import product
    return [ (','.join(name for key,name,fnc in cmds), PipelineFixd([(key,fnc) for key,name,fnc in cmds])) for cmds in product(*args) ]

class Modeler(object):
    """Constructs Modeler callable object used to compute and evaluate several models.

    Parameters
    ----------
    opt : argparse.Namespace
        Arguements passed in command line.
    computations : iterable
        Each item defines an computation. Computation is defined by list of keys to steps argument.
    steps : dictionary
        Step of the computation. Steps are iterables that can be variants of same method.

    """
    def __init__(self,opt, computations=None, steps=None):
        self.opt = opt
        from sklearn.mixture import GMM,DPGMM
        from sklearn.decomposition import PCA
        from sklearn.preprocessing import Scaler

        self.steps = steps if steps is not None else {
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
        computations = opt.computations if opt.computations else [
            ('Bands','GMM'),
            ('Bands','Mahal'),
            ('Threshold','Mahal'),
            ('Threshold','MomentumMVKS', 'Mahal' ),
            ('Threshold','MomentumMVKS', 'Scaler', 'Mahal' ),
            ('Threshold','PCA', 'Scaler', 'Mahal' ),
            ('Threshold','PCA', 'Scaler', 'GMM' )
        ]
        computations = [(tuple(m.strip() for m in comp.split(',')) if isinstance(comp,str) else comp) for comp in computations]
        self.methods = self._methods(computations)

    def _methods(self,computations):
        return dict( reduce(add, ( fiterate(*[ self.steps[m] for m in c if m in self.steps])  for c in computations ) ) )


    def _get_labeling(self,h5grp,model=None,legit=None,malicious=None,model_legit=None):
        annot = h5grp['annotations'][:]
        filter = None
        if model is not None and legit is not None and malicious is not None:
            model_legit = not set(model).intersection(set(malicious))
            filter =  set(model + legit+ malicious)
        print (colorize(boldblue, green) * '#annotations detected#:' )
        annotations = {}
        for i,type, caption in ((int(scalar(a['annot'])),scalar(a['type']),scalar(a['caption'])) for a in annot):
            if filter is not None and i not in  filter:
                continue
            if type == 'FILTER_LEGITIMATE':
                print (colorize(boldyellow, green) * '[%d] %s : %s' % (i, type, caption))
            elif type == 'FILTER_MALICIOUS':
                print (colorize(boldyellow, boldred) * '[%d] %s : %s' % (i, type, caption))
            else:
                print (colorize(boldyellow, yellow) * '[%d] %s : %s' % (i, type, caption))
            annotations[i] = (type, caption)
        def get_classes(msg):
            model = []
            while not model:
                s = raw_input(msg)
                model = [k for k,v in annotations.iteritems() if s in v]
                if not model:
                    try:
                        model = [ j for j in ( int(i.strip()) for i in  s.split(',') ) if j in annotations]
                    except KeyboardInterrupt:
                        break
                    except :
                        pass
            return model
        if model is None: model  = get_classes('classes included in model: ')
        if legit is None: legit  = get_classes('normal classes: ')
        if malicious is None: malicious  = get_classes('anomal classes: ')
        if model_legit is None:
            while model_legit is None:
                try: model_legit = bool(int(raw_input('model is normal: ')))
                except KeyboardInterrupt: break
                except : pass

        print (colorize(boldblue, green) * '#annotations used#:' )
        print(colorize(green if model_legit else boldred, green, boldred ) *
              'model=%s, legit=%s, malicious=%s' %
              (str(model), str(legit), str(malicious), ))

        classes = {}
        if model_legit:    # 2 - positive (alarm) 1 - negative
            classes.update((i,-1) for i in legit if i not in model)
            classes.update((i,1) for i in malicious if i not in model)
            classes.update((i,-1) for i in model)
        else:              # 1 - positive (alarm) -1 - negative
            classes.update((i,1) for i in legit if i not in model)
            classes.update((i,2) for i in malicious if i not in model)
            classes.update((i,2) for i in model)

        binarize = np.vectorize(lambda x: classes[x] if x in classes else 0)

        return model, binarize, classes
    def _eval(self, score_raw, ybin):
        from sklearn.metrics import roc_curve,auc
        idx = ybin != 0
        ybin = ybin[idx]
        model_legit = np.unique(ybin)[0]
        score_raw = model_legit * score_raw[idx]
        fpr, tpr, thresholds = roc_curve(ybin, score_raw)
        return auc(fpr, tpr), (fpr, tpr,thresholds)

    def _crossval(self, method, X, y, binarize=None, fit=None, folds = 10, name='', **params):
        from sklearn.cross_validation import StratifiedKFold

        fit = np.array(fit)
        y = np.copy(y.squeeze())

        ybin = binarize(y)
        idx = ybin != 0

        X = X[idx,...]
        y = y[idx]
        ybin = ybin[idx]

        y_uni,y_sorted =  np.unique(y, return_inverse=True)
        y_cnt = np.bincount(y_sorted)
        y_wrong = y_uni[y_cnt<=folds]

        print(colorize(cyan, boldblue) * '#evaluating# %s:' % (name, ))

        if len(y_wrong):
            if np.any(fit[...,np.newaxis] == y_wrong):
                #fit = fit[np.any(fit[...,np.newaxis] == y_wrong,0).squeeze()]
                raise Exception('The fitted class has less than %d members, which is too few. %s' % (folds,str(y_wrong)))
            print(colorize(None,boldred,red)*'## #warning#: #%d classes has less than %d members, discaring them#'%(len(y_wrong),folds))
            idx = np.all(y[np.newaxis,...] != y_wrong[...,np.newaxis],0)
            X = X[idx,...]
            y = y[idx]
            ybin = ybin[idx]

        idx = np.all(np.isfinite(X),1)
        X = X[idx,...]
        y = y[idx]
        ybin = ybin[idx]

        fit = np.any(y == fit[...,np.newaxis],0)
        ybincls = np.unique(ybin[ybin!=0])
        if len(ybincls) != 2:
            raise Exception('Expecting binary classification instead of:' + str(ybincls))

        modelcnt = np.sum(fit)
        negcnt = np.sum(ybin==ybincls[0])
        poscnt = np.sum(ybin==ybincls[1])


        print(colorize(boldyellow, cyan, boldred, green) *
              '\t#using# #%d samples for model#, #%d positive (malicious)# and #%d negative (legitimate)# samples for validation ' %
              (modelcnt, poscnt, negcnt))

        #unknown = y==-1
        s=[]; roc = []
        for train, test in StratifiedKFold(y, folds, indices=False):
            train &= fit
            #test &= unknown
            try:
                method.fit(X[train,...], **params)
                scores = method.score(X[test,...], y[test])
                auc,(fpr, tpr,thresholds) = self._eval(scores.squeeze(),ybin[test])
                s.append(auc.mean())
                roc.append((fpr, tpr,thresholds))
            except FitError:
                s.append(-np.inf)

        print(colorize(cyan,boldyellow, yellow) * u'\t#auc#=%.2f#\u00b1%.2f#' % (np.mean(s),np.std(s)))

        return np.array(s),roc

    def __call__(self, h5grp = None, fit=None, binarize = None):

        sampl = h5grp
        annot = sampl['annot']

        X = sampl['X'][...]
        y = sampl['y'][...]
        freqs = sampl['freqs'][...]

        #flowids = sampl['flowids'][...]

        annotations = annot['annotations'][...]
        lbl = annot['y'][...]
        aflowids = annot['flowids'][...]

        #from models import Modeler
        #sampl = h5['/samples/data_psd_0.003300_200_simulated/']
        #annot = sampl['annot']
        #X = sampl['X'][...]
        #y = sampl['y'][...]
        #lbl = annot['y'][...]
        #freqs = sampl['freqs'][...]
        #annotations = annot['annotations'][...]
        #binary = {'FILTER_MALICIOUS':1, 'FILTER_LEGITIMATE': -1}
        #binary = dict((int(scalar(a['annot'])),binary.get(scalar(a['type']),0))  for a in annotations)
        #binarize = np.vectorize(lambda x: binary[x] if x in binary else 0)
        #binarize = np.vectorize(lambda x: 1 if x in (82,) else -1 )
        #m = Modeler(opt)
        classes = {}
        if fit is None or binarize is None:
            fit,binarize,classes = self._get_labeling(annot)

        #methods = self._methods(computations)
        res = []
        for k,v in self.methods.items():
            #print k
            s,roc = self._crossval(v, X , lbl, binarize , fit, name=k, FreqBands__freqs=freqs, FreqThresh__freqs=freqs)
            res.append((k,s,roc))
        return (fit,binarize,classes), res




from sklearn.base import BaseEstimator,TransformerMixin

class FitError(Exception):
    pass
class NotImplementedYet(Exception):
    pass


class LinearTransformer(BaseEstimator, TransformerMixin):
    """Projection to nex space determined by projection matrix.

    Parameters
    ----------
    A : array-like, shape [n_orig_features,n_new_features] or callable
        The transformation is denoted as dot prodct: Y = XA.
        If parameter A is callable, the matrix determined during fit.
    """
    def __init__(self, A):
        if callable(A):
            self.getA = A
            self.A = None
        elif A is None:
            raise ValueError('Must provide matrix or callable.')
        else:
            self.getA = None
            self.A = A
    def fit(self, X, y=None, **params):
        """If cellable has been provided instead of matrix A it is invoked
        on **params dictionaty to determine A in formula: Y = XA.

        Parameters
        ----------
        X : array-like, shape [n_samples, n_features]
            Original feature set.
        y : array-like, shape [ n_samples, 1]
            Class information. Not used in linear transform.
        params : additional parameters, implemented in subclasses

        Returns
        -------
        self : object
            Returns self.
        """
        if callable(self.getA):
            self.A = self.getA(X,**params)

        return self

    def transform(self, X, y=None):
        """Perform linear transformation : Y = XA

        Parameters
        ----------
        X : array-like, shape [n_samples, n_features]
            Original feature set.
        y : array-like, shape [ n_samples, 1]
            Class information. Not used in linear transform.

        Returns
        -------
        X_transformed : array-like [n_samples, n_new_features]
            Transformed feature space.
        """
        from sklearn.utils.validation import warn_if_not_float
        return np.dot(X,self.A)

class FreqBaseTransformer(LinearTransformer):
    def __init__(self):
        """Base class for frequency based transformations.
            The transformation matrix A is computed according to
            frequency vector in function `get_A` that must be
            overriden in child classes.
        """
        super(FreqBaseTransformer, self).__init__(self._get_A)
    def _get_A(self, X, freqs=None, **params):
        """Returns transforamtion matrix based on impelentation
            of the `get_A`. This is internal class.
        """
        A = self.get_A(X,freqs)
        return A
    def get_A(self, X, freqs):
        """Returns transforamtion matrix.
            To be implemented in subclass
        """
        raise NotImplementedYet()

class FreqThresh(FreqBaseTransformer):
    """Creates projection based on frequency thresholds.
    The frequency components that are greater then threshold
    are retained, others are discarded. If optional upper
    thredhold is provided it is applied in conjuction with
    lower threshold.


    Parameters
    ----------
    f_thresh : number , lower threshold
    f_thresh_hi : number , upper threshold

    """
    def __init__(self,f_thresh, f_thresh_hi=None):
        super(FreqThresh, self).__init__()
        self.f_thresh = f_thresh
        self.f_thresh_hi = f_thresh_hi
    def get_A(self, X, freqs):
        """Returns transformation matrix. Used internally.
        """
        idx = freqs>self.f_thresh
        if self.f_thresh_hi is not None:
            idx &= freqs<=self.f_thresh_hi
        n_old_features = X.shape[1]
        n_new_features = np.sum(idx)
        A = np.zeros(shape=(n_old_features,n_new_features))
        A[idx,...] = np.eye(n_new_features)
        return A

class FreqBands(FreqBaseTransformer):
    """Creates projection based on frequency band filtering.
    The frequency spectrum is divided into equal or logatitmic intervals
    in which are spectral components summed.

    Parameters
    ----------
    n_bands : number of bands
    log_scale : boolean, if true logarithic scale instead of linear is used,
                default: False

    """
    def __init__(self,n_bands, log_scale = False, mean=False):
        super(FreqBands, self).__init__()
        self.n_bands = n_bands
        self.log_scale = log_scale
        self.mean = mean
    def get_A(self, X, freqs):
        """Returns transformation matrix. Used internally.
        """
        if self.log_scale:
            bands = np.logspace(0,np.log2(freqs.max()),num=self.n_bands+1, endpoint=True,base=2)
        else:
            bands = np.linspace(0,freqs.max(),num=self.n_bands+1, endpoint=True)
        bounds_low = bands[:-1][np.newaxis,...]
        bounds_hi = bands[1:][np.newaxis,...]
        freqs = freqs[...,np.newaxis]
        A = 1.*((freqs > bounds_low) & (freqs <= bounds_hi))
        if self.mean:
            Asum = np.sum(A,0)
            A[...,Asum!=0] /=  Asum[Asum!=0][np.newaxis,...]
        return A

class Momentum(BaseEstimator, TransformerMixin):
    """ Computation of the moments of an data instance result in
    features in new feature space where each dimension is dedicated
    to particular moment.

    Parameters
    ----------
    moments : string where characters denote moment estimator:
            'm' - mean
            'v' - variance
            'k' - kurtosis
            's' - skewness
            ordering determines the ordering of the computations
    """
    _moments_map = {'m':np.mean, 'v':np.var , 'k': st.kurtosis, 's': st.skew }
    def __init__(self, moments = 'mvks'):
        if not all(k in self._moments_map for k in moments):
            raise ValueError('Unexpected value: %s'%moments)
        self.moment_fnc = [self._moments_map[k] for k in moments ]
    def fit(self, X, y=None, **params):
        """Dummy function does nothing
        """
        return self

    def transform(self, X, y=None):
        """Perform calculation of the moments over features.

        Parameters
        ----------
        X : array-like, shape [n_samples, n_features]

        Returns
        -------
        moments : array-like ith shape [n_samples, n_moments]
            Moments of the original features. Ordering of
            the moments is according to argument `moments`
            given in initialization of the object
        """
        from sklearn.utils.validation import warn_if_not_float
        return np.hstack(tuple(m(X,axis=1)[...,np.newaxis] for m in self.moment_fnc))

class Mahalanobis (BaseEstimator):
    """Mahalanobis distance estimator. Uses Covariance estimate
    to compute mahalanobis distance of the observations
    from the model.

    Parameters
    ----------
    robust : boolean to determine wheter to use robust estimator
        based on Minimum Covariance Determinant computation
    """
    def __init__(self, robust=False):
        if not robust:
            from sklearn.covariance import EmpiricalCovariance as CovarianceEstimator #
        else:
            from sklearn.covariance import MinCovDet as CovarianceEstimator #
        self.model = CovarianceEstimator()
        self.cov = None
    def fit(self, X, y=None, **params):
        """Fits the covariance model according to the given training
        data and parameters.

        Parameters
        ----------
        X : array-like, shape = [n_samples, n_features]
            Training data, where n_samples is the number of samples and
            n_features is the number of features.

        Returns
        -------
        self : object
            Returns self.
        """
        self.cov = self.model.fit(X)
        return self
    def score(self, X, y=None):
        """Computes the mahalanobis distances of given observations.

        The provided observations are assumed to be centered. One may want to
        center them using a location estimate first.

        Parameters
        ----------
        X : array-like, shape = [n_samples, n_features]
          The observations, the Mahalanobis distances of the which we compute.

        Returns
        -------
        mahalanobis_distance : array, shape = [n_observations,]
            Mahalanobis distances of the observations.
        """

        #return self.model.score(X,assume_centered=True)
        return - self.model.mahalanobis(X-self.model.location_) ** 0.33

from sklearn.pipeline import Pipeline

class  PipelineFixd (Pipeline):
    def _pre_transform(self, X, y=None, **fit_params):
        fit_params_steps = dict((step, {}) for step, _ in self.steps)
        for pname, pval in fit_params.iteritems():
            pname2 = pname.split('__', 1)
            if len(pname2) == 1:
                continue
            else:
                step, param = pname2
                if  step not in  fit_params_steps:
                    continue
                fit_params_steps[step][param] = pval
        Xt = X
        for name, transform in self.steps[:-1]:
            if hasattr(transform, "fit_transform"):
                Xt = transform.fit_transform(Xt, y, **fit_params_steps[name])
            else:
                Xt = transform.fit(Xt, y, **fit_params_steps[name])\
                .transform(Xt)
        return Xt, fit_params_steps[self.steps[-1][0]]

    def fit(self, X, y=None, **params):
        """Fit all the transforms one after the other and transform the
        data, then fit the transformed data using the final estimator.
        """
        Xt, fit_params = self._pre_transform(X, y, **params)
        self.steps[-1][-1].fit(Xt, y=y, **fit_params)
        return self

    def score(self, X, y=None):
        """Applies transforms to the data, and the score method of the
        final estimator. Valid only if the final estimator implements
        score."""
        Xt = X
        for name, transform in self.steps[:-1]:
            Xt = transform.transform(Xt)
        return self.steps[-1][-1].score(Xt)

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
        self.scaler.fit(X[y.squeeze()<0,...])
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
        return np.std(X, axis=1), y, None
class freq_momentum(base):
    def __init__(self, moment, **kwargs):
        from scipy.stats import skew,kurtosis
        import numpy as np
        if not isSequenceType(moment):
            moment=tuple(int(i) for i in reversed(bin(moment)[2:]))
        else:
            moment = tuple(moment)
        base.__init__(self, moment=moment, **kwargs)
        self.methods = (np.mean,np.std, skew, kurtosis)
    def _process(self, X, y, freqs):
        import numpy as np
        meth = filter(None,((self.methods[i] if self.moment[i] and i < len(self.moment) else None) for i in range(len(self.methods))))
        return np.hstack(tuple(m(X,axis=1)[...,np.newaxis] for m in meth)), y, None
class pca(base):
    def __init__(self, ndim, **kwargs):
        base.__init__(self, ndim=ndim, **kwargs)
        self.pca = None
    def fit(self, X, y, freqs):
        from sklearn.decomposition import PCA
        from scipy.linalg import LinAlgError
        self.pca = PCA(self.ndim)
        try:self.pca.fit(X[y.squeeze()<0,...])
        except LinAlgError: raise FitError()
        return self.pca.transform(X),y,freqs
    def score(self,X,y, freqs):
        return self.pca.transform(X),y,freqs
class mahal(base):
    def __init__(self, lbl, **kwargs):
        from sklearn.mixture import DPGMM as GMM
        from sklearn.covariance import EmpiricalCovariance, MinCovDet
        base.__init__(self, lbl=lbl, **kwargs)
        #self.model = EmpiricalCovariance()
        #self.model = GMM(1, covariance_type='diag', n_iter=100, params='wmc', init_params='wmc')
    def _labeling(self, X, y, freqs):
        import numpy as np
        y = np.copy(y).squeeze()
        model = np.abs([i for i in np.unique(y) if i < 0 and i is not None])
        i = np.abs(y.squeeze())==model
        j = ~i & (y.squeeze()!=0)
        y[...,i] = 1
        y[...,j] = -1
        return X, y, freqs
    def fit(self, X, y, freqs):
        from sklearn.covariance import EmpiricalCovariance, MinCovDet
        X, y, freqs = self._labeling(X, y, freqs)
        self.model = EmpiricalCovariance()
        X = X[y.squeeze() == 1,...]
        self.cov = self.model.fit(X)
        #print 'model size : %s'  % str(self.model.means_.shape)
        return X,y,freqs
    def score(self,X,y, freqs):
        from sklearn.metrics import roc_curve,auc
        X, y, freqs = self._labeling(X, y, freqs)
        #score_raw = self.model.score(X[y.squeeze()!=0,...])
        #score_raw = self.model.mahalanobis(X[y!=0,...]-X[y!=0,...].mean())
        score_raw = self.model.mahalanobis(X[y.squeeze()!=0,...] - self.cov.location_) ** 0.33
        fpr, tpr, thresholds = roc_curve(y[y.squeeze()!=0,...].squeeze(), score_raw)
        return (auc(fpr, tpr), (fpr, tpr,thresholds)),y,freqs
class gmm(base):
    def __init__(self, n_dim, **kwargs):
        from sklearn.mixture import DPGMM as GMM
        base.__init__(self, n_dim=n_dim, **kwargs)
        #self.model = GMM(4, covariance_type='full', n_iter=100, params='wmc', init_params='wmc')
    def _labeling(self, X, y, freqs):
        import numpy as np
        y = np.copy(y).squeeze()
        model = np.abs([i for i in np.unique(y) if i < 0 and i is not None])
        i = (y.squeeze()==model) | (y.squeeze()==-model)
        j = ~i & (y.squeeze()!=0)
        y[...,i] = 1
        y[...,j] = -1
        return X, y, freqs
    def fit(self, X, y, freqs):
        from sklearn.mixture import DPGMM as GMM
        X, y, freqs = self._labeling(X, y, freqs)
        self.model = GMM(self.n_dim, covariance_type='full', n_iter=100, params='wmc', init_params='wmc')
        self.model.fit(X[y.squeeze() == 1,...])
        #print 'model size : %s'  % str(self.model.means_.shape)
        return X,y,freqs
    def score(self,X,y, freqs):
        from sklearn.metrics import roc_curve,auc
        X, y, freqs = self._labeling(X, y, freqs)
        score_raw = self.model.score(X[y.squeeze()!=0,...])
        fpr, tpr, thresholds = roc_curve(y[y.squeeze()!=0,...].squeeze(), score_raw)
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