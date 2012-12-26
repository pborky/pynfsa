
from util import *

import numpy as np
import scipy.stats as st
from functional import *

def fapply(fnc, *args, **kwargs):
    kwstr = ( '%s=%s'%i for i in  kwargs.iteritems())
    fkey = lambda fnc,arg: '%s' % fnc.__name__
    if len(args):
        fargs = lambda arg: arg if is_iterable(arg) and not isinstance(arg,str) else (arg,)
        fstring = lambda fnc,arg: '%s(%s)' %(fnc.__name__, ','.join([str(s) for s in fargs(arg)]+list(kwstr)))
        return [ (fkey(fnc,a), fstring(fnc,a), fnc(*fargs(a))) for a in args ]
    else:
        return  (fkey(fnc,None), '%s(%s)'%(fnc.__name__, ','.join(kwstr)) ,fnc()),

def fiterate( *args):
    from itertools import product
    from sklearn.pipeline import Pipeline
    return [ (','.join(name for key,name,fnc in cmds), Pipeline([(key,fnc) for key,name,fnc in cmds])) for cmds in product(*args) ]

class Modeler(object):
    def __init__(self,opt, computations):
        self.opt = opt
        from sklearn.mixture import DPGMM as GMM
        from sklearn.decomposition import PCA
        from sklearn.preprocessing import Scaler

        self.steps = {
            'Scaler': fapply( Scaler ),
            'Bands': fapply( FreqBandsTransformer, 3, 10, 25, (5,True), (10,True) ),
            'Threshold': fapply( FreqThresholdTransformer, 0 ),
            'MomentumMVKS': fapply( MomentumTtransformer, 'mvks'),
            'GMM' : fapply( GMM, 1, 5, covariance_type='full', verbose=False, n_iter=40 ),
            'Mahal': fapply( MahalanobisEstimator, False ),
            'PCA': fapply( PCA, 3, 10, 25  )
        }
        methods = self._methods(computations)

    def _methods(self,computations):
        return dict( reduce(add, ( fiterate(*[ self.steps.get(m) for m in c ])  for c in computations ) ) )

    def __call__(self, h5grp = None):

        samples = h5grp





from sklearn.base import BaseEstimator,TransformerMixin

class FitError(Exception):
    pass
class NotImplementedYet(Exception):
    pass


class LinearTransformer(BaseEstimator, TransformerMixin):
    def __init__(self, A):
        """ Projection to nex space determined by projection matrix.

            Parameters
            ----------
            A : array-like, shape [n_orig_features,n_new_features]
                the transformation is denoted as dot prodct: Y = XA.
                if A is an callable, the matrix determined during fit
        """
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
                X : used to determine matrix A invocation
                y : dummy, not used to fit the model.
                params : used to determine matrix A invokation

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

            Returns
            -------
            array-like X transformed
        """
        from sklearn.utils.validation import warn_if_not_float

        X = np.asarray(X)
        warn_if_not_float(X, estimator=self)
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
        return self.get_A(X,freqs)
    def get_A(self, X, freqs):
        """Returns transforamtion matrix.
            To be implemented in subclass
        """
        raise NotImplementedYet()

class FreqThresholdTransformer(FreqBaseTransformer):
    def __init__(self,f_thresh, f_thresh_hi=None):
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
        super(FreqThresholdTransformer, self).__init__()
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

class FreqBandsTransformer(FreqBaseTransformer):
    def __init__(self,n_bands, log_scale = False):
        """Creates projection based on frequency band filtering.
            The frequency spectrum is divided into equal or logatitmic intervals
            in which are spectral components summed.

            Parameters
            ----------
            n_bands : number of bands
            log_scale : boolean, if true logarithic scale instead of linear is used,
                        default: False

        """
        super(FreqBandsTransformer, self).__init__()
        self.n_bands = n_bands
        self.log_scale = log_scale
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
        A = ((freqs > bounds_low) & (freqs <= bounds_hi))
        return A

class MomentumTtransformer(BaseEstimator, TransformerMixin):
    _moments_map = {'m':np.mean, 'v':np.var , 'k': st.kurtosis, 's': st.skew }
    def __init__(self, moments = 'mvks'):
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
            Returns
            -------
            self : object
                Returns self.
        """
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
            array-like ith shape [n_samples, n_moments] whith
                moments of the original features. Ordering of
                the moments is according to argument `moments`
                given in initialization of the object
        """
        from sklearn.utils.validation import warn_if_not_float

        X = np.asarray(X)
        warn_if_not_float(X, estimator=self)
        return np.hstack(tuple(m(X,axis=1) for m in self.moment_fnc))

class MahalanobisEstimator (BaseEstimator):
    def __init__(self, robust=False):
        """Mahalanobis distance estimator. Uses Covariance estimate
            to compute mahalanobis distance of the observations
            from the model.

            Parameters
            ----------
            robust : boolean to determine wheter to use robust estimator
                based on Minimum Covariance Determinant computation
        """
        if not robust:
            from sklearn.covariance import EmpiricalCovariance as CovarianceEstimator #
        else:
            from sklearn.covariance import MinCovDet as CovarianceEstimator #
        self.model = CovarianceEstimator()
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
        self.model.fit(X)
        return self

    def score(self, X, assume_centered=False):
        """Computes the mahalanobis distances of given observations.

            The provided observations are assumed to be centered. One may want to
            center them using a location estimate first.

            Parameters
            ----------
            X: array-like, shape = [n_samples, n_features]
              The observations, the Mahalanobis distances of the which we compute.

            Returns
            -------
            mahalanobis_distance: array, shape = [n_observations,]
                Mahalanobis distances of the observations.
        """
        return self.model.mahalanobis(X, assume_centered)

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
        from collections import Iterable
        from scipy.stats import skew,kurtosis
        import numpy as np
        if not isinstance(moment, Iterable):
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