
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
class freq_momentum(base):
    def __init__(self, moment, **kwargs):
        base.__init__(self, moment=moment, **kwargs)
    def _process(self, X, y, freqs):
        import numpy as np
        from scipy.stats import skew,kurtosis
        methods = (np.mean,np.std, skew, kurtosis)
        meth = methods[self.moment-1]
        return meth(X,axis=1)[...,np.newaxis], y, None
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
        self.model = MinCovDet()
        #self.model = GMM(1, covariance_type='diag', n_iter=100, params='wmc', init_params='wmc')
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
        self.cov = self.model.fit(X[y.squeeze() < 0,...])
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
    def __init__(self, lbl, **kwargs):
        from sklearn.mixture import DPGMM as GMM
        base.__init__(self, lbl=lbl, **kwargs)
        self.model = GMM(4, covariance_type='full', n_iter=100, params='wmc', init_params='wmc')
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
        self.model.fit(X[y.squeeze() < 0,...])
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