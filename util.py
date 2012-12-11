
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
        a = fig.add_subplot(111)
        result = plt_fnc(a)
        if name: a.set_title(name)
    else:
        l = len(plt_fnc)
        result = []
        subimgs = np.ceil(np.sqrt(l))
        for i in range(l):
            a = fig.add_subplot(subimgs,subimgs,1+i)
            result += plt_fnc[i](a),
            if name and len(name) > i: a.set_title(name[i])
        result = tuple(result)
        #if callable(xfmt_fnc): a.axes.xaxis.set_major_formatter(ticker.FuncFormatter(xfmt_fnc))
    #if callable(yfmt_fnc): a.axes.yaxis.set_major_formatter(ticker.FuncFormatter(yfmt_fnc))
    if show: fig.show()
    return fig,result

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
        def __call__(self, *args, **kwargs):
            from datetime import datetime
            print '## function <%s>: started' % self.fnc.__name__
            start = datetime.now()
            result = self.fnc.__call__(*args,**kwargs)
            print '## function <%s>: elapsed time: %f' % (self.fnc.__name__ ,(datetime.now() - start).total_seconds())
            return result
    return TimedRun(fnc)

def reverseDns(ip):
    """ execute dig to reverse lookup of given address
    """
    try:
        import subprocess
        dig = subprocess.Popen(['/usr/bin/dig', '+noall', '+answer', '-x', ip], stderr=subprocess.STDOUT,stdout = subprocess.PIPE )
        out, err = dig.communicate()
        if "PTR" in out:
            return out[out.index("PTR"):].split()[1]
    except:
        return ''

