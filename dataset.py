__author__ = 'peterb'

class Dataset(object):
    """Encapsulation of the numpy array, in order to conviently select/update data.
    """
    def __init__(self, data=None, fields=None, h5=None):
        """constructor
            Input:
                data - numpy matrix or list of lists
                fields - list of column names
        """
        from numpy import array,ndarray
        if h5 is not None:
            self.data = h5['data'].value
            self.fields = tuple(h5['fields'].value)
        elif data is not None and fields is not None:
            self.data = data if isinstance(data,ndarray) else array(data)
            self.fields = tuple(fields)
        else:
            raise Exception('no data')
    def __add__(self,other):
        """add two dataset objects. Must have same shape and fields."""
        from numpy import vstack
        if isinstance(other,Dataset):
            raise TypeError('Must be Dataset')
        if self.fields != other.fields:
            raise TypeError('Must have same fields')
        return Dataset(data=vstack(self.data,other.data),fields=self.fields)
    def __len__(self):
        """return the length of the dataset."""
        return self.data.shape[0]
    def __getitem__(self, key):
        if isinstance(key, tuple):
            return self.select(None,fields=key)
        else:
            return self.select(None,fields=(key,))
    def __delitem__(self, key):
        self.retain_fields(tuple(f for f in self.fields if f!=key))
    def __setitem__(self,key, value):
        return self.set_fields(None, key, value)
    def __contains__(self,item):
        return item in self.fields
    def __iter__(self):
        def iterator():
            for i in range(len(self)):
                yield Dataset(data=self.data[i,...],fields=self.fields)
        return iterator()
    def _getfield(self,x,f):
        """return vector containing the field"""
        return x[...,self.fields.index(f)]
    def select(self, predicate, order=None, group= None, retdset=None, fields=None, **kwargs):
        """Select submatrix based on predicate and fields.
            Input:
                predicate - An subclass of Predicate. It generates boolean vector to be used as indexig vector.
                order - field to be used for ordering of the resultset
                group - not implemented
                retdset - if true reslt is encapsulated in new Dataset instance
                fields - a tuple specifying fields to keep
            Output:
                a submatrix of new Dataset object based on predicate
            Example:
                size = PredicateFactory('size')
                r = data.select((size >= 10) & (size < 15), fields = ('time', 'size'))
                # select submatrix containing time and size columns and rows where size is in interval [10,15)
        """
        from numpy import argsort
        if callable(predicate):
            result =  self.data[predicate (self.data, self._getfield),...]
        else:
            result =  self.data[:]
        fld = self.fields
        if order and order in fld:
            result=result[argsort(self._getfield(result,order)),...]
        if group:
            print '###### grouping is not implemented'
        if fields:
            result = result[...,tuple(fld.index(f) for f in fields)]
            fld = fields
        if retdset:
            return Dataset(data=result,fields=fld)
        else:
            return result
    def add_field(self,field, value):
        """Add new column called 'field' and set its value to 'value'. It can be vector or scalar (it will be broadcast)."""
        from numpy import hstack
        self.data = hstack((self.data,self.data[...,-1]))
        self.fields = field
        self.set_fields(None, field, value)
    def retain_fields(self, fields):
        """Keep column specified in 'fields', others are discarded."""
        if any(f not in self.fields for f in fields):
            raise ValueError('some fields not in this dataset')
        self.data = self.data[...,tuple(self.fields.index(f) for f in fields)]
        self.fields = fields
    def set_fields(self, predicate, field, value):
        """Set column specified by 'field', and rows matched by 'predicate' set its value to 'value'.
           It can be vector or scalar (it will be broadcast).
        """
        if callable(value):
            if predicate is None:
                idx =  self.fields.index(field)
                self.data[... ,idx] = value(self.data[... ,idx])
            else:
                pred =  predicate (self.data, self._getfield)
                idx =  self.fields.index(field)
                self.data[pred,idx] = value(self.data[pred,idx])
        else:
            if predicate is None:
                idx =  self.fields.index(field)
                self.data[... ,idx] = value
            else:
                pred =  predicate (self.data, self._getfield)
                idx =  self.fields.index(field)
                self.data[pred,idx] = value
        return self.data.shape[0] if predicate is None else pred.sum()
    def save(self,h5):
        h5.create_dataset('data', data = self.data,compression='gzip')
        h5.create_dataset('fields', data = self.fields,compression='gzip')
## convivence method for compsoting coditions.
class Predicate(object):
    def __call__(self,arg, fnc):
        raise Exception('not implementd')
    def __and__(self, other):
        return Conj(self,other)
    def __or__(self, other):
        return Dis(self,other)
    def __xor__(self, other):
        return Xor(self,other)
    def __eq__(self, other):
        return Equ(self,other)

class Term(Predicate):
    def __init__(self, field,value):
        self.value = value
        self.field = field
class Always(Term):
    def __call__(self, arg, fnc):
        a = fnc(arg,self.field)
        return a==a
class Never(Term):
    def __call__(self, arg, fnc):
        a = fnc(arg,self.field)
        return a!=a
class Lt(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) < self.value
class Gt(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) > self.value
class Le(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) <= self.value
class Ge(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) >= self.value
class Eq(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) == self.value
class Ne(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) != self.value
class And(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) & self.value
class Or(Term):
    def __call__(self,arg, fnc):
        return fnc(arg,self.field) | self.value
class In(Term):
    def __call__(self,arg, fnc):
        d = fnc(arg,self.field) if callable(fnc) else fnc
        return reduce(lambda x,y: x|y, (i==d for i in self.value))

class Binary(Predicate):
    def __init__(self, *args):
        super(Binary, self).__init__()
        argsg = (a.preds if isinstance(a,self.__class__) else (a,) for a in args)
        self.preds = tuple(i for sub in argsg for i in sub)
    def reduction(self, x, y):
        raise Exception('Not implemented')
    def __call__(self, arg, fnc):
        return reduce(self.reduction, (p(arg,fnc) if callable(p) else p for p in self.preds))
class Conj(Binary):
    def reduction(self,x,y): return x&y
class Dis(Binary):
    def reduction(self,x,y): return x|y
class Xor(Binary):
    def reduction(self,x,y): return x^y
class Equ(Binary):
    def reduction(self,x,y): return x==y

class Variable(object):
    """Used to build and predicate instance."""
    def __init__(self, field):
        self.field = field
    def __lt__(self,other):
        return Lt(self.field,other)
    def __gt__(self,other):
        return Gt(self.field,other)
    def __eq__(self,other):
        return Eq(self.field,other)
    def __ne__(self,other):
        return Ne(self.field,other)
    def __le__(self,other):
        return Le(self.field,other)
    def __ge__(self,other):
        return Ge(self.field,other)
    def __contains__(self,other):
        return In(self.field, other)
    def __and__(self, other):
        return And(self.field, other)
    def __or__(self, other):
        return Or(self.field, other)
    def always(self):
        return Always(self.field,None)
    def never(self):
        return Never(self.field,None)
    def nonzero(self):
        return Nz(self.field)
