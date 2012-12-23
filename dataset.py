__author__ = 'peterb'

class H5File(object):
    def __init__(self, opt, h5 = None, grp = None ):
        from tables import openFile,File
        if isinstance(h5,File):
            self.h5 = h5
        else:
            self.h5 = openFile(opt.database,'a')
        self.group = self.h5.root if grp is None else grp
        self.opt = opt
    def __contains__(self, item):
        from tables import NoSuchNodeError
        try:
            self.h5.getNode(self.group,item)
            return True
        except NoSuchNodeError:
            return False
    def __delitem__(self, key):
        self.h5.getNode(self.group,key)._f_remove(True)
    def __getitem__(self, item):
        from tables import Group,NoSuchNodeError
        try:
            item = self.h5.getNode(self.group,item)
            if isinstance(item,Group):
                result = H5File(self.opt,h5=self.h5, grp=item)
                if 'data' in result and 'fields' in result:
                    return Dataset(h5=result)
                else:
                    return result
            else:
                return item
        except NoSuchNodeError:
            return H5File(self.opt, h5=self.h5, grp=self.h5.createGroup(self.group,item))
    def __setitem__(self, key, value):
        from collections import Iterable
        if key[0] == '/':
            raise ValueError("the ``/`` character is not allowed in object names: '%s'"%key)
        path = key.rsplit('/',1)
        if len(path)==2:
            path,name = path
            grp = self[path].group
        else:
            name, = path
            grp = self.group
        try:
            if not isinstance(value,Iterable):
                value=value,
            self.h5.createArray(grp,name,value)
        except TypeError:
            setattr(grp,name,value)
        #print self.keys()
    def keys(self):
        return  [ g._v_pathname.rsplit('/',1)[-1] for g in self.h5.listNodes(self.group) ]
    def close(self):
        self.h5.close()
    def handle_exit(self, try_fnc, *arg,**kwarg):
        if not callable(try_fnc):
            raise ValueError()
        try:
            try_fnc(self.opt, h5 = self)
        except KeyboardInterrupt:
            pass
        finally:
            self.close()
        exit()

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
            self.data = h5['data']
            self.fields = tuple(h5['fields'])
        elif data is not None and fields is not None:
            self.data = data if isinstance(data,ndarray) else array(data)
            self.fields = tuple(fields)
        else:
            raise Exception('no data')
        for f in self.fields:
            setattr(self,f,Variable(f))
    def __add__(self,other):
        """add two dataset objects. Must have same shape and fields."""
        from numpy import vstack
        if not isinstance(other,Dataset):
            raise TypeError('Must be Dataset')
        if self.fields != other.fields:
            raise TypeError('Must have same fields')
        return Dataset(data=vstack((self.data,other.data)),fields=self.fields)
    def __len__(self):
        """return the length of the dataset."""
        return self.data.shape[0]
    def __getitem__(self, key):
        if isinstance(key, tuple):
            predicate = key[0] if isinstance(key[0],Predicate) else None
            fields = key[1:] if isinstance(key[0],Predicate) else key
            return self.select(predicate,fields=fields,retdset=isinstance(key[0],Predicate))
        elif isinstance(key,Predicate):
            return self.select(key,retdset=True)
        else:
            return self.select(None,fields=(key,))
    def __delitem__(self, key):
        if isinstance(key, tuple):
            predicate = key[0] if isinstance(key[0],Predicate) else None
            fields = key[1:] if isinstance(key[0],Predicate) else key
            self.data = self.select(predicate,retdset=False)
            self.retain_fields(tuple(f for f in self.fields if f not in fields))
        elif isinstance(key,Predicate):
            self.data = self.select(key,retdset=False)
        else:
            self.retain_fields(tuple(f for f in self.fields if f not in key))
    def __setitem__(self,key, value):
        if isinstance(key, tuple):
            if len(key) > 2 :
                raise ValueError('expecting optional predicate to filter rows and strig to denote column')
            predicate = key[0] if isinstance(key[0],Predicate) else None
            field = key[1] if isinstance(key[0],Predicate) else key
            return self.set_fields(predicate, field, value)
        else:
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
        from numpy import argsort,where
        if callable(predicate):
            idx, = where(predicate (self.data, self._getfield))
            result =  self.data[idx,...]
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
        from numpy import where
        if callable(value):
            if predicate is None:
                idx =  self.fields.index(field)
                self.data[... ,idx] = value(self.data[... ,idx])
            else:
                pred =  where(predicate (self.data, self._getfield))
                idx =  self.fields.index(field)
                self.data[pred,idx] = value(self.data[pred,idx])
        else:
            if predicate is None:
                idx =  self.fields.index(field)
                self.data[... ,idx] = value
            else:
                pred =  where(predicate (self.data, self._getfield))
                idx =  self.fields.index(field)
                self.data[pred,idx] = value
        return self.data.shape[0] if predicate is None else pred.size
    def save(self,h5):
        h5['data'] =  self.data
        h5['fields'] =  self.fields

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
        from operator import or_
        d = fnc(arg,self.field) if callable(fnc) else fnc
        return reduce(or_, (i==d for i in self.value))

class Binary(Predicate):
    def __init__(self, reduction, *args):
        super(Binary, self).__init__()
        argsg = (a.preds if isinstance(a,self.__class__) else (a,) for a in args)
        self.preds = tuple(i for sub in argsg for i in sub)
        self.reduction = reduction if reduction else tuple
    def __call__(self, arg, fnc):
        return reduce(self.reduction, (p(arg,fnc) if callable(p) else p for p in self.preds))
class Conj(Binary):
    def __init__(self, *args):
        from operator import and_
        super(Conj, self).__init__(and_,*args)
class Dis(Binary):
    def __init__(self, *args):
        from operator import or_
        super(Dis, self).__init__(or_,*args)
class Xor(Binary):
    def __init__(self, *args):
        from operator import xor
        super(Xor, self).__init__(xor,*args)
class Equ(Binary):
    def __init__(self, *args):
        from operator import eq
        super(Equ, self).__init__(eq,*args)

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
