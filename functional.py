from operator import *
from math import *
from functools import partial
from itertools import imap,ifilter

def combinator(*fncs):
    return lambda *args:getitem(
            reduce(lambda acc,fnc:(fnc(*acc),), 
                   reversed(fncs), 
                   args), 0)

def flip(f):
    return lambda *a: f(*reversed(a))

# example of usage (overkill little-bit?:)
def minkowski(n, p1, p2):
    rpow = flip(pow)
    nth_pow = partial(rpow,n)
    nth_root = partial(rpow,1./n)
    return nth_root(reduce(add, imap(combinator(nth_pow,sub),p1,p2)))

euclid = partial(minkowski,2)
