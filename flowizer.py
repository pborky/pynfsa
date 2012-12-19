

class Flowizer(object):
    """ Annotates records based on requirements.
    """
    def __init__(self, fields = ('time', 'paylen', 'flow'), fflow=('src','sport','dst','dport'), bflow=('dst','dport','src','sport'), usesyns = True, opt=None):
        self.fields = fields
        self.fflow = fflow
        self.bflow = bflow
        self.reverse_dns = opt.reverse_dns if opt else True
        self.protocol = opt.protocol if opt else True
        self.usesyns = opt.usesyns if opt else usesyns
    def __call__(self, data, flowids=None):
        from numpy import array,abs
        from dataset import Variable,Dataset
        from util import scalar,int2ip,flow2str
        from sys import stdout
        variables = dict((k,Variable(k))for k in ('src','sport','dst','dport'))

        paylen =  Variable('paylen')
        flags =  Variable('flags')
        proto =  Variable('proto')
        time =  Variable('time')

        flow2str2 =  lambda x,f: flow2str(x,f,dns=self.reverse_dns,services=self.reverse_dns)

        pay = data.select((proto==self.protocol),order='time',retdset=True)
        hashes = {} if flowids is None else dict((scalar(f['flow']),tuple(f[self.fflow])) for f in flowids)
        scalar = lambda x : x.item() if  hasattr(x,'item') else x
        negate = lambda x: -abs(x)
        l = 0
        dropped = 0
        droppedips = set()
        for x in pay:
            t = tuple(scalar(x[f]) for f in self.fflow)
            h = hash(t)
            tr = tuple(scalar(x[f]) for f in self.bflow)
            hr = hash(tr)
            negative = False
            if h in hashes:
                if hashes[h] != t:
                    stdout.write('\r****** collision in %s (hash: %d)\n' %(flow2str2(t,self.fflow),h))
                    stdout.flush()
                    dropped += 1
                    continue
            elif hr in hashes:
                if hashes[hr] != tr:
                    stdout.write( '\r****** collision in %s (hash: %d)\n' %(flow2str2(tr,self.bflow),hr))
                    stdout.flush()
                    dropped += 1
                    continue
                negative = True
            else:
                #print scalar(x['flags'])&18
                if self.usesyns:
                    if 'packets' in pay:  # we deal with netflow data and thus we demand SYN
                        syn = scalar(x['flags'])&2 == 2
                    else: # we deal with pcap data, so SYN packet is distinguishable
                        # we don`t care about SYN+ACK
                        syn = scalar(x['flags'])&18 == 2
                    if not syn:
                        stdout.write( '\r****** no syn packet in %s (hash: %d)\n' % (flow2str2(t,self.fflow),h))
                        stdout.write( '\rprogress: \033[33;1m%0.1f %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        ' % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                        stdout.flush()
                        dropped += 1
                        droppedips.add((scalar(x['dst']),scalar(x['dport'])))
                        continue
                stdout.write( '\r###### new flow %s (hash: %d)\n' % (flow2str2(t,self.fflow),h))
                stdout.write( '\rprogress: \033[33;1m%0.1f %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        ' % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                stdout.flush()
                hashes[h] = t
            x['flow'] = h
            if negative:
                for i in ('paylen','size'):
                    if i in x:
                        x[i] = negate # broadcasting lambda
            l += 1
            if l%1000 == 0 :
                stdout.write( '\rprogress: \033[33;1m%0.1f %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        ' % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                stdout.flush()
        stdout.write( '\rprogress: \033[33;1m100 %%\033[0m (dropped: \033[33m%d\033[0m of \033[33;1m%d\033[0m)        \n' % (dropped,(l+dropped)))
        stdout.write( '\n%s\n'% [(int2ip(d),pd) for d,pd in droppedips])
        stdout.flush()
        if 'paylen' in pay:
            pay = pay.select((paylen!=0),order=('time',),retdset=True, fields=self.fields)
        else:
            pay = pay.select(None,order=('time',),retdset=True, fields=self.fields)

        qd = Dataset(data=array(tuple((j,)+k for j,k in hashes.items())),fields=('flow',)+self.fflow)
        return  qd, pay

