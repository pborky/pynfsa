"""Contains flowizer object

"""

from util import *

tmpl_colision = colorize(boldred,None,boldwhite) * '\r****** #collision# in %s (hash: %d)\n'
tmpl_progress = colorize(boldyellow,boldred,boldblue) * '\rprogress: progress: %0.1f %% (dropped: %d of %d)'
tmpl_progress2 = colorize(boldyellow,boldred,boldblue) * '\rprogress: progress: #100# %% (dropped: %d of %d)\n'

class Flowizer(object):
    """Creates an callable that is used to generate flow data.

    Parameters
    ----------
    fialds : tuple
        tuple of field names (a columns of dataset
    fflow : tuple
        tuple determinid the flow schema (forward packets)
    bflow : tuple
        tuple determinid the flow schema (backward packets)
    usesyns : boolean
        use syns to determine flow direction
    opt : argparse.Namespace
        Arguements passed in command line.

    """
    def __init__(self, fields = ('time', 'paylen', 'flow'), fflow=('src','sport','dst','dport'), bflow=('dst','dport','src','sport'), usesyns = True, opt=None):
        self.fields = fields
        self.fflow = fflow
        self.bflow = bflow
        self.reverse_dns = opt.reverse_dns if opt else True
        self.protocol = opt.protocol if opt else True
        self.usesyns = opt.usesyns if opt else usesyns
    def __call__(self, data, flowids=None):
        """flowize and data

        Parameters
        ----------
        data : dataset.Table
            a table

        flowids : dataset.Table
            thread the flowids troughout the subsequent calls

        """
        from numpy import array,abs,vstack,squeeze
        from dataset import Table
        from sys import stdout

        flow2str2 =  lambda x,f: flow2str(x,f,dns=self.reverse_dns,services=self.reverse_dns)

        pay = data.select((data.proto==self.protocol),order='time',retdset=True)
        flow = set(squeeze((flowids['flow']))) if flowids else set()
        hashes = {} #if flowids is None else dict((scalar(f['flow']),tuple(f[self.fflow])) for f in flowids)
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

            if h in flow:
                pass
            elif hr in flow:
                negative = True
            elif h in hashes:
                if hashes[h] != t:
                    stdout.write(tmpl_colision % (flow2str2(t,self.fflow),h))
                    stdout.flush()
                    dropped += 1
                    continue
            elif hr in hashes:
                if hashes[hr] != tr:
                    stdout.write(tmpl_colision % (flow2str2(tr,self.bflow),hr))
                    stdout.flush()
                    dropped += 1
                    continue
                negative = True
            else:
                #print scalar(x['flags'])&18
                if self.usesyns:
                    if 'packets' in pay:  # we deal with netflow data and thus we demand SYN and don`t care about ACK
                        syn = scalar(x['flags'])&2 == 2
                    else: # we deal with pcap data, so SYN packet is distinguishable
                        # we don`t care about SYN+ACK
                        syn = scalar(x['flags'])&18 == 2
                    if not syn:
                        stdout.write( '\r****** no syn packet in %s (hash: %d) (flags: %d)\n' % (flow2str2(t,self.fflow),h,scalar(x['flags']) ))
                        stdout.write( tmpl_progress % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                        stdout.flush()
                        dropped += 1
                        droppedips.add((scalar(x['dst']),scalar(x['dport'])))
                        continue
                stdout.write( '\r###### new flow %s (hash: %d)\n' % (flow2str2(t,self.fflow),h))
                stdout.write( tmpl_progress % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                stdout.flush()
                hashes[h] = t
            x['flow'] = h
            if negative:
                if 'paylen' in x:
                    x['paylen'] = negate # broadcasting lambda
                elif 'size' in x:
                    x['size'] = negate # broadcasting lambda
            l += 1
            if l%10 == 0 :
                stdout.write( tmpl_progress % (100.*(l+dropped)/len(pay), dropped, (l+dropped))  )
                stdout.flush()
        stdout.write( tmpl_progress2 % (dropped,(l+dropped)))
        stdout.write( '\n%s\n'% [(int2ip(d),pd) for d,pd in droppedips])
        stdout.flush()
        if 'paylen' in pay:
            pay = pay.select(pay.paylen!=0,order='time',retdset=True, fields=self.fields)
        else:
            pay = pay.select(None,order='time',retdset=True, fields=self.fields)

        if not flowids:
            return Table(data=array(tuple((j,)+k for j,k in hashes.items())),fields=('flow',)+self.fflow),pay
        else:
            if not len(hashes):
                return  flowids, pay
            else:
                d = array(tuple((j,)+k for j,k in hashes.items()))
                return Table(data=vstack((flowids.data,d)),fields=('flow',)+self.fflow),pay

