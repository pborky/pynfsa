
from __future__ import print_function
from util import *

class Labeler(object):
    def __init__(self,opt):
        self.opt = opt
        if not opt.annotations:
            raise Exception('no annotation file specified')
    fieldmap = {
        'dstIPs':'dst',
        'srcIPs':'src',
        'srcPorts':'sport',
        'dstPorts':'dport',
        'dst':'dst',
        'src':'src',
        'sport':'sport',
        'dport':'dport'
    }
    def prepare(self):
        import json
        try:
            f = open(self.opt.annotations,'r')
            self.filters = json.load(f)
        except IOError:
            self.filters = self._interact(opt)
        self._predicates()
        return self.filters
    def _predicates(self,fields = None):
        from dataset import Variable
        from functional import partial,combinator,eq,or_,and_

        if self.opt.flowid=='3':
            fields = ('dstIPs','dstPorts','srcIPs')
        elif self.opt.flowid=='4':
            fields = ('dstIPs','dstPorts','srcIPs','srcPorts')
        else:
            raise Exception('not implemented')

        i = 0
        for f in self.filters:
            f.update( (k,map(ip2int,v)) for k,v in f.iteritems() if k in ('dstIPs','srcIPs') )
            variable = combinator(Variable,self.fieldmap.get) # variable :: key -> Variable
            variableeq = combinator(partial(partial,eq),variable) # variableeq :: key -> (Variable ==)
            f['predicate'] = reduce(and_,( reduce(or_, map( variableeq(k) ,v )) for k,v in f.items() if k in fields and len(v) ))
            f['idx'] = i
            i+=1
    def _interact(self, opt, h5=None):
        """ Crappy feature allowing to create annotation file
        """
        from operator import add
        from sys import stdout
        from dataset import H5Node
        import json

        def feedback(i):
            types = {'-1':'FILTER_MALICIOUS','1':'FILTER_LEGITIMATE', '0': None}
            input = ()
            while len(input)!=2 or input[0].strip() not in types:
                input = raw_input('%s ? '%flow2str(i,dns=True,services=True)).split(',',1)
            return {'type':types.get(input[0].strip()),'annotation':input[1],'data':i}

        if not h5 :
            h5 = H5Node(opt)

        if opt.flowid == '3':
            flowid = 'flows3'
        elif opt.flowid == '4':
            flowid = 'flows4'
        else:
            raise NotImplementedError('flowid='+opt.flowid)

        d  = h5['%s/flowids'%flowid]
        data = reduce(add,  (h5['%s/%s'%(flowid,k)] for k in h5['flows3'].keys() if k.startswith('data')))
        flows = [i for i in reversed(sorted(((i,len(data[data.flow==scalar(i['flow'])])) for i in d),key=lambda x: x[-1]))]
        min_packets =  opt.min_packets if opt.min_packets else 100
        flows = [i for i,c in flows if c>min_packets]
        print('## %d records to annotate'%len(flows))
        print('''Please enter annotations for each destination
in form: `<number>,<text>`
where number is -1 for malicious, 1 for legitimate and 0 for unknown destiantions
and text is any text used as annotation.''')
        filt = [feedback(i) for i in sorted(flows,key=lambda x: x['dport'])]
        filt2 = [
            {
            'dstIPs':list(set( int2ip(scalar(j['data']['dst'])) for j in filt if j['annotation'] == a)),
            'dstPorts':list(set( scalar(j['data']['dport']) for j in filt if j['annotation'] == a)),
            'annotation':a,
            'type':t
        } for a,t in set((i['annotation'],i['type']) for i in filt)
        ]
        try:
            out = open(opt.annotations,'w') if  opt.annotations else stdout
        except :
            out =  stdout
        json.dump(filt2,out)
        return  filt2
    def __call__(self, h5grp):
        from numpy import array,vectorize,unique
        from dataset import Table
        if 'flowids' not in h5grp:
            raise ValueError('expectiong \'flowids\' dataset is present in h5 group')
        fl = h5grp['flowids']
        fl.add_field('annot',-1)
        flows = {}
        annot = dict((f['idx'],f) for f in self.filters)
        #print(annot)
        for f in self.filters:
            pred =  f['predicate']
            match = fl[pred]
            if not len(match):
                continue
            if (match['annot']!=-1).any():
                if not f['dstIPs'] or not f['dstPorts']:
                    print(colorize(None, boldred,red,boldyellow,red)*'## #warning#: #colliding filter# %s #is ignored#:'%f['annotation'],(match['annot']!=-1).sum())
                    match = match[match.annot==-1]
                else:
                    colliding = [annot[scalar(a)]['annotation'] for a in unique(match['annot']) if a in annot ]
                    print(colorize(None, boldred,red,boldyellow, boldyellow,red,)*'## #warning#: #filters# %s, %s #are not disjoint, you will probably loose some information#: '%(f['annotation'],', '.join(colliding)),(match['annot']!=-1).sum())
            fl[pred,'annot'] = f.get('idx')

            if len(match) == 1:
                flows[scalar(match['flow'].squeeze())] = f.get('idx')
            elif len(match) > 1:
                flows.update( (i,f.get('idx')) for i in match['flow'].squeeze() )
        if 'annot' in h5grp:
            print(colorize(None, boldyellow,yellow)*'## #warning#: #annotation dataset is going to be overwritten#')
            del h5grp['annot']
        fl[...,'flow','annot'].save(h5grp['annot/flowids'])
        annots = {}
        for f in self.filters:
            if 'idx' in f:
                annots[f['idx']] = (f.get('type'),'%s (%s)' %(f.get('annotation'),f.get('fileName')))
        a = array([ list((k,)+v) for k,v in annots.iteritems()  ], dtype=str)
        annot = Table(data=a, fields=('annot','type','caption'))
        annot.save(h5grp['annot/annotations'])


        flow2annot = vectorize(lambda x: flows[x] if x in flows else -1)
        lbl = flow2annot(h5grp['y'])
        h5grp['annot/y'] = lbl

        return flows,annots,lbl

