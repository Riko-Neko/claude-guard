"""Append-only editing of LuLu's pinned keyed-archive format.

Existing object records are preserved verbatim. No Cocoa unarchive/resave round trip,
no private XPC, and no extension control. This module only transforms byte strings.
"""
import plistlib
import uuid

class PolicyError(ValueError): pass

class Archive:
    def __init__(self, data):
        self.data = plistlib.loads(data)
        if self.data.get('$archiver') != 'NSKeyedArchiver': raise PolicyError('Unknown archive format')
        self.objects = self.data.get('$objects')
        if not isinstance(self.objects,list) or len(self.objects)>200000: raise PolicyError('Invalid object table')
        if not self.objects or self.objects[0] != '$null': raise PolicyError('Invalid null sentinel')
        self.root = self.get(self.data.get('$top',{}).get('root'))
        self.mapping(self.root)

    def get(self, ref):
        if not isinstance(ref,plistlib.UID) or not 0<=ref.data<len(self.objects): raise PolicyError('Invalid object reference')
        return self.objects[ref.data]

    def add(self, obj):
        self.objects.append(obj);return plistlib.UID(len(self.objects)-1)

    def cls(self, name):
        for i,obj in enumerate(self.objects):
            if isinstance(obj,dict) and obj.get('$classname')==name:return plistlib.UID(i)
        supers={'NSMutableDictionary':['NSMutableDictionary','NSDictionary','NSObject'],
                'NSMutableArray':['NSMutableArray','NSArray','NSObject'],'Rule':['Rule','NSObject']}
        return self.add({'$classname':name,'$classes':supers[name]})

    def mapping(self, obj):
        if not isinstance(obj,dict) or set(['NS.keys','NS.objects'])-obj.keys():raise PolicyError('Invalid dictionary')
        if len(obj['NS.keys'])!=len(obj['NS.objects']):raise PolicyError('Invalid dictionary pairs')
        pairs=[(self.get(k),v) for k,v in zip(obj['NS.keys'],obj['NS.objects'])]
        if any(not isinstance(k,str) for k,_ in pairs) or len(set(k for k,_ in pairs))!=len(pairs):raise PolicyError('Invalid keys')
        return dict(pairs)

    def new_dict(self, pairs):
        return self.add({'NS.keys':[self.add(k) for k in pairs], 'NS.objects':list(pairs.values()),'$class':self.cls('NSMutableDictionary')})

    def rule_fields(self, ref):
        obj=self.get(ref)
        if not isinstance(obj,dict) or self.get(obj.get('$class')).get('$classname')!='Rule':raise PolicyError('Unknown rule object')
        return {k:self.get(v) if isinstance(v,plistlib.UID) else v for k,v in obj.items() if k!='$class'}

    def entries(self):
        for key,ref in self.mapping(self.root).items():
            entry=self.mapping(self.get(ref));array=self.get(entry.get('rules'))
            if not isinstance(array,dict) or 'NS.objects' not in array:raise PolicyError('Invalid rule array')
            yield key,ref,[self.rule_fields(r) for r in array['NS.objects']]

    def append_policy(self, paths, port):
        if type(port) is not int or not 1024<=port<=65535:raise PolicyError('Invalid gateway port')
        paths=tuple(paths)
        if not paths or any(not p.startswith('/') or not p.endswith('/*') or '..' in p.split('/') for p in paths):raise PolicyError('Invalid protected paths')
        root_pairs=self.mapping(self.root)
        for key,ref,rules in list(self.entries()):
            # No replacement of unrelated policy. Conflicting ancestor/global allow
            # rules require explicit review rather than broad deletion.
            for rule in rules:
                path=rule.get('path','')
                broad=path=='*' or (path.endswith('/*') and any(p.startswith(path[:-1]) for p in paths))
                if broad and path not in paths and rule.get('action')==1 and not rule.get('isDisabled'):
                    raise PolicyError('An existing broad allow rule conflicts with the protected scope')
            if key in paths: raise PolicyError('Protected scope already exists; refuse unreviewed replacement')
        for path in paths:
            refs=[]
            for action,addr,p in [(0,'*','*'),(1,'127.0.0.1',str(port))]:
                values={'uuid':str(uuid.uuid4()).upper(),'key':path,'path':path,'name':'Claude Guard '+path.rsplit('/',2)[-2],
                        'endpointAddr':addr,'endpointPort':p,'endpointHost':None,
                        'isEndpointAddrRegex':0,'type':3,'scope':1,'action':action,
                        'isDisabled':False,'pid':None,'csInfo':None,'creation':None,'expiration':None}
                obj={k:plistlib.UID(0) if v is None else self.add(v) for k,v in values.items()}
                obj['$class']=self.cls('Rule');refs.append(self.add(obj))
            array=self.add({'NS.objects':refs,'$class':self.cls('NSMutableArray')})
            root_pairs[path]=self.new_dict({'rules':array})
        # Only the top-level dictionary gets new key/value arrays. All old entries
        # and object records, including unknown future fields, remain unchanged.
        self.root['NS.keys']=[self.add(k) for k in root_pairs]
        self.root['NS.objects']=list(root_pairs.values())
        return plistlib.dumps(self.data,fmt=plistlib.FMT_BINARY,sort_keys=False)


def make_policy(data, paths, port):
    return Archive(data).append_policy(paths,port)
