#!/usr/bin/env python3
import os, sys, subprocess, zipfile, json, re, xml.dom.pulldom, xml.dom.minidom, urllib.request, ssl, platform

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning) # SSLv3

class SimpleDownloader: # {{{ Simple super unsecure http(s) downloader
    def __init__(self):
        context = ssl.create_default_context()
        context.ssl_version = ssl.PROTOCOL_SSLv23
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.options &= ~ssl.OP_NO_SSLv3
        context.options |= 0x4 #OP_LEGACY_SERVER_CONNECT https://bugs.python.org/issue44888
        context.minimum_version = ssl.TLSVersion.SSLv3
        context.set_ciphers('ALL:COMPLEMENTOFALL@SECLEVEL=0')
        self.context = context

    def __call__(self, url):
        print('Downloading', url,)
        response = urllib.request.urlopen(url, context=self.context)
        assert response.code == 200
        resp = response.read()
        print('done')
        return resp
# }}}

class JNLP: # {{{
    def __init__(self, filename):
        doc = xml.dom.pulldom.parse(filename)
        for event, node in doc:
            if event == xml.dom.pulldom.START_ELEMENT:
                doc.expandNode(node)
                self.xml = node
                return
        assert False

    def parse(self, debug = False):
        self.resources = []
        self.native = []

        root = self.xml
        if debug:
            print(root.toxml)
        assert root.tagName == 'jnlp'
        assert root.getAttribute('spec') == '1.0+'
        self.codebase = root.getAttribute('codebase')
        assert self.codebase
        pack_extension = ''
        use_version = False
        self.j2se_versions = set()

        for child in root.childNodes:
            if root.nodeType != child.nodeType:
                continue
            if child.tagName in ('information', 'security', 'update'):
                continue
            if child.tagName == 'application-desc':
                self.mainclass = child.getAttribute('main-class')
                self.args = []
                for arg in child.childNodes:
                    if arg.nodeType != child.nodeType:
                        continue
                    assert len(arg.childNodes) == 1
                    self.args.append(arg.childNodes[0].wholeText)
                continue
            if child.tagName == 'resources':
                os_filter = child.getAttribute('os')
                arch_filter = child.getAttribute('arch')
                for jar in child.childNodes:
                    if jar.nodeType != child.nodeType:
                        continue
                    if jar.tagName == 'property':
                        assert jar.getAttribute('value') == 'true'
                        name = jar.getAttribute('name')
                        if name == 'jnlp.packEnabled':
                            pack_extension = '.pack.gz'
                        elif name == 'jnlp.versionEnabled':
                            use_version = True
                        else:
                            assert False
                    elif jar.tagName == 'j2se':
                        jv = jar.getAttribute('version')
                        if jv:
                            self.j2se_versions.add(jv)
                    elif jar.tagName in ('jar', 'nativelib'):

                        name = jar.getAttribute('href')
                        assert name
                        version = jar.getAttribute('version')
                        if use_version and version:
                            assert(name[-4:] == '.jar')
                            path = '{}__V{}.jar'.format(name[:-4], version)
                        else:
                            path = name
                        if jar.tagName == 'jar':
                            assert os_filter == arch_filter == ''
                            self.jar = os.path.basename(path)
                        else:
                            self.native.append(os.path.basename(path))
                        path += pack_extension
                        self.resources.append((path, os_filter, arch_filter))
                continue
            print("JNLP Error: unknown attribute:")
            print(child.toxml())
            sys.exit(1)
# }}}

class Java: # {{{
    def __init__(self, java, propsjar, unpack, blacklist):
        self.java    = java
        self.unpack  = unpack
        self.props   = json.loads(subprocess.check_output([self.java, '-jar', propsjar]))
        self.os      = self.props['os.name']
        self.arch    = self.props['os.arch']
        self.version = self.props['java.version']
        self.blacklist = re.compile(blacklist)

    def set_jnlp(self, jnlp):
        self.jnlp = jnlp

    def download(self, temp_dir, downloader = None):
        self.temp_dir = temp_dir
        os.makedirs(temp_dir, exist_ok = True)

        if downloader is None:
            downloader = SimpleDownloader()
        for res, osname, archname in self.jnlp.resources:
            if osname and osname != self.os:
                continue
            if archname and archname != self.arch:
                continue
            if self.blacklist.search(res):
                print("Skipping blacklisted resource {}".format(res))
                continue
            if re.match('^https?://', res):
                res_uri = res
            elif re.match('^//', res):
                res_uri = 'http:' + res #FIXME
            elif re.match('^/', res):
                assert re.match('^https?://',self.jnlp.codebase)
                res_uri = '/'.join(self.jnlp.codebase.split('/')[:3]) + res
            else:
                res_uri = self.jnlp.codebase.rstrip('/') + '/' + res
            resp = downloader(res_uri)
            base = os.path.basename(res)
            with open(os.path.join(temp_dir, base), 'wb') as f:
                f.write(resp)
            res2 = re.sub('\.pack(\.gz)?$', '', base)
            if res2 != base:
                self.unpack(os.path.join(temp_dir, base), os.path.join(temp_dir, res2))
            if res2 in self.jnlp.native:
                with zipfile.ZipFile(os.path.join(temp_dir, res2), 'r') as z:
                    z.extractall(path=temp_dir, members=[ x for x in z.namelist() if '/' not in x and x[0] != '.'])

    def run(self):
        cmdline = [
            self.java,
            '-Djava.library.path=' + self.temp_dir,
            '-Djava.security.properties=' + os.path.join(os.path.dirname(__file__),'java.security')
        ]
        jar = os.path.join(self.temp_dir, self.jnlp.jar)
        if self.jnlp.mainclass:
            cmdline.extend([ '-cp', jar, self.jnlp.mainclass ])
        else:
            cmdline.extend([ '-jar', jar ])
        cmdline.extend(self.jnlp.args)
        print('Executing:', cmdline)
        subprocess.call(cmdline)

    def unlink(self, res):
        try:
            os.unlink(os.path.join(self.temp_dir, res))
        except OSError:
            pass

    def cleanup(self):
        for nat in self.jnlp.native:
            try:
                with zipfile.ZipFile(os.path.join(self.temp_dir, nat), 'r') as z:
                    for x in z.namelist():
                        if '/' not in x and x[0] != '.':
                            self.unlink(x)
            except OSError:
                pass

        for res, _, _ in self.jnlp.resources:
            base = os.path.join(self.temp_dir, os.path.basename(res))
            self.unlink(base)
            res2 = re.sub('\.pack(\.gz)?$', '', base)
            if res2 != base:
                self.unlink(res2)
        try:
            os.rmdir(self.temp_dir)
        except OSError:
            pass
# }}}

class Main:
    args = dict(
        jnlp      = None,
        java      = 'java',
        propsjar  = os.path.join(os.path.dirname(__file__), 'PrintProps.jar'),
        unpack    = None,
        blacklist = r'(?:^|/)avctKVMIOLinux(?:64)?[_.][^/]*$',
        debug     = False,
        temp      = os.path.join(os.path.dirname(__file__), 'tmp'),
    )

    @classmethod
    def unpack200_candidates(cls):
        yield 'unpack200'
        basepath = os.path.dirname(__file__)
        for candidate in os.scandir(basepath):
            if candidate.name.startswith('unpack200.'):
                yield candidate.path

    def parse_args(self):
        seen = set()
        args = dict(self.args)
        for arg in sys.argv[1:]:
            if '=' in arg:
                k, v = arg.split('=',1)
            else:
                k = 'jnlp'
                v = arg
            if k not in args:
                print("Error: Unknown argument {}".format(k), file=sys.stderr)
                sys.exit(1)
            if k in seen:
                print("Error: Multiple values for {}".format(k), file=sys.stderr)
                sys.exit(1)
            seen.add(k)
            args[k] = v
        if args['jnlp'] is None:
            print("""
        Usage {} [option=value option=value ...] file
        Options:
            java      path to java binary
            unpack    path to unpack200 binary
            propsjar  path to PrintProps.jar
            blacklist regexp of blacklisted jars
            temp      temporary directory
        """.format(sys.argv[0]))
            sys.exit(0)
        return args

    def unpack200(self, source, destination):
        if self.unpack_binary is None:
            probe_file = os.path.join(os.path.dirname(__file__),'empty.jar.pack.gz')
            if self.debug:
                print('Detecting unpack200 binary...')
            for candidate in self.unpack200_candidates():
                try:
                    os.unlink(destination)
                except FileNotFoundError:
                    pass
                if self.debug:
                    print('  probing', candidate)
                try:
                    subprocess.check_output([candidate, probe_file, destination])
                    self.unpack_binary = candidate
                except Exception:
                    continue
        if self.unpack_binary is None:
            raise FileNotFoundError('unpack200')
        try:
            os.unlink(destination)
        except FileNotFoundError:
            pass
        subprocess.check_call([self.unpack_binary, source, destination])

    def run(self, **args):
        self.debug = args.pop('debug')
        jnlp_arg = args.pop('jnlp')
        if jnlp_arg == '-':
            jnlp = JNLP(sys.stdin)
        else:
            jnlp = JNLP(jnlp_arg)
        jnlp.parse(self.debug)

        temp_dir = args.pop('temp')
        temp_dir = os.path.join(temp_dir, str(os.getpid()))

        self.unpack_binary = args.pop('unpack', None)
        args['unpack'] = self.unpack200

        java = Java(**args)
        java.set_jnlp(jnlp)
        try:
            java.download(temp_dir)
            java.run()
        finally:
            if not self.debug:
                java.cleanup()

    def __call__(self):
        args = self.parse_args()
        self.run(**args)

if __name__ == '__main__':
    try:
        Main()()
    except FileNotFoundError as f:
        if f.args == ('unpack200',):
            print("Please provide suitable unpack200 binary")
            sys.exit(1)
        else:
            raise
