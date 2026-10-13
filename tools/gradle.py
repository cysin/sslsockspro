#!/usr/bin/env python3
"""Run Gradle with the same HTTP proxy as the developer's existing environment."""
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parents[1]
environment = os.environ.copy()
if (root / '.tools/jdk/bin/javac').exists():
    environment['JAVA_HOME'] = str(root / '.tools/jdk')
options = []
for protocol in ('http', 'https'):
    value = urllib.request.getproxies().get(protocol)
    if value:
        proxy = urllib.parse.urlsplit(value)
        if proxy.scheme != 'http' or proxy.username:
            raise SystemExit('Gradle proxy setup requires an unauthenticated HTTP proxy or explicit JVM proxy settings.')
        options += ['-D' + protocol + '.proxyHost=' + proxy.hostname, '-D' + protocol + '.proxyPort=' + str(proxy.port or 80)]
options += ['-Dhttp.nonProxyHosts=localhost|127.*|[::1]']
raise SystemExit(subprocess.call([str(root / 'gradlew'), *options, *sys.argv[1:]], cwd=root, env=environment))
