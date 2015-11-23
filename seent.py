# Volatility facebook plugin
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#


import volatility.timefmt as timefmt
import volatility.obj as obj
import volatility.utils as utils
import volatility.commands as commands
import volatility.win32.tasks as tasks
import os
import re
import HTMLParser
import lxml.html
import time
import json
from hashlib import sha1
import tempfile
import binascii
#pylint: disable-msg=C0111

uescapes = re.compile(r'(?<!\\)\\u[0-9a-fA-F]{4}', re.UNICODE)
def uescape_decode(match): return match.group().decode('unicode_escape')

safestringre=re.compile('[\x00-\x1F\x80-\xFF]')
def safestring(badstring):
        """makes a good strings out of a potentially bad one by escaping chars out of printable range"""
        return safestringre.sub('',badstring)

class Seent(commands.Command):
    """Retrieve browser artifacts from a memory image"""

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,help = 'Operate on these Process IDs (comma-separated) rather than all browser processes',action = 'store', type = 'str')
    
    def calculate(self):
        """Calculate and carry out any processing that may take time upon the image"""
        # Load the address space
        addr_space = utils.load_as(self._config)

        # Call a subfunction so that it can be used by other plugins
        for proc in tasks.pslist(addr_space):
            if str(proc.ImageFileName).lower() in("iexplore.exe","firefox","firefox.exe","chrome","chrome.exe"):
                yield proc

    def render_text(self, outfd, data):
        """Renders the data as text to outfd"""
        startTime=time.time()
        outfd.write('searching for browser processes...\n')


        hParser=HTMLParser.HTMLParser()
        encoding="ascii"

        
        for proc in data:
            if proc.UniqueProcessId:
                pid = proc.UniqueProcessId
                if not self._config.PID ==None and str(pid) not in list(self._config.PID.split(',')):
                    #skip this browser pid
                    continue                    
                outfd.write('found browser pid: {0}, {1}\n'.format(pid,proc.ImageFileName))
                foundItemsHashes=list()
                procSpace = proc.get_process_address_space()
                pages = procSpace.get_available_pages()
                if pages:
                    f=tempfile.TemporaryFile() 
                    for p in pages:
                        procdata = procSpace.read(p[0], p[1])
                        if procdata == None:
                            if self._config.verbose:
                                outfd.write("Memory Not Accessible: Virtual Address: 0x{0:x} File Offset: 0x{1:x} Size: 0x{2:x}\n".format(p[0], proc.obj_offset, p[1]))
                        else:
                            dataDecoded= procdata.decode('ascii','ignore')
                            f.write(dataDecoded.replace('\x00',''))
                    
                    #now read back in the memory for this process looking for facebook artifacts
                    f.seek(0)
                    browserData=f.read()
                    outfd.write('examining {0} bytes\n'.format(len(browserData)))
                    f.close()

                print "Tasty Stuff Goes Here"   
                f = open('browserData.txt', 'w')
                f.write(browserData)
                f.close

                # x = re.compile('{.*}', re.I | re.S)
                # for xx in x.finditer(browserData):
                #    print xx
                              
                        
        endTime=time.time()
        outfd.write("{0} seconds\n".format(endTime-startTime))
