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
import os.path
import re
import HTMLParser
import lxml.html
import time
import datetime
import json
from hashlib import sha1
import tempfile
import binascii
#pylint: disable-msg=C0111


class BulkExtractor(commands.Command):
    """Retrieve specific artifacts from a memory image"""

    def __init__(self, config, *args, **kwargs):
        commands.Command.__init__(self, config, *args, **kwargs)
        config.add_option('PID', short_option = 'p', default = None,help = 'Operate on these Process IDs (comma-separated) rather than all browser processes',action = 'store', type = 'int')
    
    def calculate(self):
        """Calculate and carry out any processing that may take time upon the image"""
        # Load the address space
        addr_space = utils.load_as(self._config)

        print("Bulk Exractor Starting")
        print("Note: data is extracted using regex on a dirty dump of memory and may miss a minor percentage of edge cases.")
        # Call a subfunction so that it can be used by other plugins
        for proc in tasks.pslist(addr_space):
            if self._config.PID == proc.UniqueProcessId:
                yield proc

    def render_text(self, outfd, data):
        proc = next(data)
        # get the memory dump of a process
        proc_data = self.get_process_data(proc)

        # create subdirectory string
        time_st = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        subdirectory = "bulk_extractor" + time_st

        # create subdirectory
        try:
            os.mkdir(subdirectory)
        except Exception:
            pass

        # write all urls to a file
        urls = self.extract_urls(proc_data)
        self.write(subdirectory, "urls.txt", urls)

        # write all emails to a file
        emails = self.extract_emails(proc_data)
        self.write(subdirectory, "emails.txt", emails)

        # write all json to a file
        # json = self.extract_json(proc_data)
        # self.write(subdirectory, "json.txt", json)

        # write all IPv4 addresses to a file
        # IPv4 = self.extract_json(proc_data)
        # self.write(subdirectory, "IPv4.txt", IPv4)


    def get_process_data(self, proc):
        pid = proc.UniqueProcessId             
        print('found browser pid: {0}, {1}'.format(pid,proc.ImageFileName))
        print('Getting process memory dump')
        # get process's memory
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
            
            f.seek(0)
            browserData=f.read()
            f.close()
        return browserData


    def write(self, subdirectory, filename, data_list):
        filename = os.path.join(subdirectory, filename)
        f = open(filename, 'w')
        f.write( "\n".join(data_list) )
        f.close

    def extract_urls(self, proc_data_string):
        print('Extracting URLs')
        regex = 'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        return re.findall(regex, proc_data_string)

    def extract_emails(self, proc_data_string):
        print('Extracting emails')
        regex_1 = '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        regex_2 = '[\w\-][\w\-\.]+@[\w\-][\w\-\.]+[a-zA-Z]{1,4}'
        regex_3 = "[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
        return  re.findall(regex_2, proc_data_string)
    
    def extract_json(self, proc_data_string):
        print("Extracting Json")

    def extract_ip_addys(self, proc_data_string):
        print("Extracting IPv4 addresses")


