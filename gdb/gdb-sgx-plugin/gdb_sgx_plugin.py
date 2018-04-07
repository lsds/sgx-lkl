#!/usr/bin/env python
#
# Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

from __future__ import print_function
import gdb
import struct
import os.path
from ctypes import create_string_buffer
import load_symbol_cmd
import sgx_emmt
import ctypes

# Calculate the bit mode of current debuggee project
SIZE = gdb.parse_and_eval("sizeof(long)")

ET_SIM = 0x1
ET_DEBUG = 0x2
PAGE_SIZE = 0x1000
KB_SIZE = 1024
# The following definitions should strictly align with the structure of
# debug_enclave_info_t in uRTS.
# Here we only care about the first 7 items in the structure.
# pointer: next_enclave_info, start_addr, tcs_list, lpFileName,
#          g_peak_heap_used_addr
# int32_t: enclave_type, file_name_size
ENCLAVE_INFO_SIZE = 5 * 8 + 2 * 4
INFO_FMT = 'QQQIIQQ'
ENCLAVES_ADDR = {}

# The following definitions should strictly align with the struct of
# tcs_t
# Here we only care about the first 8 items in the structure
# uint64_t: state, flags, ossa, oentry, aep, ofs_base
# uint32_t: nssa, cssa
ENCLAVE_TCS_INFO_SIZE = 6*8 + 2*4
TCS_INFO_FMT = 'QQQIIQQQ'

inited = 0
ubase = 0
heap_size = 0
debug_file = ''

def get_inferior():
    """Get current inferior"""
    try:
        if len(gdb.inferiors()) == 0:
            print ("No gdb inferior could be found.")
            return -1
        else:
            inferior = gdb.inferiors()[0]
            return inferior
    except AttributeError:
        print ("This gdb's python support is too old, please update first.")
        exit()

def read_from_memory(addr, size):
    """Read data with specified size  from the specified meomory"""
    inferior = get_inferior()
    # actually we can check the addr more securely
    # ( check the address is inside the enclave)
    if inferior == -1 or addr == 0:
        print ("Error happens in read_from_memory: addr = {0:x}".format(int(addr)))
        return None
    try:
        string = inferior.read_memory(addr, size)
        return string
    except gdb.MemoryError:
        print ("Can't access memory at {0:x}.".format(int(addr)))
        return None

def write_to_memory(addr, buf):
    """Write a specified buffer to the specified memory"""
    inferior = get_inferior()
    if inferior == -1 or addr == 0:
        print ("Error happens in write_to_memory: addr = {0:x}".format(int(addr)))
        return -1
    try:
        inferior.write_memory(addr, buf)
        return 0
    except gdb.MemoryError:
        print ("Can't access memory at {0:x}.".format(int(addr)))
        return -1

def target_path_to_host_path(target_path):
    so_name = os.path.basename(target_path)
    strpath = gdb.execute("show solib-search-path", False, True)
    path = strpath.split()[-1]
    strlen = len(path)
    if strlen != 1:
        path = path[0:strlen-1]
    host_path = path + "/" + so_name
    #strlen = len(host_path)
    #host_path = host_path[0:strlen-7]
    return host_path

class enclave_info(object):
    """Class to contain the enclave inforation,
    such as start address, stack addresses, stack size, etc.
    The enclave information is for one enclave."""
    def __init__(self, _next_ei, _start_addr, _enclave_type, _stack_addr_list, \
            _stack_size, _enclave_path, _heap_addr, _tcs_addr_list):
        self.next_ei         =   _next_ei
        self.start_addr      =   _start_addr
        self.enclave_type    =   _enclave_type
        self.stack_addr_list =   _stack_addr_list
        self.stack_size      =   _stack_size
        self.enclave_path    =   _enclave_path
        self.heap_addr       =   _heap_addr
        self.tcs_addr_list   =   _tcs_addr_list
    def __str__(self):
        print ("stack address list = {0:s}".format(self.stack_addr_list))
        return "start_addr = %#x, enclave_path = \"%s\", stack_size = %d" \
            % (self.start_addr, self.enclave_path, self.stack_size)
    def __eq__(self, other):
        if other == None:
            return False
        if self.start_addr == other.start_addr:
            return True
        else:
            return False
    def init_enclave_debug(self):
        # Only product HW enclave can't be debugged
        if (self.enclave_type & ET_SIM) != ET_SIM and (self.enclave_type & ET_DEBUG) != ET_DEBUG:
            print ('Warning: {0:s} is a product hardware enclave. It can\'t be debugged and sgx_emmt doesn\'t work'.format(self.enclave_path))
            return -1
        # set TCS debug flag
        for tcs_addr in self.tcs_addr_list:
            string = read_from_memory(tcs_addr + 8, 4)
            if string == None:
                return 0
            flag = struct.unpack('I', string)[0]
            flag |= 1
            gdb_cmd = "set *(unsigned int *)%#x = %#x" %(tcs_addr + 8, flag)
            gdb.execute(gdb_cmd, False, True)
        #If it is a product enclave, won't reach here.
        #load enclave symbol
        if os.path.exists(self.enclave_path) == True:
            enclave_path = self.enclave_path
        else:
            enclave_path = target_path_to_host_path(self.enclave_path)
        gdb_cmd = load_symbol_cmd.GetLoadSymbolCommand(enclave_path, str(self.start_addr))
        if gdb_cmd == -1:
            return 0
        print (gdb_cmd)
        gdb.execute(gdb_cmd, False, True)
        global ENCLAVES_ADDR
        ENCLAVES_ADDR[self.start_addr] = gdb_cmd.split()[2]
        return 0

    def get_peak_heap_used(self):
        """Get the peak value of the heap used"""
        if self.heap_addr == 0:
            return -2
        # read the peak_heap_used value
        string = read_from_memory(self.heap_addr, SIZE)
        if string == None:
            return -1
        if SIZE == 4:
            fmt = 'I'
        elif SIZE == 8:
            fmt = "Q"
        peak_heap_used = struct.unpack(fmt, string)[0]
        return peak_heap_used

    def internal_compare (self, a, b):
        return (a > b) - (a < b)

    def find_boundary_page_index(self, stack_addr, stack_size):
        """Find the unused page index of the boundary for the used and unused pages
            with the binary search algorithm"""
        page_index = -1   #record the last unused page index
        low = 0
        high = (stack_size>>12) - 1
        mid = 0
        # Read the mid page and check if it is used or not
        # If the mid page is used, then continue to search [mid+1, high]
        while low <= high:
            #print "low = %x, high = %x, mid = %x" % (low, high, mid)
            mid = (low + high)>>1
            string = read_from_memory(stack_addr + mid*PAGE_SIZE + (PAGE_SIZE>>1), PAGE_SIZE>>1)
            if string == None:
                return -2
            dirty_flag = 0
            for i in range(0, PAGE_SIZE>>4):
                temp = struct.unpack_from("Q", string, ((PAGE_SIZE>>4) - 1 - i)*8)[0]
                if (self.internal_compare(temp, 0xcccccccccccccccc)) != 0:
                    dirty_flag = 1
                    break
            if dirty_flag == 0:
                low = mid + 1
                page_index = mid
            else:
                high = mid -1
        return page_index

    def get_peak_stack_used(self):
        """Get the peak value of the stack used"""
        peak_stack_used = 0
        for tcs_addr in self.tcs_addr_list:
            tcs_str = read_from_memory(tcs_addr, ENCLAVE_TCS_INFO_SIZE)
            if tcs_str == None:
                return -1
            tcs_tuple = struct.unpack_from(TCS_INFO_FMT, tcs_str)
            offset = tcs_tuple[7]
            if SIZE == 4:
                td_fmt = '20I'
            elif SIZE == 8:
                td_fmt = '20Q'
            td_str = read_from_memory(self.start_addr+offset, (20*SIZE))
            if td_str == None:
                return -1
            td_tuple = struct.unpack_from(td_fmt, td_str)

            stack_commit_addr = td_tuple[19]
            stack_base_addr = td_tuple[2]
            stack_limit_addr = td_tuple[3]

            stack_usage = 0
            if stack_commit_addr > stack_limit_addr:
                stack_base_addr_page_align = (stack_base_addr + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
                stack_usage = stack_base_addr_page_align - stack_commit_addr
            elif stack_limit_addr != 0:
                page_index = self.find_boundary_page_index(stack_limit_addr, self.stack_size)
                if page_index == (self.stack_size)/PAGE_SIZE - 1:
                    continue
                elif page_index == -2:
                    return -1
                else:
                    string = read_from_memory(stack_limit_addr + (page_index+1) * PAGE_SIZE, PAGE_SIZE)
                    if string == None:
                        return -1
                    for i in range(0, len(string)):
                        temp = struct.unpack_from("B", string, i)[0]
                        if (self.internal_compare(temp, 0xcc)) != 0:
                            stack_usage = self.stack_size - (page_index+1) * PAGE_SIZE - i
                            break

            if peak_stack_used < stack_usage:
                peak_stack_used = stack_usage

        return peak_stack_used

    def show_emmt(self):
        ret = gdb.execute("show sgx_emmt", False, True)
        if ret.strip() == "sgx_emmt enabled":
            print ("Enclave: \"{0:s}\"".format(self.enclave_path))
            peak_stack_used = self.get_peak_stack_used()
            if peak_stack_used == -1:
                print ("Failed to collect the stack usage information for \"{0:s}\"".format(self.enclave_path))
            else:
                peak_stack_used_align = (peak_stack_used + KB_SIZE - 1) & ~(KB_SIZE - 1)
                print ("  [Peak stack used]: {0:d} KB".format(peak_stack_used_align >> 10))
            peak_heap_used = self.get_peak_heap_used()
            if peak_heap_used == -1:
                print ("Failed to collect the heap usage information for \"{0:s}\"".format(self.enclave_path))
            elif peak_heap_used == -2:
                print ("  [Can't get peak heap used]: You may use version script to control symbol export. Please export \'g_peak_heap_used\' in your version script.")
            else:
                peak_heap_used_align = (peak_heap_used + KB_SIZE - 1) & ~(KB_SIZE - 1)
                print ("  [Peak heap used]:  {0:d} KB".format(peak_heap_used_align >> 10))

    def fini_enclave_debug(self):
        # If it is HW product enclave, nothing to do
        if (self.enclave_type & ET_SIM) != ET_SIM and (self.enclave_type & ET_DEBUG) != ET_DEBUG:
            return -2
        self.show_emmt()
        try:
            # clear TCS debug flag
            for tcs_addr in self.tcs_addr_list:
                string = read_from_memory(tcs_addr + 8, 4)
                if string == None:
                    return -2
                flag = struct.unpack('I', string)[0]
                flag &= (~1)
                gdb_cmd = "set *(unsigned int *)%#x = %#x" %(tcs_addr + 8, flag)
                gdb.execute(gdb_cmd, False, True)
            #unload symbol
            if os.path.exists(self.enclave_path) == True:
                enclave_path = self.enclave_path
            else:
                enclave_path = target_path_to_host_path(self.enclave_path)
            gdb_cmd = load_symbol_cmd.GetUnloadSymbolCommand(enclave_path, str(self.start_addr))
            if gdb_cmd == -1:
                return -1
            print (gdb_cmd)
            try:
                gdb.execute(gdb_cmd, False, True)
                global ENCLAVES_ADDR
                del ENCLAVES_ADDR[self.start_addr]
            except gdb.error:
                print ("Old gdb doesn't support remove-file-symbol command")
            return 0
        ##It is possible enclave has been destroyed, so may raise exception on memory access
        except gdb.MemoryError:
            return -1
        except:
            return -1

    def append_tcs_list(self, tcs_addr):
        for tcs_tmp in self.tcs_addr_list:
    	    if tcs_tmp == tcs_addr:
    	        return 0
        self.tcs_addr_list.append(tcs_addr)
        return 0

class CreateEnclaveBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="__gdb_hook_init_done", internal=1)

    def stop(self):
        global ubase, heap_size, debug_file
        try:
            ubase = gdb.parse_and_eval("(uint64_t)ubase")
            heap_size = gdb.parse_and_eval("(uint64_t)heap_size")
            print("Enclave base: %x" % int(ubase))
            print("Enclave heap size: %d" % int(heap_size))
        except:
            print("Error while trying to determine enclave base address")
            return False

        gdb_cmd = load_symbol_cmd.GetLoadSymbolCommand(debug_file.filename + ".debug", str(ubase), str(heap_size))
        if gdb_cmd == -1:
            return 0
        print (gdb_cmd)
        gdb.execute(gdb_cmd, False, True)
        
        tcs_num = int(gdb.parse_and_eval("get_tcs_num()"))
        for i in range(tcs_num):
            tcs_addr = gdb.parse_and_eval("get_tcs_addr(" + str(i) + ")")
            gdb_cmd = "set *(unsigned int *)%#x = %#x" %(int(tcs_addr.cast(gdb.lookup_type('long'))) + 8, 1)
            gdb.execute(gdb_cmd, False, True)

        self.enabled = False
        return False

class LoadEventBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="sgx_debug_load_state_add_element", internal=1)

    def stop(self):
        bp_in_urts = is_bp_in_urts()

        if bp_in_urts == True:
            handle_load_event()
        return False

class UnloadEventBreakpoint(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__ (self, spec="sgx_debug_unload_state_remove_element", internal=1)

    def stop(self):
        bp_in_urts = is_bp_in_urts()

        if bp_in_urts == True:
            handle_unload_event()
        return False

def sgx_debugger_init():
    print ("detected SGX-LKL, initializing")
    CreateEnclaveBreakpoint()

    #execute "set displaced-stepping off" to workaround the gdb 7.11 issue
    gdb.execute("set displaced-stepping off", False, True)

def exit_handler(event):
    # When the inferior exited, remove all enclave symbol
    for key in list(ENCLAVES_ADDR.keys()):
        gdb.execute("remove-symbol-file -a %s" % (ENCLAVES_ADDR[key]), False, True)
    ENCLAVES_ADDR.clear()

def newobj_handler(event):
    global inited, debug_file
    obj = event.new_objfile
    print(obj.filename)
    if (gdb.lookup_global_symbol("__gdb_hook_init_done") != None and inited == 0):
        inited = 1
        debug_file = obj
        #obj.add_separate_debug_file(obj.filename + ".debug")
        sgx_debugger_init()
    return

if __name__ == "__main__":
    gdb.events.new_objfile.connect(newobj_handler)
    sgx_emmt.init_emmt()
