import lief
import common_util
from datetime import datetime,timezone
from concurrent.futures import ThreadPoolExecutor

def ExtractOptionalHeaderFeat(parsed_file):
    op_header : lief.PE.OptionalHeader = parsed_file.optional_header
    the_packet = {}
    the_packet["Address Of Entry"] = common_util.ConvertIntToHex(op_header.addressof_entrypoint)
    the_packet["Size of Code"] = op_header.sizeof_code
    the_packet["Size of Image"] = op_header.sizeof_image
    
    the_packet["Size Of Headers"] = op_header.sizeof_headers
    the_packet["Size of unintialized data"] = op_header.sizeof_uninitialized_data
    the_packet["Size of intialized data"] = op_header.sizeof_initialized_data
    the_packet["Base of code"] = op_header.baseof_code
    the_packet["Image base"] = op_header.imagebase
    the_packet["Number of RVA"] = op_header.numberof_rva_and_size
    the_packet["Size of stack reserve"] = op_header.sizeof_stack_reserve
    the_packet["Size of stack commit"] = op_header.sizeof_stack_commit
    the_packet["Size of heap reserve"] = op_header.sizeof_heap_reserve
 

    return the_packet
    

def ExtractLibraries(parsed_file):
    libraries = {}
    for imported_libraries in parsed_file.imports:
        libraries[imported_libraries.name] = []
        for funcs in imported_libraries.entries:
            libraries[imported_libraries.name].append(funcs.name)
    return libraries
                
def ExtractCOFFHeader(parsed_file):
    header : lief.PE.Header = parsed_file.header
    header_packet = {}
    time_stamp = header.time_date_stamps
    header_packet["Compiled time"] = datetime.fromtimestamp(time_stamp, tz=timezone.utc).isoformat()
    header_packet["Number of sections"] = header.numberof_sections
    header_packet["Size of Optional Header"] = header.sizeof_optional_header
    return header_packet

def StartExtractingPE(file):
    parsed_file = lief.parse(file)
    big_one = {}
    #Added multi threading for extracting strings and capa to increase speed
    ex = ThreadPoolExecutor(max_workers=2)
    f1 = ex.submit(common_util.ExtractStrings, file)
    f2 = ex.submit(common_util.CapaExtract, file)

    big_one["Size"] = common_util.GetFileSize(file)
    big_one["Entropy"] = common_util.EntropyCalc(file)
    big_one["COFF Header"] = ExtractCOFFHeader(parsed_file)
    big_one["Optional Header"] = ExtractOptionalHeaderFeat(parsed_file)
    big_one["Libraries and API"] = ExtractLibraries(parsed_file)

    big_one["Strings"] = f1.result()
    
    capa_pack = f2.result()
    big_one["CAPA"] = capa_pack["CAPA"]
    big_one["MBC"] = capa_pack["MBC"]
    big_one["ATT&CK"] = capa_pack["ATT&CK Tactic"]
    ex.shutdown() 
    return big_one
    