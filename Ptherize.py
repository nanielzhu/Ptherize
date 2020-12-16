# ! C:\Users\dzhu002\AppData\Local\Programs\Python\Python36\python


'''this tool is only be used  to decode messages captured by WCS single message traces tools, it will convert to pcap format
 for wireshark,
 usage Ptherize.py  inputfile -o outputfile -t msg/syn -v
 -t msg will decode SMT result, -t SYN to decode synwatch result; -v to turn on debug mode
 debug file will be C:\Temp\debug.txt
 Author: Daniel '''

import os
import re
import sys




debugfile = r'C:\Temp\debug.txt'
outputfile = r'C:\Temp\output.txt'
pcapfile = r'C:\Temp\result.pcap'
debugon = 0
nummsgfound = 0
sccpInst2Type = {}

defSetting = {
    'Ssn': 142,
    'RanapSsn': 142,
    'ownPc': 257,
    'ranPc': 514,
    'ranMtPc': 771,
    'ranHoPc': 772
}

proto2PC = {
    'SCCP': 516,
    'ISUP': 517,
    'BICC': 518,
    'ALCAP': 519,
    'TEXT': 257
}

ranSSN = [142, 222, 254]

optSetting = {
    'type': 'MSG'
}
hexdig = r'[0-9|A-F][0-9|A-F]\s'
hexdig2 = r'[0-9|A-F][0-9|A-F]'
hexdigLC = r'[0-9|a-f][0-9|a-f]'
zeroXDig = '0x[0-9|A-F][0-9|A-F]\s'
sccpInst2Type = {}

siMap = {
    'snm': '0',
    'mtns': '2',
    'sccp': '3',
    'isup': '5',
    'alcap': 'C',
    'bicc': 'D'
}

SI2Proto = {
    '3': 'SCCP',
    '5': 'ISUP',
    'C': 'ALCAP',
    'D': 'BICC'
}

##protocol to service indicator, ANSI version
proto2Si_a = {
    'SCCP': '83',
    'ISUP': '85',
    'ALCAP': '8c',
    'BICC': '8d',
}

# protocol to Service Indicator ITU version
proto2Si_i = {
    'SCCP': '03',
    'ISUP': '05',
    'ALCAP': '0c',
    'BICC': '0d'
}


def getSI(protocol):
    return int(proto2Si_i[protocol], 16)


dataLenToStripDigs = {
    '35': 6,
    '27': 6,
    '87': 3,
    '91': 3,
    '19': 5,
    '23': 3
}

#########################
## All Protocol Template
########################


byteHeader = '0000'
ethernetHeader = '02 02 02 02 02 02 02 02 02 02 02 01 08 00'

# IP template for SCTP (0x84 proto)
ipTmplt = '45 00 {:02x} {:02x} 12 34 00 00 ff 84 a2 44 01 01 01 01 02 02 02 02'  # IP length byte1, IP lenbyte2
ipTmpltSize = 32

ipTmpltForTcp = '45 00 {0:02x} {0:02x} 12 34 00 00 ff 06 a2 44 %s %s'
tcpTmplt = '36 b1 36 b1 00 00 00 01 00 00 00 00 60 00 00 01 00 00 00 00 00 00 00 00'
tcpTmpltSize = 24

# for M2UA SCTP,
sctpM2uaTmplt = '0b 58 0b 58 00 00 00 00 73 c6 39 7b 00 03 {:02x} {:02x} 00 00 00 00 00 00 00 00 00 00 00 02'
sctpM2uaTmpltSize = 14

# SCTP header for M3UA, len1 and len2, last 03 mean M3UA.it will be for ITU version
sctpM3uaTmplt = '0b 58 0b 58 00 00 00 00 73 c6 39 7b 00 03 {:02x} {:02x} 00 00 00 00 00 00 00 00 00 00 00 03'
sctpM3uaTmpltSize = 16

# SCTP header for WCS primitive, len1 and len2,     last cd mean Unknown.
sctpTextTmplt = '13 cd 13 cd 00 00 00 00 73 c6 39 7b 00 03 {:02x} {:02x} 00 00 00 00 00 00 00 00 00 00 13 cd'
sctpTextTmpltSize = 16

urrTmplt = '{0:02x} {0:02x} 01'
urrTmpltSize = 3

# for ANSI, it use M2UA
m2uaTmplt = '01 00 06 01 00 00 {:02x} {:02x} 03 00 {:02x} {:02x}'  # len1 len2 parmlen1 parmlen2
m2uaTmpltbytessize = 10
m2uaTmpltparmsize = 4

# M3UA ITU version--->       bytelen1,bytelen2, parmlen1 parmlen2 dpc1 dpc2 dpc3 opc1 opc2 opc3 serviceindicator
m3uaTmplt = '01 00 01 01 00 00 {:02x} {:02x} 02 10 {:02x} {:02x} 00 {:02x} {:02x} {:02x} 00 {:02x} {:02x} {:02x} {:02x} 02 00 0b'
m3uaTmpltbytesize = 8
m3uaTmpltparmsize = 16

#  ITU SCCP non-Connection
#                           calledpc2 calledpc3 called_ssn, callingpc2 callingpc3 callingssn sccplen
sccpTmplt = '09 00 03 07 0b 04 43 {:02x} {:02x} {:02x} 04 43 {:02x} {:02x} {:02x} {:02x}'
sccpTmpltLen = 16

#   ITU XUDT SCCP
#           Segment offset,  calledpc2 calledpc3 called ssn callingpc2 callingpc3 callingSSN sccplen
sccpXudtTmplt = '11 81 05 04 08 0c {:02x} 04 43 {:02x} {:02x} {:02x} 04 43 {:02x} {:02x} {:02x} {:02x}'
sccpXudtTmpltLen = 7
sccpXudtParamTmpltLen = 12

# ITU  XUDT SCCP message Footer segment,
#                        remainign segement, SLR,
sccpXudtFooterTmplt = '10 04 {:02x} {:02x} {:02x} {:02x} 00'
sccpXudtFooterTmpltLen = 6

# ANSI SCCP Connection template
sccpCoTmpltHash = {
    'SCCP_CON': '01 {:02x} {:02x} {:02x} 02 02 04 02 c1 {:02x} 04 02 c1 {:02x} 0f {:02x}',
# slr called_ssn  calling_ssn  dataLen
    'SCCP_CC': '02 {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} 02 01 0f {:02x}',  # dlr     slr    dataLen
    'SCCP_DAT': '06 {:02x} {:02x} {:02x} 00 01 {:02x}',  # dlr    dataLen
    'SCCP_DIS': '04 {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} 00 00'  # dlr               slr
}



def calsccpLen(sccpTmpl, sccpLen):
    for key, value in sccpTmpl.items():
        sccpLen[key] = len(list(value.split(' ')))


sccpCoTmpltLen = {}
calsccpLen(sccpCoTmpltHash, sccpCoTmpltLen)

# ITU SCCP CONNECTION Template
sccpCoTmpltItu = {
    'SCCP_CON': '01 {:02x} {:02x} {:02x} 02 02 06 04 43 {:02x} {:02x} {:02x} 04 04 43 {:02x} {:02x} {:02x} 0f {:02x}',
# slr PC ssn  PC, SSN  dataLen
    'SCCP_CC': '02 {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} 02 01 0f {:02x}',  # dlr  slr   dataLen
    'SCCP_DAT': '06 {:02x} {:02x} {:02x} 00 01 {:02x}',  # dlr      dataLen
    'SCCP_DIS': '04 {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} 00 00'  # dlr   slr
}

sccpCoTmpltItuLen = {}
calsccpLen(sccpCoTmpltItu, sccpCoTmpltItuLen)

pattern_len_data = re.compile(r'SCCP_MSU.*  ({})({})(({})+)'.format(zeroXDig, zeroXDig, zeroXDig))
pattern_len_bicc = re.compile(r'ISUP_MSU.*  ({})({})(({})+)'.format(zeroXDig, zeroXDig, zeroXDig))
pattern_len_isup = re.compile(r'ISUP_MSU.*  ({})({})(({})+)MsgType'.format(zeroXDig, zeroXDig, zeroXDig))
pattern_sccp_con = re.compile(r'OamMtDecode.cc.* Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP_CONNECTION_DATA')
pattern_sccp_pcssn = re.compile(
        r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP.*calling: pc=(\d+).*SSN=(\d+).*called: pc=(\d+).*SSN=(\d+).*SCCP_MSU')
pattern_sccp_ssn = re.compile(
    r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP.*calling: pc=(\d+).*SSN=(\d+).*called.*SSN=(\d+).*SCCP_MSU')
pattern_sccp_2ssn = re.compile(
    r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP.*calling.*SSN=(\d+).*called.*SSN=(\d+).*SCCP_MSU')
pattern_no_pcssn = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP_.*SCCP_MSU')
pattern_bicc = re.compile(
    r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SGW_BICC_ID.*ISUP_DAT_.*OPC=(\d+) DPC=(\d+).*ISUP_MSU')

pattern_isup = re.compile(
    r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SGW_ISUP_ID.*ISUP_DAT_.*OPC=(\d+) DPC=(\d+).*ISUP_MSU')
pattern_alcap = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*ALCAP_MSU')

def pcfromText(pcDecimal):
    if isinstance(pcDecimal, str):
        pcDecimal = int(pcDecimal)
    pc1 = (pcDecimal & 0xFF0000) >> 16
    pc2 = (pcDecimal & 0x00FF00) >> 8
    pc3 = pcDecimal & 0x0000FF
    return pc1, pc2, pc3


def lrfromText(lrDecimal):
    if isinstance(lrDecimal, str):
        lrDecimal = int(lrDecimal)
    lr3 = (lrDecimal & 0xFF0000) >> 16
    lr2 = (lrDecimal & 0x00FF00) >> 8
    lr1 = lrDecimal & 0x0000FF
    return lr1, lr2, lr3


def random_slr():
    from random import randint
    slr1 = 0
    tmprandom = randint(1, 1000)
    slr2, slr3 = divmod(tmprandom, 256)

    return slr1, slr2, slr3


def checkPC(callingpc, calledpc, callingssn, calledssn, protocol):
    if callingpc != defSetting['ownPc']:
        # worked on calling pc
        if callingssn not in ranSSN:
            callingpc = proto2PC[protocol]
    else:
        # working on the called PC
        if calledssn not in ranSSN:
            calledpc = proto2PC[protocol]
    return callingpc, calledpc


def check_SSN(callingssn, calledssn):
    if callingssn == 0 and calledssn == 0 :
        callingssn = defSetting['Ssn']
        calledssn = defSetting['Ssn']
    elif calledssn == 0:
        calledssn = callingssn
    elif callingssn == 0:
        callingssn = calledssn

    return callingssn, calledssn


def debug(text):
    global debugon
    if debugon == 1:
        with open(debugfile, 'a') as fp:
            fp.write(text)
    else:
        return 0


def output(text):
    with open(outputfile, 'a') as fp:
        fp.write(text)


def print_help_message(linenum, protocol, callingpc, calledpc, date, time):
    output('\n######################################################\n')
    output('# Protocol = {} Logfile Linenum={}\n'.format(protocol, linenum))
    output('# Calling PC = {}\n'.format(callingpc))
    output('# called PC = {}\n'.format(calledpc))
    output('{} {}\n\n'.format(date, time))
    return 0


# get SCCP non-connection MSU length
def getMsuDataLen(lenbyte1, lenbyte2, data_r):
    # "0x64 " -> 5 characters per hex byte dump
    datalen = len(data_r)

    # convert lenbyte into int
    lenbyte1 = int(lenbyte1, 16)
    lenbyte2 = int(lenbyte2, 16)

    # little-endian length
    lelen = (lenbyte2 * 256 + lenbyte1) * 5
    if (datalen - lelen) >= 0 and (datalen - lelen) > 25:
        templen = lelen + 15
    else:
        # Big Endian length
        belen = (lenbyte1 * 256 + lenbyte2) * 5
        if 0 <= (datalen - belen) < 20:
            templen = belen
        else:
            templen = lelen

    if templen != datalen:
        data_r = data_r[:templen]

    trimdata = re.sub('0x', '', data_r)
    return trimdata, datalen


# get internal message length
def getTextMsuDataLen(lenbyte1, lenbyte2, data_r):
    # "0x64 " -> 5 characters per hex byte dump
    datalen = len(data_r) // 5

    lenbyte1 = int(lenbyte1, 16)
    lenbyte2 = int(lenbyte2, 16)

    # little-endian length
    lelen = (lenbyte2 * 256 + lenbyte1) * 5
    templen = datalen
    if 0 <= (datalen - lelen) < 20:
        templen = lelen
    else:
        # Big Endian length
        belen = (lenbyte1 * 256 + lenbyte2) * 5
        if 0 <= (datalen - belen) < 20:
            templen = belen

    if templen != datalen:
        data_r = data_r[:templen]

    trimdata = re.sub('0x', '', data_r)
    return trimdata


# get SCCP CONNECTION MSU length
def getConMsuDataLen(lenbyte1, lenbyte2, data_r):
    # "0x64 " -> 5 characters per hex byte dump
    datalen = len(data_r)
    lenbyte1 = int(lenbyte1, 16)
    lenbyte2 = int(lenbyte2, 16)

    # little-endian length
    templen = datalen
    lelen = (lenbyte2 * 256 + lenbyte1) * 5
    if 0 <= (datalen - lelen) < 20:
        templen = lelen
    else:
        # Big Endian length
        belen = (lenbyte1 * 256 + lenbyte2) * 5
        if 0 <= (datalen - belen) < 20:
            templen = belen

    if templen != datalen:
        data_r = data_r[:templen]

    trimdata = re.sub('0x', '', data_r)
    return trimdata



# check if a SCCP_CON_IND is for MT (i.e. contains Paging response)
def isConnIndforMT(thismessage):
    if 'msgId=MBD_RR_PagingResponse' in thismessage:
        return True
    else:
        find1 = re.search(r'Layer3Info.*?=06 27', thismessage)
        find2 = re.search(r'nasPDU =.*?val = 06 27', thismessage)
        if find1 or find2:
            return True
        return False


# check the SCCP connection type (0-MO, 1-MT, 2-HO) of a SCCP CO message
def checkSccpConType(suInstId, spInstId):
    try:
        suType = sccpInst2Type[suInstId]
    except:
        try:
            spType = sccpInst2Type[spInstId]
        except:
            return 0
        else:
            sccpInst2Type[suInstId] = spType
            return spType
    else:
        try:
            _ = sccpInst2Type[spInstId]
        except:
            sccpInst2Type[spInstId] = suType
            return suType
        else:
            return suType


def handle_mtp_portion(protocol, callingpc, calledpc, sizeabovemtp3, sccpheader, data_r, sccpfooter):
    calledpc1, calledpc2, calledpc3 = pcfromText(calledpc)
    callingpc1, callingpc2, callingpc3 = pcfromText(callingpc)
    if protocol == 'MTP3':
        mtpparmlen = sizeabovemtp3 + m2uaTmpltparmsize
        mtplen = mtpparmlen + m2uaTmpltbytessize
        mtplenbyte1, mtplenbyte2 = divmod(mtplen, 256)
        mtpparmlenbyte1, mtpparmlenbyte2 = divmod(mtpparmlen, 256)

        mtpportion = m2uaTmplt.format(mtplenbyte1, mtplenbyte2, mtpparmlenbyte1, mtpparmlenbyte2)

    elif protocol == 'TEXT':
        mtplen = sizeabovemtp3
        mtpportion = ''
        sccpheader = ''
    elif protocol == 'ISUP' or protocol == 'BICC':
        mtpparmlen = sizeabovemtp3 + m3uaTmpltparmsize
        mtplen = mtpparmlen + m3uaTmpltbytesize
        mtplenbyte1, mtplenbyte2 = divmod(mtplen, 256)
        mtpparmlenbyte1, mtpparmlenbyte2 = divmod(mtpparmlen, 256)
        si = getSI(protocol)
        mtpportion = m3uaTmplt.format(mtplenbyte1, mtplenbyte2, mtpparmlenbyte1, mtpparmlenbyte2, callingpc1, callingpc2,
                                      callingpc3, calledpc1, calledpc2, calledpc3, si)
    else:  # SCCP and ALCAP share same case here
        mtpparmlen = sizeabovemtp3 + m3uaTmpltparmsize
        mtplen = mtpparmlen + m3uaTmpltbytesize
        mtplenbyte1, mtplenbyte2 = divmod(mtplen, 256)
        mtpparmlenbyte1, mtpparmlenbyte2 = divmod(mtpparmlen, 256)
        si = getSI(protocol)
        mtpportion = m3uaTmplt.format(mtplenbyte1, mtplenbyte2, mtpparmlenbyte1, mtpparmlenbyte2, callingpc1,callingpc2,
                                      callingpc3, calledpc1, calledpc2, calledpc3, si)

    if protocol == 'TEXT' or protocol == 'ISUP' or protocol == 'BICC':
        sctplen = mtplen + sctpTextTmpltSize
    elif protocol == 'MTP3':
        sctplen = mtplen + sctpM2uaTmpltSize
    else:
        sctplen = mtplen + sctpM3uaTmpltSize

    sctplenbyte1, sctplenbyte2 = divmod(sctplen, 256)

    if protocol == 'TEXT':
        sctpportion = sctpTextTmplt.format(sctplenbyte1, sctplenbyte2)
    elif protocol == 'MTP3':
        sctpportion = sctpM2uaTmplt.format(sctplenbyte1, sctplenbyte2)
    else:
        sctpportion = sctpM3uaTmplt.format(sctplenbyte1, sctplenbyte2)

    iplen = sctplen + ipTmpltSize
    iplenbyte1, iplenbyte2 = divmod(iplen, 256)

    ipportion = ipTmplt.format(iplenbyte1, iplenbyte2)

    output('{}   {}   {}   {}   {}   {}   {}  {}\n\n'.format(byteHeader, ethernetHeader, ipportion, sctpportion,
                                                             mtpportion, sccpheader, data_r, sccpfooter))
    return 0


def formatSynEthCapfile(linenum, protocol, date, time, callingpc, calledpc, data_r):
    global nummsgfound
    nummsgfound = nummsgfound + 1
    # trim leading spaces
    data_r = data_r.strip()
    datasize = len(list(data_r.split(' ')))

    debug('Syn Message ,Date:{},Time:{},Protocol={},callingpc:{},called pc:{}\n\n'.format(date, time, protocol,
                                                                                          callingpc, calledpc))
    #    print('HAAAAAAAAAAA--:MESSAGE:{}\n'.format(data_r))

    print_help_message(linenum, protocol, callingpc, calledpc, date, time)

    sizeabovemtp3 = datasize
    sccpheader = ''
    sccpfooter = ''

    handle_mtp_portion(protocol, callingpc, calledpc, sizeabovemtp3, sccpheader, data_r, sccpfooter)


def formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, data_r):
    global nummsgfound
    nummsgfound = nummsgfound + 1
    # trim leading spaces
    data_r = data_r.strip()
    datasize = len(list(data_r.split(' ')))

    debug('ITU normal,Date:{},Time:{},PROTOCOL={},DATA SIZE:{},callingSSN:{},called SSN:{}\n\n'.format(date, time, protocol, datasize,
                                                                                           callingssn, calledssn))
    #    print('HAAAAAAAAAAA--:MESSAGE:{}\n'.format(data_r))

    if protocol == 'SCCP':
        callingssn, calledssn = check_SSN(callingssn, calledssn)
        callingpc, calledpc = checkPC(callingpc, calledpc, callingssn, calledssn, protocol)
    elif protocol == 'BICC' or protocol == 'ISUP':
        if callingpc == 0:
            callingpc = proto2PC[protocol]
        if calledpc == 0:
            calledpc = proto2PC[protocol]
    else:
        if callingpc != defSetting['ownPc']:
            callingpc = proto2PC[protocol]
        else:
            calledpc = proto2PC[protocol]

    calledpc1, calledpc2, calledpc3 = pcfromText(calledpc)
    callingpc1, callingpc2, callingpc3 = pcfromText(callingpc)
#   print('I am here:callingpc={},calledpc={},callingssn={},calledssn={}\n'.format(callingpc,calledpc,callingssn,calledssn))
    print_help_message(linenum, protocol, callingpc, calledpc, date, time)
    sccpheader = ''
    if callingssn or calledssn:
        sccplen = datasize
        debug('SCCP LEN = {};\nSCCP MESSAGE:{}\n'.format(sccplen, data_r))
        # trancated long sCCP message
        if sccplen >= 256:
            sccplen = 255

        #    print(calledpc2,calledpc3,calledssn,callingpc2,callingpc3,callingssn,sccplen)

        sccpheader = sccpTmplt.format(calledpc2, calledpc3, calledssn, callingpc2, callingpc3, callingssn, sccplen)

        sizeabovemtp3 = datasize + sccpTmpltLen
    else:
        sizeabovemtp3 = datasize

    sccpfooter = ''
    handle_mtp_portion(protocol, callingpc, calledpc, sizeabovemtp3, sccpheader, data_r, sccpfooter)


def formatItuSccpConEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, slr, dlr,
                               data_r):
    global nummsgfound
    nummsgfound = nummsgfound + 1
    # trim leading spaces
    data_r = data_r.strip()
    datasize = len(list(data_r.split(' ')))
    debug('ITU SCCP CONN,Time:{},DATA SIZE:{},\nMESSAGE={}\n'.format(time, datasize, data_r))

    callingssn, calledssn = check_SSN(callingssn, calledssn)

    calledpc1, calledpc2, calledpc3 = pcfromText(calledpc)
    callingpc1, callingpc2, callingpc3 = pcfromText(callingpc)

    slr1, slr2, slr3 = lrfromText(slr)
    dlr1, dlr2, dlr3 = lrfromText(dlr)

    sccpcotmplt = sccpCoTmpltItu[protocol]
    sccpcotmpltlen = sccpCoTmpltItuLen[protocol]

    sccpfooter = ""
    sccpfooterlen = 0
    sccplen = datasize

    if protocol == 'SCCP_CON':
        if sccplen == 0:
            debug('SCCP LEN is 0, Ignore this messagem , line number is {}\n'.format(linenum))
            return 0

        sccpfooter = '00'
        sccpfooterlen = 1
        sccpheader = sccpcotmplt.format(slr1, slr2, slr3, calledpc2, calledpc3, calledssn, callingpc2, callingpc3,
                                        callingssn, sccplen)
    elif protocol == 'SCCP_CC':
        if sccplen == 0:
            debug('SCCP LEN is 0, Ignore this messagem , line number is {}\n'.format(linenum))
            return 0
        sccpfooter = '00'
        sccpfooterlen = 1
        sccpheader = sccpcotmplt.format(dlr1, dlr2, dlr3, slr1, slr2, slr3, sccplen)
    elif protocol == 'SCCP_DAT':
        sccpheader = sccpcotmplt.format(dlr1, dlr2, dlr3, sccplen)
    else:
        sccpheader = sccpcotmplt.format(dlr1, dlr2, dlr3, slr1, slr2, slr3)

    print_help_message(linenum, protocol, callingpc, calledpc, date, time)

    # calculate total size for SCCP and above
    sizeabovemtp3 = datasize + sccpcotmpltlen + sccpfooterlen
    protocol = 'SCCP'
    handle_mtp_portion(protocol, callingpc, calledpc, sizeabovemtp3, sccpheader, data_r, sccpfooter)


def formatItuSccpXudtEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, data_r,
                                tmpsccpseg, slr1, slr2, slr3):
    global nummsgfound
    nummsgfound = nummsgfound + 1
    # trim leading spaces
    data_r = data_r.strip()
    datasize = len(list(data_r.split(' ')))

    debug('ITU SCCP XUDT,Date:{},Time:{},DATA SIZE:{}\nMessge={}\n'.format(date, time, datasize, data_r))

    if protocol == 'SCCP':
        callingssn, calledssn = check_SSN(callingssn, calledssn)
        # set pesudo-PC for non-RAN remote nodes
        callingpc, calledpc = checkPC(callingpc, calledpc, callingssn, calledssn, protocol)
    else:
        if callingpc != defSetting['ownPc']:
            callingpc = proto2PC[protocol]
        else:
            calledpc = proto2PC[protocol]

    calledpc1, calledpc2, calledpc3 = pcfromText(calledpc)
    callingpc1, callingpc2, callingpc3 = pcfromText(callingpc)

    #    debug('SLR= {} hex:{0:02x} {0:02x} {0:02x}; DLR={}  hex: {0:02x} {0:02x} {0:02x}\n'.format(slr,slr1, slr2, slr3,dlr,dlr1, dlr2, dlr3))

    if callingssn or calledssn:
        sccplen = datasize
        sccpfooter = sccpXudtFooterTmplt.format(tmpsccpseg, slr1, slr2, slr3)

        if sccplen >= 256:
            sccplen = 255

        sccpxudtsize = sccplen + sccpXudtParamTmpltLen

        sccpheader = sccpXudtTmplt.format(sccpxudtsize, calledpc2, calledpc3, calledssn, callingpc2, callingpc3,
                                          callingssn, sccplen)
        sizeabovemtp3 = sccpxudtsize + sccpXudtTmpltLen + sccpXudtFooterTmpltLen
    else:
        sizeabovemtp3 = datasize
        sccpheader = ''
        sccpfooter = ''

    print_help_message(linenum, protocol, callingpc, calledpc, date, time)
    handle_mtp_portion(protocol, callingpc, calledpc, sizeabovemtp3, sccpheader, data_r, sccpfooter)


def processTextMessage(linenum, origMsg):
    global nummsgfound
    nummsgfound = nummsgfound + 1
    import binascii
    debug('processTextMessage,Number MSG Found:{}\n\n'.format(nummsgfound))
    date = ''
    time = ''
    pat = re.compile(r'Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+)')
    find = pat.search(origMsg)
    if find:
        date, time = find[1], find[2]

    tmpmsg = binascii.b2a_hex(origMsg.encode('utf-8'))
    data = re.sub(r'([0-9a-f])([0-9a-f])', r'\1\2 ', tmpmsg.decode('ascii'))
    formatItuEthCapfile(linenum, 'TEXT', date, time, 0, 0, 0, 0, data)


def sccp_Conn_Handler(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage, outmsgprocessed):
    debug('\n ENTER SCCP_CON case,date={},Time={}\n'.format(date, time))
    find = re.search(r'calling:.* SSN=(\d+).* called:.* SSN=(\d+).* RtgInd=', thismessage)
    if find:
        callingssn = int(find[1])
        calledssn = int(find[2])

    if 'RaAllSdus' in thismessage:
        if calledssn == 0 and 'Dest: SGW_MTP3_ID' in thismessage:
            calledssn = defSetting['RanapSsn']
        if callingssn == 0 and 'Src:  SGW_MTP3_ID' in thismessage:
            callingssn = defSetting['RanapSsn']

    suinstid = 0
    spinstid = 0
    find = re.search(r'suInstId[=|:][-]?([0-9]+) spInstId[=|:][-]?([0-9]+)', thismessage)
    if find:
        suinstid = int(find[1])
        spinstid = int(find[2])
    else:
        debug('not matched suInstId/spInstId: suInstId={}: spInstId={}\n'.format(suinstid, spinstid))

    debug('callingssn={};calledssn={},suInst={};spInst={}\n'.format(callingssn, calledssn, suinstid, spinstid))
    if 'SCCP_CON_IND' in thismessage or 'SCCP_CON_REQ' in thismessage:
        protocol = 'SCCP_CON'
    elif 'SCCP_CON_RSP' in thismessage or 'SCCP_CON_CFM' in thismessage:
        protocol = 'SCCP_CC'
    elif 'SCCP_DIS' in thismessage:
        protocol = 'SCCP_DIS'
    else:
        protocol = 'SCCP_DAT'

    if protocol == 'SCCP_CON' and suinstid == 0 and spinstid == 0:
        debug('Special case for SCCP_CON,suinstid and spinstid are 0;\n\n')

    # sccpConType:: MO--->0; MT--->1; HO--->2

    if protocol == 'SCCP_CON' and callingpc == defSetting['ownPc']:
        sccpcontype = 2
        sccpInst2Type[suinstid] = sccpcontype
        calledpc = defSetting['ranHoPc']
    elif protocol == 'SCCP_CON' and isConnIndforMT(thismessage):
        sccpcontype = 1
        sccpInst2Type[spinstid] = sccpcontype
        callingpc = defSetting['ranMtPc']
    elif protocol != 'SCCP_CON' and suinstid > 0 and spinstid > 0:
        sccpcontype = checkSccpConType(suinstid, spinstid)
        if sccpcontype == 1:
            if callingpc != defSetting['ownPc']:
                callingpc = defSetting['ranMtPc']
            else:
                calledpc = defSetting['ranMtPc']
        elif sccpcontype == 2:
            if callingpc != defSetting['ownPc']:
                callingpc = defSetting['ranHoPc']
            else:
                calledpc = defSetting['ranHoPc']

    if outmsgprocessed == 1:
        slr, dlr = suinstid, spinstid
    else:
        slr, dlr = spinstid, suinstid

    find = pattern_len_data.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]

        trimdata = getConMsuDataLen(lenbyte1, lenbyte2, data)
        formatItuSccpConEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, slr, dlr,
                                   trimdata)
    return 0


def xudt_handle(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, datalen, trimdata):
    from math import ceil
    slr1, slr2, slr3 = random_slr()
    totalsccpseg = ceil(datalen / 1145)

    tmpsccpseglen = 687
    #           xudtsccppadding = ''
    for i in range(totalsccpseg):
        tmpsize = i * tmpsccpseglen
        endsize = (i + 1) * tmpsccpseglen
        if i == (totalsccpseg - 1):
            tmpsccpseg = trimdata[tmpsize:]
        else:
            tmpsccpseg = trimdata[tmpsize:endsize]

        if i == 0:
            tmpsccpsegpadding = 191 + totalsccpseg
        else:
            tmpsccpsegpadding = totalsccpseg + 63 - i
        formatItuSccpXudtEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn,
                                    tmpsccpseg, tmpsccpsegpadding, slr1, slr2, slr3)
    return 0


def sccp_Connless_Handle1(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER SCCP NON CONNECTION CASE1,date={},Time={},callingSSN:{},called SSN:{}\n'.format(date, time, callingssn, calledssn))

    find = pattern_len_data.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]
        debug('data={},lenbyte1={},lenbyte2={}\n'.format(data,lenbyte1, lenbyte2))
        trimdata, datalen = getMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'SCCP'
        if datalen > 1275:
            xudt_handle(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, datalen, trimdata)
            return 0
        else:
            formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, trimdata)
            return 0


def sccp_Connless_Handle2(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER SCCP NON CONNECTION CASE2,date={},Time={}\n'.format(date, time))

    find = pattern_len_data.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]

        trimdata, datalen = getMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'SCCP'
        if datalen > 1275:
            xudt_handle(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, datalen, trimdata)
            return 0
        else:
            formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn,
                                trimdata)
            return 0


def sccp_Connless_Handle3(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER SCCP NON CONNECTION CASE3,date={},Time={}\n'.format(date, time))

    find = pattern_len_data.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]

        trimdata, datalen = getMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'SCCP'
        if datalen > 1275:
            xudt_handle(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, datalen, trimdata)
            return 0
        else:
            formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn,
                                trimdata)
            return 0


def sccp_Connless_Handle4(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER  SCCP CONNTIONLESS case,date={},Time={}\n'.format(date, time))

    find = pattern_len_data.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]

        trimdata, _ = getMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'SCCP'
        formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, trimdata)

    return 0


def bicc_handle(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER  BICC case,date={},Time={}\n'.format(date, time))
    find = pattern_len_bicc.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]
        debug('\n length={}{},,,,data={}\n'.format(lenbyte1, lenbyte2, data))
        trimdata = getTextMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'BICC'
        formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, trimdata)
    return 0


def isup_handle(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER ISUP case,date={},Time={}\n'.format(date, time))
    find = pattern_len_isup.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]
        debug('\n length={}{},,,,data={}\n'.format(lenbyte1, lenbyte2, data))
        trimdata = getTextMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'ISUP'
        formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, trimdata)
    return 0


def alcap_Handle(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage):
    debug('\n ENTER ALCAP case,date={},Time={}'.format(date, time))
    find = pattern_len_data.search(thismessage)
    if find:
        lenbyte1, lenbyte2, data = find[1], find[2], find[3]

        trimdata = getTextMsuDataLen(lenbyte1, lenbyte2, data)
        protocol = 'ALCAP'
        formatItuEthCapfile(linenum, protocol, date, time, callingpc, calledpc, callingssn, calledssn, trimdata)
    return 0


def procMsgTraceMsg(thismessage, origMsg, linenum):
    outmsgprocessed = 0
    callingssn = 0
    calledssn = 0

    if 'Primitive: ' not in thismessage:
        debug('error, this message is not WCS promtive:{}'.format(thismessage))
        return 0

    # add case for SIP raw trace
    if re.search('Primitive:\s+CMNP_SIP_TRACE', thismessage):
        processTextMessage(linenum, origMsg)
        return 0

    #   Ignore  trace setting message
    if 'Cat:  CMNP' in thismessage:
        return 0


    if re.search('Dest:\s+SGW_MTP3_ID', thismessage):
        callingpc = defSetting['ownPc']
        calledpc = defSetting['ranPc']
        outmsgprocessed = 1
    elif re.search('Src:\s+SGW_MTP3_ID', thismessage):
        callingpc = defSetting['ranPc']
        calledpc = defSetting['ownPc']
    else:
        # non MTP3 message
        processTextMessage(linenum, origMsg)
        return 0

    # special handling for SCCP Connection-oriented message
#    pattern = re.compile(r'OamMtDecode.cc.* Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP_CONNECTION_DATA')
    find = pattern_sccp_con.search(thismessage)
    if find:
        date, time = find[1], find[2]
        sccp_Conn_Handler(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage, outmsgprocessed)
        return 0

#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP.*calling: pc=(\d+).*SSN=(\d+).*called: pc=(\d+).*SSN=(\d+).*SCCP_MSU')
    find = pattern_sccp_pcssn.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingssn, calledssn = int(find[4]), int(find[6])

        sccp_Connless_Handle1(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0

#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP.*calling: pc=(\d+).*SSN=(\d+).*called.*SSN=(\d+).*SCCP_MSU')
    find = pattern_sccp_ssn.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingssn, calledssn = int(find[4]), int(find[5])

        sccp_Connless_Handle2(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0

#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP.*calling.*SSN=(\d+).*called.*SSN=(\d+).*SCCP_MSU')
    find = pattern_sccp_2ssn.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingssn, calledssn = int(find[3]), int(find[4])

        sccp_Connless_Handle3(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0

#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*SCCP_.*SCCP_MSU')
    find = pattern_no_pcssn.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingssn = defSetting['Ssn']
        calledssn = defSetting['Ssn']
        sccp_Connless_Handle4(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0

#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*ISUP_DAT_.*OPC=(\d+) DPC=(\d+).*ISUP_MSU')
    find = pattern_bicc.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingpc, calledpc = find[3], find[4]
        callingssn = 0
        calledssn = 0
        bicc_handle(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0

#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*ISUP_DAT_.*OPC=(\d+) DPC=(\d+).*ISUP_MSU')
    find = pattern_isup.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingpc, calledpc = find[3], find[4]
        callingssn = 0
        calledssn = 0
        isup_handle(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0


#    pattern = re.compile(r'OamMtDecode.cc.*Time: (\d+/\d+/\d+) (\d+:\d+:\d+.\d+).*ALCAP_MSU')
    find = pattern_alcap.search(thismessage)
    if find:
        date, time = find[1], find[2]
        callingssn = 0
        calledssn = 0
        alcap_Handle(linenum, date, time, callingpc, calledpc, callingssn, calledssn, thismessage)
        return 0

    debug('bad luck, I am lost in your message:{}\n'.format(origMsg))
    return 0


def startWireShark():
    if os.name == 'nt':
        import subprocess
        if os.path.isfile(pcapfile):
            cmd = r'"C:\Program Files\Wireshark\Wireshark.exe" {}'.format(pcapfile)
            subprocess.Popen(cmd)
    #       ps.wait()
    else:
        print("Error, not supported in other OS")
    return 0


def procSynMsg(thismessage, linenum):
    import time
    currtime = time.strftime(r'%m/%d/%Y %H:%M:%S', time.localtime())
    find = re.search(r'virtual port #\d* -\s\s?(\d*:\d*:\d*.\d*)', thismessage)

    if find:
        time = find[1]
    else:
        time = currtime.split(' ')[1]
    date = currtime.split(' ')[0]

    find = re.search(r'.*MSU.*SIO=(\S+) SIF Length={}(({})+)'.format(hexdig, hexdig), thismessage)
    if find:
        data_r = find[1] + ' ' + find[2]
    else:
        return 0

    data_r = data_r.strip()
    debug('data_r={}\n'.format(data_r))
    findpc = re.search(r'((' + hexdig + '){3})((' + hexdig + '){3})((' + hexdig + ')+)', data_r)
    if findpc:
        tempdpc, tempopc = findpc[1].strip(), findpc[3].strip()
        dpc1, dpc2, dpc3 = tempdpc.split(' ')
        dpc = int(dpc1, 16) * 256 + int(dpc2, 16) * 16 + int(dpc3, 16)
        opc1, opc2, opc3 = tempopc.split(' ')
        opc = int(opc1, 16) * 256 + int(opc2, 16) * 16 + int(opc3, 16)
    else:
        return 0

    debug('DPC={}-----OPC={}\n'.format(dpc, opc))
    protocol = 'MTP3'
    formatSynEthCapfile(linenum, protocol, date, time, opc, dpc, data_r)

    return 0


def procMsgTraceFile(inputfile):
    linenum = 0
    thismessage = ""
    origmsg = ""
    # use to discard text before first message
    found_start = 0
    with open(inputfile, 'r', encoding='UTF-8', errors='ignore') as fp:
        for line in fp:
            linenum += 1
            temp = re.sub('^[0-9]+\t:', '', line, 1)
#            temp =line
            if 'OamMtDecode.cc' in temp:
                if found_start == 1:
                    if thismessage:
                        #   debug(thismessage)
                        procMsgTraceMsg(thismessage, origmsg, linenum)
                    thismessage = ""
                    origmsg = ""
                else:
                    found_start = 1

                origmsg = origmsg + temp
                tempmsg = temp.strip()
                thismessage = thismessage + ' ' + tempmsg
            else:
                origmsg = origmsg + temp
                tempmsg = temp.strip()
                thismessage = thismessage + ' ' + tempmsg
    #                print(origmsg)

    if found_start == 1 and thismessage:
        procMsgTraceMsg(thismessage, origmsg, linenum)

    debug('# total line processed : {}\n'.format(linenum))
    debug('# Total message processed : {}\n'.format(nummsgfound))


def procSynFile(inputfile):
    linenum = 0
    thismessage = ""
    # use to discard text before first message
    found_start = 0
    with open(inputfile, 'r', encoding='UTF-8', errors='ignore') as fp:
        for line in fp:
            linenum += 1
            line = line.strip()
            if line == '':
                continue
            if 'Rcv Channel' in line or 'Snd Channel' in line:
                if found_start == 1:
                    if thismessage:
                        debug(thismessage)
                        procSynMsg(thismessage, linenum)
                    thismessage = ""
                else:
                    found_start = 1
                thismessage = thismessage + ' ' + line
            else:
                find = re.search(r'.*MSU.*SIO=\S+ SIF\s*', line)
                if find:
                    thismessage = thismessage + ' ' + line + ' '

                find = re.search(r'(^({})+)'.format(hexdig), line)
                if find:
                    thismessage = thismessage + '' + find[1]

    if found_start == 1 and thismessage:
        procSynMsg(thismessage, linenum)

    debug('# total line processed : {}\n'.format(linenum))
    debug('# Total message processed : {}\n'.format(nummsgfound))


def generatePcap():
    global inputfile, outputfile, pcapfile, debugfile
    debug('will run text2pcap with outputfile={}; pcap file={}'.format(outputfile, pcapfile))
    if os.name == 'nt':
        import subprocess
        cmd = r'"C:\Program Files\Wireshark\text2pcap.exe" {} {} -q -t "%m/%d/%Y %T."'.format(outputfile, pcapfile)
        ps = subprocess.Popen(cmd)
        if ps.wait() == 0 and debugon == 0:
            os.remove(outputfile)

    else:
        print("Error, not supported in other OS")
    return 0


def usage():
    print('inputfile must be present, -d to turn on debug mode, -o to output to destination file\n')
    print('-t to set MSG or SYN,  -h for help\n')


def procMain():
    global inputfile, outputfile, pcapfile, debugfile, debugon
    import argparse
    if os.path.isfile(debugfile):
        os.remove(debugfile)

    # test mode will not check argv, just use file
    testmode = 0
    # default setting to MSG trace
    optSetting['type'] = 'MSG'
    if testmode == 1:
        inputfile = r'C:\Temp\3G TO 3G.abdisamad'
        filename = inputfile.split('\\')[-1]
        debugon = 1
    #   optSetting['type'] = 'SYN'
    else:
        parser = argparse.ArgumentParser(description='Ptherize')
        parser.add_argument('input', action='store', type=str, nargs='?', help='input filename')
        parser.add_argument('-o', action='store', type=str, default='', dest='out',
                            help='output file')
        parser.add_argument('-t', action='store', dest='type', help='message type:MSG/SYN', type=str)
        parser.add_argument('-d', action='store_true', default=False, dest='debug', help='debug mode')
        parser.add_argument('-version', action='version', version=' %(prog)s 1.0')

        results = vars(parser.parse_args(sys.argv[1:]))
        if results['input']:
            inputfile = results['input']
            filename = inputfile.split('\\')[-1]
        else:
            usage()
            sys.exit()
        if results['out']:
            debug('outfile={}\n'.format(results['out']))
            filename = results['out']
        if results['debug']:
            debugon = 1
        if results['type'] == 'MSG' or results['type'] == 'SYN':
            optSetting['type'] = results['type']

    debug('input file is :{}\n'.format(inputfile))
    tempfile = filename.replace(' ','')
    outputfile = r'C:\Temp\{}.txt'.format(tempfile)
    pcapfile = r'C:\Temp\{}.pcap'.format(tempfile)

    debug('outputfile is: {}\n'.format(outputfile))
    debug('pcap file is: {}\n'.format(pcapfile))

    if not os.path.isfile(inputfile):
        debug("Error, file doesn't exist")

    if os.path.isfile(outputfile):
        os.remove(outputfile)


    #    print(outputfile)
    if optSetting['type'] == 'MSG':
        procMsgTraceFile(inputfile)
    elif optSetting['type'] == 'SYN':
        procSynFile(inputfile)
    else:
        print('Error, not supported yet')

    generatePcap()
    startWireShark()


if __name__ == '__main__':
    procMain()