#!/usr/bin/env python

# Copyright (c) 2014, Jelmer Tiete <jelmer@tiete.be>.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The name of the author may not be used to endorse or promote
#    products derived from this software without specific prior
#    written permission.

# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Implementation based on stm32loader by Ivan A-R <ivan@tuxotronic.org>

# Serial boot loader over UART for CC13xx / CC2538 / CC26xx
# Based on the info found in TI's swru333a.pdf (spma029.pdf)
#
# Bootloader only starts if no valid image is found or if boot loader
# backdoor is enabled.
# Make sure you don't lock yourself out!! (enable backdoor in your firmware)
# More info at https://github.com/JelmerT/cc2538-bsl

from __future__ import print_function
from subprocess import Popen, PIPE

import sys
import getopt
import glob
import time
import struct
import traceback
import logging
from util.serial_bsl_logging import SerialBSLLogger
from util.exception import CmdException, ProtocolException, SerialBSLException
from util.firmware import FirmwareFile
from interface.serial_interface import SerialInterface

logger = SerialBSLLogger.get_logger("serial-bsl")

# version
VERSION_STRING = "2.1"

# Verbose level
QUIET = logging.INFO

# Check which version of Python is running
PY3 = sys.version_info >= (3, 0)

# Takes chip IDs (obtained via Get ID command) to human-readable names
CHIP_ID_STRS = {0xb964: 'CC2538',
                0xb965: 'CC2538'
                }


class Protocol(object):
    ACK_NACK_START_BYTE = 0x00
    ACK_BYTE = 0xCC
    NACK_BYTE = 0x33
    SYNCH_BYTE = 0x55

    def __init__(self, interface):
        self.interface = interface

    @staticmethod
    def _calc_checksum(command, data=bytearray(0)):
        return (command + sum(data)) & 0xFF

    def send_synch(self):
        cmd = Protocol.SYNCH_BYTE

        self.interface.flush()

        logger.debug("Sending synch sequence")

        self.interface.write(bytearray([cmd, cmd]))
        return self._wait_for_ack(Protocol.SYNCH_BYTE, 2)

    def _wait_for_ack(self, command, timeout=1):
        stop = time.time() + timeout
        got = bytearray(2)

        while (got[-2] != Protocol.ACK_NACK_START_BYTE or
               got[-1] not in (Protocol.ACK_BYTE, Protocol.NACK_BYTE)):

            got += self.interface.read(1)
            if time.time() > stop:
                raise ProtocolException("Timeout waiting for ACK/NACK after "
                                        "'0x%02x'" % (command,))

        # Our bytearray's length is: 2 initial bytes + 2 bytes for the ACK/NACK
        # plus a possible N-4 additional (buffered) bytes
        logger.debug("Got %d additional bytes before ACK/NACK"
                     % (len(got) - 4,))

        # The ACK/NACK byte is the last one in the bytearray
        ask = got[-1]

        if ask == Protocol.ACK_BYTE:
            return True
        elif ask == Protocol.NACK_BYTE:
            logger.debug("Target replied with a NACK during 0x%02x" % command)
            return False

        # Unknown response
        logger.debug("Unrecognised response 0x%x to 0x%02x" % (ask, command))
        return True

    def send_ack(self):
        self.interface.write(bytearray([Protocol.ACK_NACK_START_BYTE,
                                        Protocol.ACK_BYTE]))

    def send_nack(self):
        self.interface.write(bytearray([Protocol.ACK_NACK_START_BYTE,
                                        Protocol.NACK_BYTE]))

    def send_command(self, command, data=bytearray(0), verify=True,
                     timeout=1):
        check = self._calc_checksum(command, data)
        length = 3 + len(data)

        send_packet = bytearray((length, check, command,)) + data

        logger.debug("send_command 0x%02x, len=%i, check=0x%02x payload=[%s]"
                     % (command, length, check,
                        ' '.join('%02X' % x for x in send_packet[:12])))

        self.interface.write(send_packet)

        if verify:
            return self._wait_for_ack(command, timeout)

        return True

    def read_response(self):
        got = self.interface.read(2)

        size = got[0]
        chks = got[1]
        data = bytearray(self.interface.read(size - 2))

        logger.debug("Received 0x%02x bytes" % size)
        if chks == sum(data) & 0xFF:
            self.send_ack()
            return data
        else:
            self.send_nack()
            # TODO: retry receiving!
            raise ProtocolException("Received packet checksum error")


class CommandInterface(object):
    COMMAND_RET_SUCCESS = 0x40
    COMMAND_RET_UNKNOWN_CMD = 0x41
    COMMAND_RET_INVALID_CMD = 0x42
    COMMAND_RET_INVALID_ADR = 0x43
    COMMAND_RET_FLASH_FAIL = 0x44

    RETURN_CMD_STRS = {COMMAND_RET_SUCCESS: 'Success',
                       COMMAND_RET_UNKNOWN_CMD: 'Unknown command',
                       COMMAND_RET_INVALID_CMD: 'Invalid command',
                       COMMAND_RET_INVALID_ADR: 'Invalid address',
                       COMMAND_RET_FLASH_FAIL: 'Flash fail'}

    def __init__(self, protocol):
        self.protocol = protocol

    def _encode_four_bytes(self, addr):
        byte3 = (addr >> 0) & 0xFF
        byte2 = (addr >> 8) & 0xFF
        byte1 = (addr >> 16) & 0xFF
        byte0 = (addr >> 24) & 0xFF

        return bytearray([byte0, byte1, byte2, byte3])

    def _decode_four_bytes(self, byte_seq):
        return ((byte_seq[0] << 24) | (byte_seq[1] << 16) |
                (byte_seq[2] << 8) | (byte_seq[3] << 0))

    def checkLastCmd(self):
        stat = self.cmdGetStatus()
        if not stat:
            raise CmdException("No response from target on status request. "
                               "(Did you disable the bootloader?)")

        if stat[0] == CommandInterface.COMMAND_RET_SUCCESS:
            logger.debug("Command Successful")
            return 1
        else:
            stat_str = CommandInterface.RETURN_CMD_STRS.get(stat[0], None)
            if stat_str is None:
                logger.warning("Unrecognized status returned 0x%x" % stat[0])
            else:
                logger.warning("Target returned: 0x%x, %s"
                               % (stat[0], stat_str))
            return 0

    def cmdPing(self):
        cmd = 0x20

        logger.debug("*** Ping command (0x20)")

        if self.protocol.send_command(cmd):
            return self.checkLastCmd()

        return False

    def cmdReset(self):
        cmd = 0x25

        logger.debug("*** Reset command (0x25)")

        return self.protocol.send_command(cmd)

    def cmdGetChipId(self):
        cmd = 0x28

        logger.debug("*** GetChipId command (0x28)")

        if self.protocol.send_command(cmd):
            # 4 byte answ, the 2 LSB hold chip ID
            version = self.protocol.read_response()
            if self.checkLastCmd():
                assert len(version) == 4, ("Unreasonable chip "
                                           "id: %s" % repr(version))
                logger.debug("    Version 0x%02X%02X%02X%02X" % tuple(version))
                chip_id = (version[2] << 8) | version[3]
                return chip_id
            else:
                raise CmdException("GetChipID (0x28) failed")

    def cmdGetStatus(self):
        cmd = 0x23

        logger.debug("*** GetStatus command (0x23)")

        if self.protocol.send_command(cmd):
            return self.protocol.read_response()

    def cmdSetXOsc(self):
        cmd = 0x29

        logger.debug("*** SetXOsc command (0x29)")

        return self.protocol.send_command(cmd)

    def cmdRun(self, addr):
        cmd = 0x22

        logger.debug("*** Run command(0x22)")

        self.protocol.send_command(cmd, data=self._encode_four_bytes(addr),
                                   verify=False)

        return 1

    def cmdEraseMemory(self, addr, size):
        cmd = 0x26

        logger.debug("*** Erase command(0x26)")

        # Addition of bytearrays will give us a new bytearray
        payload = self._encode_four_bytes(addr) + self._encode_four_bytes(size)

        if self.protocol.send_command(cmd, data=payload, timeout=10):
            return self.checkLastCmd()

    def cmdBankErase(self):
        cmd = 0x2C

        logger.debug("*** Bank Erase command(0x2C)")

        if self.protocol.send_command(cmd, timeout=10):
            return self.checkLastCmd()

        return False

    def cmd_crc_wrapper(self, addr, size, read_attempts=bytearray(0)):
        cmd = 0x27

        logger.debug("*** CRC32 command(0x27)")

        # Addition of bytearrays will give us a new bytearray
        payload = (self._encode_four_bytes(addr) + self._encode_four_bytes(size)
                   + read_attempts)

        if self.protocol.send_command(cmd, data=payload, timeout=2):
            crc = self.protocol.read_response()
            if self.checkLastCmd():
                return self._decode_four_bytes(crc)

    def cmdCRC32(self, addr, size):
        return self.cmd_crc_wrapper(addr, size)

    def cmdCRC32CC26xx(self, addr, size):
        read_attemts = self._encode_four_bytes(0x00000000)
        return self.cmd_crc_wrapper(addr, size, read_attemts)

    def cmdDownload(self, addr, size):
        cmd = 0x21

        logger.debug("*** Download command (0x21)")

        if (size % 4) != 0:  # check for invalid data lengths
            raise CmdException('Invalid data size: %i. '
                               'Size must be a multiple of 4.' % size)

        # Addition of bytearrays will give us a new bytearray
        payload = self._encode_four_bytes(addr) + self._encode_four_bytes(size)

        if self.protocol.send_command(cmd, data=payload, timeout=5):
            return self.checkLastCmd()

    def cmdSendData(self, data):
        cmd = 0x24

        logger.debug("*** Send Data (0x24)")

        payload = bytearray(data)
        payload_len = len(payload)

        if payload_len > 252:
            raise CmdException('Max data size exceeded. Size was %i'
                               % payload_len)

        if self.protocol.send_command(cmd, data=payload, timeout=10):
            return self.checkLastCmd()

    def cmd_mem_read_wrapper(self, addr, width, read_attempts=bytearray(0)):
        cmd = 0x2A

        logger.debug("*** Mem Read (0x2A), addr=0x%08x, width=%i"
                     % (addr, width))

        # Addition of bytearrays will give us a new bytearray
        payload = (self._encode_four_bytes(addr) + bytearray((width,))
                   + read_attempts)

        if self.protocol.send_command(cmd, data=payload):
            response = self.protocol.read_response()
            if self.checkLastCmd():
                return response

    def cmdMemRead(self, addr):
        return self.cmd_mem_read_wrapper(addr, 4)

    def cmdMemReadCC26xx(self, addr):
        return self.cmd_mem_read_wrapper(addr, 1, bytearray((1,)))

    def cmdMemWrite(self, addr, data, width):  # untested
        cmd = 0x2B

        logger.debug("*** Mem write (0x2B)")

        if width not in (1, 4):
            raise CmdException("cmdMemWrite error")

        payload = (self._encode_four_bytes(addr) + bytearray(data) +
                   bytearray((width,)))

        if self.protocol.send_command(cmd, data=payload, timeout=2):
            return self.checkLastCmd()

# Complex commands section

    def writeMemory(self, addr, data):
        lng = len(data)
        # amount of data bytes transferred per packet (theory: max 252 + 3)
        trsf_size = 248
        empty_packet = bytearray((0xFF,) * trsf_size)

        # Boot loader enable check
        # TODO: implement check for all chip sizes & take into account partial
        # firmware uploads
        if (lng == 524288):  # check if file is for 512K model
            # check the boot loader enable bit  (only for 512K model)
            if not ((data[524247] & (1 << 4)) >> 4):
                if not (conf['force'] or
                        query_yes_no("The boot loader backdoor is not enabled "
                                     "in the firmware you are about to write "
                                     "to the target. You will NOT be able to "
                                     "reprogram the target using this tool if "
                                     "you continue! "
                                     "Do you want to continue?", "no")):
                    raise Exception('Aborted by user.')

        logger.info("Writing %(lng)d bytes starting at address 0x%(addr)08X"
                    % {'lng': lng, 'addr': addr})

        offs = 0
        addr_set = 0

        # check if amount of remaining data is less then packet size
        while lng > trsf_size:
            # skip packets filled with 0xFF
            if data[offs:offs+trsf_size] != empty_packet:
                if addr_set != 1:
                    # set starting address if not set
                    self.cmdDownload(addr, lng)
                    addr_set = 1
                SerialBSLLogger.console_handler.terminator = '\r'
                logger.info("Write %(len)d bytes at 0x%(addr)08X\r"
                            % {'addr': addr, 'len': trsf_size})
                SerialBSLLogger.console_handler.terminator = '\n'
                sys.stdout.flush()

                # send next data packet
                self.cmdSendData(data[offs:offs+trsf_size])
            else:   # skipped packet, address needs to be set
                addr_set = 0

            offs = offs + trsf_size
            addr = addr + trsf_size
            lng = lng - trsf_size

        logger.info("Write %(len)d bytes at 0x%(addr)08X"
                    % {'addr': addr, 'len': lng})
        self.cmdDownload(addr, lng)
        return self.cmdSendData(data[offs:offs+lng])  # send last data packet


class Chip(object):
    def __init__(self, phy_if):
        # Some defaults. The child can override.
        self.flash_start_addr = 0x00000000
        self.has_cmd_set_xosc = False

        self.phy_if = phy_if
        self.protocol = Protocol(phy_if)
        self.cmd_if = CommandInterface(self.protocol)

    def invoke_bootloader(self, bsl_active_high=False, inverted=False):
        """
        Use the RTS and CTS (DTR) lines to force the device into bootloader mode

        This assumes that:
          * One of the two lines is connected to the Chip's !RESET line
          * The second line is connected the bootloader (BSL) pin


        Parameters:
            bsl_active_high:
                True: Chip enters bootloader mode is pin is high on reset
                False: Chip enters bootloader mode is pin is low on reset
            inverted:
                False:
                    * RTS connected to !RESET
                    * DTR connected to BSL
                True:
                    * RTS connected to BSL
                    * DTR connected to !RESET
        """
        if inverted:
            set_bootloader_pin = self.phy_if.sp.setRTS
            set_reset_pin = self.phy_if.sp.setDTR
        else:
            set_bootloader_pin = self.phy_if.sp.setDTR
            set_reset_pin = self.phy_if.sp.setRTS

        set_bootloader_pin(1 if bsl_active_high else 0)
        set_reset_pin(0)
        set_reset_pin(1)
        set_reset_pin(0)
        time.sleep(0.002)
        set_bootloader_pin(0 if bsl_active_high else 1)

        # Some boards have a co-processor that detects this sequence here and
        # then drives the main chip's BSL enable and !RESET pins. Depending on
        # board design and co-processor behaviour, the !RESET pin may get
        # asserted after we have finished the sequence here. In this case, we
        # need a small delay so as to avoid trying to talk to main chip before
        # it has actually entered its bootloader mode.
        #
        # See contiki-os/contiki#1533
        time.sleep(0.1)

    def open(self, force_bsl=False):
        logger.info("Connecting to target device...")
        self.phy_if.open()

        if force_bsl:
            self.invoke_bootloader()

        if type(self.phy_if) is SerialInterface:
            try:
                self.protocol.send_synch()
                return self.cmd_if.cmdPing()
            except ProtocolException as e:
                logger.error(e)
                raise SerialBSLException("Device did not respond to the synch. "
                                         "Ensure boot loader is started.")
        return True

    def close(self):
        logger.info("Closing target device...")
        self.phy_if.close()

    def crc(self, address, size):
        return getattr(self.command_interface, self.crc_cmd)(address, size)

    def disable_bootloader(self):
        if not (conf['force'] or
                query_yes_no("Disabling the bootloader will prevent you from "
                             "using this script until you re-enable the "
                             "bootloader using JTAG. Do you want to continue?",
                             "no")):
            raise Exception('Aborted by user.')

        if PY3:
            pattern = struct.pack('<L', self.bootloader_dis_val)
        else:
            pattern = [ord(b) for b in struct.pack('<L',
                                                   self.bootloader_dis_val)]

        if cmd.writeMemory(self.bootloader_address, pattern):
            logger.info("    Set bootloader closed done                      ")
        else:
            raise CmdException("Set bootloader closed failed             ")


class CC2538(Chip):
    def __init__(self, phy_if):
        super(CC2538, self).__init__(phy_if)
        self.flash_start_addr = 0x00200000
        self.addr_ieee_address_secondary = 0x0027ffcc
        self.has_cmd_set_xosc = True
        self.bootloader_dis_val = 0xefffffff
        self.crc_cmd = "cmdCRC32"

        FLASH_CTRL_DIECFG0 = 0x400D3014
        FLASH_CTRL_DIECFG2 = 0x400D301C
        addr_ieee_address_primary = 0x00280028
        ccfg_len = 44

        # Read out primary IEEE address, flash and RAM size
        model = self.command_interface.cmdMemRead(FLASH_CTRL_DIECFG0)
        self.size = (model[3] & 0x70) >> 4
        if 0 < self.size <= 4:
            self.size *= 0x20000  # in bytes
        else:
            self.size = 0x10000  # in bytes
        self.bootloader_address = self.flash_start_addr + self.size - ccfg_len

        sram = (((model[2] << 8) | model[3]) & 0x380) >> 7
        sram = (2 - sram) << 3 if sram <= 1 else 32  # in KB

        pg = self.command_interface.cmdMemRead(FLASH_CTRL_DIECFG2)
        pg_major = (pg[2] & 0xF0) >> 4
        if pg_major == 0:
            pg_major = 1
        pg_minor = pg[2] & 0x0F

        ti_oui = bytearray([0x00, 0x12, 0x4B])
        ieee_addr = self.command_interface.cmdMemRead(
                                            addr_ieee_address_primary)
        ieee_addr_end = self.command_interface.cmdMemRead(
                                            addr_ieee_address_primary + 4)
        if ieee_addr[:3] == ti_oui:
            ieee_addr += ieee_addr_end
        else:
            ieee_addr = ieee_addr_end + ieee_addr

        logger.info("CC2538 PG%d.%d: %dKB Flash, %dKB SRAM, CCFG at 0x%08X"
               % (pg_major, pg_minor, self.size >> 10, sram,
                  self.bootloader_address))
        logger.info("Primary IEEE Address: %s"
               % (':'.join('%02X' % x for x in ieee_addr)))

    def erase(self):
        logger.info("Erasing %s bytes starting at address 0x%08X"
               % (self.size, self.flash_start_addr))
        return self.command_interface.cmdEraseMemory(self.flash_start_addr,
                                                     self.size)

    def read_memory(self, addr):
        # CC2538's COMMAND_MEMORY_READ sends each 4-byte number in inverted
        # byte order compared to what's written on the device
        data = self.command_interface.cmdMemRead(addr)
        return bytearray([data[x] for x in range(3, -1, -1)])


class CC26xx(Chip):
    # Class constants
    MISC_CONF_1 = 0x500010A0
    PROTO_MASK_BLE = 0x01
    PROTO_MASK_IEEE = 0x04
    PROTO_MASK_BOTH = 0x05

    def __init__(self, phy_if):
        super(CC26xx, self).__init__(phy_if)
        self.bootloader_dis_val = 0x00000000
        self.crc_cmd = "cmdCRC32CC26xx"

        ICEPICK_DEVICE_ID = 0x50001318
        FCFG_USER_ID = 0x50001294
        PRCM_RAMHWOPT = 0x40082250
        FLASH_SIZE = 0x4003002C
        addr_ieee_address_primary = 0x500012F0
        ccfg_len = 88
        ieee_address_secondary_offset = 0x20
        bootloader_dis_offset = 0x30
        sram = "Unknown"

        # Determine CC13xx vs CC26xx via ICEPICK_DEVICE_ID::WAFER_ID and store
        # PG revision
        device_id = self.command_interface.cmdMemReadCC26xx(ICEPICK_DEVICE_ID)
        wafer_id = (((device_id[3] & 0x0F) << 16) +
                    (device_id[2] << 8) +
                    (device_id[1] & 0xF0)) >> 4
        pg_rev = (device_id[3] & 0xF0) >> 4

        # Read FCFG1_USER_ID to get the package and supported protocols
        user_id = self.command_interface.cmdMemReadCC26xx(FCFG_USER_ID)
        package = {0x00: '4x4mm',
                   0x01: '5x5mm',
                   0x02: '7x7mm'}.get(user_id[2] & 0x03, "Unknown")
        protocols = user_id[1] >> 4

        # We can now detect the exact device
        if wafer_id == 0xB99A:
            chip = self._identify_cc26xx(pg_rev, protocols)
        elif wafer_id == 0xB9BE:
            chip = self._identify_cc13xx(pg_rev, protocols)

        # Read flash size, calculate and store bootloader disable address
        self.size = self.command_interface.cmdMemReadCC26xx(
                                                FLASH_SIZE)[0] * 4096
        self.bootloader_address = self.size - ccfg_len + bootloader_dis_offset
        self.addr_ieee_address_secondary = (self.size - ccfg_len +
                                            ieee_address_secondary_offset)

        # RAM size
        ramhwopt_size = self.command_interface.cmdMemReadCC26xx(
                                                PRCM_RAMHWOPT)[0] & 3
        if ramhwopt_size == 3:
            sram = "20KB"
        elif ramhwopt_size == 2:
            sram = "16KB"
        else:
            sram = "Unknown"

        # Primary IEEE address. Stored with the MSB at the high address
        ieee_addr = self.command_interface.cmdMemReadCC26xx(
                                        addr_ieee_address_primary + 4)[::-1]
        ieee_addr += self.command_interface.cmdMemReadCC26xx(
                                        addr_ieee_address_primary)[::-1]

        logger.info("%s (%s): %dKB Flash, %s SRAM, CCFG.BL_CONFIG at 0x%08X"
               % (chip, package, self.size >> 10, sram,
                  self.bootloader_address))
        logger.info("Primary IEEE Address: %s"
               % (':'.join('%02X' % x for x in ieee_addr)))

    def _identify_cc26xx(self, pg, protocols):
        chips_dict = {
            CC26xx.PROTO_MASK_IEEE: 'CC2630',
            CC26xx.PROTO_MASK_BLE: 'CC2640',
            CC26xx.PROTO_MASK_BOTH: 'CC2650',
        }

        chip_str = chips_dict.get(protocols & CC26xx.PROTO_MASK_BOTH, "Unknown")

        if pg == 1:
            pg_str = "PG1.0"
        elif pg == 3:
            pg_str = "PG2.0"
        elif pg == 7:
            pg_str = "PG2.1"
        elif pg == 8 or pg == 11:
            rev_minor = self.command_interface.cmdMemReadCC26xx(
                                                CC26xx.MISC_CONF_1)[0]
            if rev_minor == 0xFF:
                rev_minor = 0x00
            pg_str = "PG2.%d" % (2 + rev_minor,)

        return "%s %s" % (chip_str, pg_str)

    def _identify_cc13xx(self, pg, protocols):
        chip_str = "CC1310"
        if protocols & CC26xx.PROTO_MASK_IEEE == CC26xx.PROTO_MASK_IEEE:
            chip_str = "CC1350"

        if pg == 0:
            pg_str = "PG1.0"
        elif pg == 2:
            rev_minor = self.command_interface.cmdMemReadCC26xx(
                                                CC26xx.MISC_CONF_1)[0]
            if rev_minor == 0xFF:
                rev_minor = 0x00
            pg_str = "PG2.%d" % (rev_minor,)

        return "%s %s" % (chip_str, pg_str)

    def erase(self):
        logger.info("Erasing all main bank flash sectors")
        return self.command_interface.cmdBankErase()

    def read_memory(self, addr):
        # CC26xx COMMAND_MEMORY_READ returns contents in the same order as
        # they are stored on the device
        return self.command_interface.cmdMemReadCC26xx(addr)


def query_yes_no(question, default="yes"):
    valid = {"yes": True,
             "y": True,
             "ye": True,
             "no": False,
             "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        if PY3:
            choice = input().lower()
        else:
            choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


# Convert the entered IEEE address into an integer
def parse_ieee_address(inaddr):
    try:
        return int(inaddr, 16)
    except ValueError:
        # inaddr is not a hex string, look for other formats
        if ':' in inaddr:
            bytes = inaddr.split(':')
        elif '-' in inaddr:
            bytes = inaddr.split('-')
        if len(bytes) != 8:
            raise ValueError("Supplied IEEE address does not contain 8 bytes")
        addr = 0
        for i, b in zip(range(8), bytes):
            try:
                addr += int(b, 16) << (56-(i*8))
            except ValueError:
                raise ValueError("IEEE address contains invalid bytes")
        return addr


def print_version():
    # Get the version using "git describe".
    try:
        p = Popen(['git', 'describe', '--tags', '--match', '[0-9]*'],
                  stdout=PIPE, stderr=PIPE)
        p.stderr.close()
        line = p.stdout.readlines()[0]
        version = line.strip()
    except:
        # We're not in a git repo, or git failed, use fixed version string.
        version = VERSION_STRING
    print('%s %s' % (sys.argv[0], version))


def usage():
    print("""Usage: %s [-DhqVfewvr] [-l length] [-p port] [-b baud] [-a addr] \
    [-i addr] [--bootloader-active-high] [--bootloader-invert-lines] [file.bin]
    -h, --help               This help
    -q                       Quiet
    -V                       Verbose
    -f                       Force operation(s) without asking any questions
    -e                       Erase (full)
    -w                       Write
    -v                       Verify (CRC32 check)
    -r                       Read
    -l length                Length of read
    -p port                  Serial port (default: first USB-like port in /dev)
    -b baud                  Baud speed (default: 500000)
    -a addr                  Target address
    -i, --ieee-address addr  Set the secondary 64 bit IEEE address
    --bootloader-active-high Use active high signals to enter bootloader
    --bootloader-invert-lines Inverts the use of RTS and DTR to enter bootloader
    -D, --disable-bootloader After finishing, disable the bootloader
    --version                Print script version

Examples:
    ./%s -e -w -v example/main.bin
    ./%s -e -w -v --ieee-address 00:12:4b:aa:bb:cc:dd:ee example/main.bin

    """ % (sys.argv[0], sys.argv[0], sys.argv[0]))

if __name__ == "__main__":

    conf = {
            'port': 'auto',
            'baud': 500000,
            'force_speed': 0,
            'address': None,
            'force': 0,
            'erase': 0,
            'write': 0,
            'verify': 0,
            'read': 0,
            'len': 0x80000,
            'fname': '',
            'ieee_address': 0,
            'bootloader_active_high': False,
            'bootloader_invert_lines': False,
            'disable-bootloader': 0
        }

# http://www.python.org/doc/2.5.2/lib/module-getopt.html

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                                   "DhqVfewvrp:b:a:l:i:",
                                   ['help', 'ieee-address=',
                                    'disable-bootloader',
                                    'bootloader-active-high',
                                    'bootloader-invert-lines', 'version'])
    except getopt.GetoptError as err:
        # print help information and exit:
        print(str(err))  # will print something like "option -a not recognized"
        usage()
        sys.exit(2)

    for o, a in opts:
        if o == '-V':
            QUIET = logging.DEBUG
        elif o == '-q':
            QUIET = logging.ERROR
        elif o == '-h' or o == '--help':
            usage()
            sys.exit(0)
        elif o == '-f':
            conf['force'] = 1
        elif o == '-e':
            conf['erase'] = 1
        elif o == '-w':
            conf['write'] = 1
        elif o == '-v':
            conf['verify'] = 1
        elif o == '-r':
            conf['read'] = 1
        elif o == '-p':
            conf['port'] = a
        elif o == '-b':
            conf['baud'] = eval(a)
            conf['force_speed'] = 1
        elif o == '-a':
            conf['address'] = eval(a)
        elif o == '-l':
            conf['len'] = eval(a)
        elif o == '-i' or o == '--ieee-address':
            conf['ieee_address'] = str(a)
        elif o == '--bootloader-active-high':
            conf['bootloader_active_high'] = True
        elif o == '--bootloader-invert-lines':
            conf['bootloader_invert_lines'] = True
        elif o == '-D' or o == '--disable-bootloader':
            conf['disable-bootloader'] = 1
        elif o == '--version':
            print_version()
            sys.exit(0)
        else:
            assert False, "Unhandled option"

    SerialBSLLogger.setup(QUIET)

    try:
        # Sanity checks
        # check for input/output file
        if conf['write'] or conf['read'] or conf['verify']:
            try:
                args[0]
            except:
                raise Exception('No file path given.')

        if conf['write'] and conf['read']:
            if not (conf['force'] or
                    query_yes_no("You are reading and writing to the same "
                                 "file. This will overwrite your input file. "
                                 "Do you want to continue?", "no")):
                raise Exception('Aborted by user.')
        if conf['erase'] and conf['read'] and not conf['write']:
            if not (conf['force'] or
                    query_yes_no("You are about to erase your target before "
                                 "reading. Do you want to continue?", "no")):
                raise Exception('Aborted by user.')

        if conf['read'] and not conf['write'] and conf['verify']:
            raise Exception('Verify after read not implemented.')

        if conf['len'] < 0:
            raise Exception('Length must be positive but %d was provided'
                            % (conf['len'],))

        # Try and find the port automatically
        if conf['port'] == 'auto':
            ports = []

            # Get a list of all USB-like names in /dev
            for name in ['ttyACM',
                         'tty.usbserial',
                         'ttyUSB',
                         'tty.usbmodem',
                         'tty.SLAB_USBtoUART']:
                ports.extend(glob.glob('/dev/%s*' % name))

            ports = sorted(ports)

            if ports:
                # Found something - take it
                conf['port'] = ports[0]
            else:
                raise Exception('No serial port found.')

        if conf['write'] or conf['verify']:
            logger.info("Reading data from %s" % args[0])
            firmware = FirmwareFile.factory(args[0])

        logger.info("Setting up port %(port)s, baud %(baud)d"
                    % {'port': conf['port'], 'baud': conf['baud']})
        physical_interface = SerialInterface(conf['port'], conf['baud'])

        device=Chip(physical_interface)
        device.open(force_bsl=True)

        device.close()


        chip_id = cmd.cmdGetChipId()
        chip_id_str = CHIP_ID_STRS.get(chip_id, None)

        if chip_id_str is None:
            logger.debug('    Unrecognized chip ID. Trying CC13xx/CC26xx')
            device = CC26xx(cmd)
        else:
            logger.debug("    Target id 0x%x, %s" % (chip_id, chip_id_str))
            device = CC2538(cmd)

        # Choose a good default address unless the user specified -a
        if conf['address'] is None:
            conf['address'] = device.flash_start_addr

        if conf['force_speed'] != 1 and device.has_cmd_set_xosc:
            if cmd.cmdSetXOsc():  # switch to external clock source
                serial_interface.close()
                conf['baud'] = 1000000
                serial_interface.sp.baudrate = conf['baud']
                logger.info("Opening port %(port)s, baud %(baud)d"
                       % {'port': conf['port'], 'baud': conf['baud']})
                serial_interface.open()
                logger.info("Reconnecting to target at higher speed...")
                if (cmd.sendSynch() != 1):
                    raise CmdException("Can't connect to target after clock "
                                       "source switch. (Check external "
                                       "crystal)")
            else:
                raise CmdException("Can't switch target to external clock "
                                   "source. (Try forcing speed)")

        if conf['erase']:
            # we only do full erase for now
            if device.erase():
                logger.info("    Erase done")
            else:
                raise CmdException("Erase failed")

        if conf['write']:
            # TODO: check if boot loader back-door is open, need to read
            #       flash size first to get address
            if cmd.writeMemory(conf['address'], firmware.bytes):
                logger.info("    Write done                                ")
            else:
                raise CmdException("Write failed                       ")

        if conf['verify']:
            logger.info("Verifying by comparing CRC32 calculations.")

            crc_local = firmware.crc32()
            # CRC of target will change according to length input file
            crc_target = device.crc(conf['address'], len(firmware.bytes))

            if crc_local == crc_target:
                logger.info("    Verified (match: 0x%08x)" % crc_local)
            else:
                cmd.cmdReset()
                raise Exception("NO CRC32 match: Local = 0x%x, "
                                "Target = 0x%x" % (crc_local, crc_target))

        if conf['ieee_address'] != 0:
            ieee_addr = parse_ieee_address(conf['ieee_address'])
            if PY3:
                logger.info("Setting IEEE address to %s"
                       % (':'.join(['%02x' % b
                                    for b in struct.pack('>Q', ieee_addr)])))
                ieee_addr_bytes = struct.pack('<Q', ieee_addr)
            else:
                logger.info("Setting IEEE address to %s"
                       % (':'.join(['%02x' % ord(b)
                                    for b in struct.pack('>Q', ieee_addr)])))
                ieee_addr_bytes = [ord(b)
                                   for b in struct.pack('<Q', ieee_addr)]

            if cmd.writeMemory(device.addr_ieee_address_secondary,
                               ieee_addr_bytes):
                logger.info("    "
                          "Set address done                                ")
            else:
                raise CmdException("Set address failed                       ")

        if conf['read']:
            length = conf['len']

            # Round up to a 4-byte boundary
            length = (length + 3) & ~0x03

            logger.info("Reading %s bytes starting at address 0x%x"
                   % (length, conf['address']))
            with open(args[0], 'wb') as f:
                for i in range(0, length >> 2):
                    # reading 4 bytes at a time
                    rdata = device.read_memory(conf['address'] + (i * 4))
                    logger.info(" 0x%x: 0x%02x%02x%02x%02x"
                           % (conf['address'] + (i * 4), rdata[0], rdata[1],
                              rdata[2], rdata[3]), '\r')
                    f.write(rdata)
                f.close()
            logger.info("    Read done                                ")

        if conf['disable-bootloader']:
            device.disable_bootloader()

        cmd.cmdReset()

    except Exception as err:
        logger.debug(traceback.format_exc())
        exit('ERROR: %s' % str(err))
