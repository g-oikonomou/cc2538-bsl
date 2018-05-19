# Copyright (c) 2014, Jelmer Tiete <jelmer@tiete.be>.
# Copyright (c) 2018, University of Bristol <www.bristol.ac.uk>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the copyright holder nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
import os
import binascii
from util.serial_bsl_logging import SerialBSLLogger
from util.exception import SerialBSLException

logger = SerialBSLLogger.get_logger("serial-bsl." + __name__)

try:
    from intelhex import IntelHex
    have_hex_support = True
except ImportError:
    have_hex_support = False

try:
    import magic
    magic.from_file
    have_magic = True
except (ImportError, AttributeError):
    have_magic = False


class FirmwareException(SerialBSLException):
    pass


class FirmwareFile(object):
    @staticmethod
    def factory(path):
        """
        Factory method that returns an object of the correct child class of
        the FirmwareFile class

        Parameters:
            path: A str with the path to the firmware file.

        Return:
            An object of type FirmwareBin or of type FirmwareHex
        """
        hex_file_extensions = ('hex', 'ihx', 'ihex')
        firmware_is_hex = False

        if have_magic:
            file_type = bytearray(magic.from_file(path, True))

            # from_file() returns bytes with PY3, str with PY2. This comparison
            # will be True in both cases"""
            if file_type == b'text/plain':
                firmware_is_hex = True
                logger.info("Firmware file: Intel Hex")
            elif file_type == b'application/octet-stream':
                logger.info("Firmware file: Raw Binary")
            else:
                error_str = "Could not determine firmware type. Magic " \
                            "indicates '%s'" % (file_type,)
                raise FirmwareException(error_str)
        else:
            if os.path.splitext(path)[1][1:] in hex_file_extensions:
                firmware_is_hex = True
                logger.info("Firmware looks like an Intel Hex file")
            else:
                logger.info("Cannot auto-detect firmware filetype: "
                            "Assuming .bin")

            logger.debug("For more solid firmware type auto-detection, "
                         "install python-magic.")
            logger.debug("Please see the readme for more details.")

        if firmware_is_hex:
            return FirmwareHex(path)

        return FirmwareBin(path)

    def __init__(self):
        """
        Read a firmware file and store its data ready for device programming.

        This class will try to guess the file type if python-magic is available.

        If python-magic indicates a plain text file, and if IntelHex is
        available, then the file will be treated as one of Intel HEX format.

        In all other cases, the file will be treated as a raw binary file.

        In both cases, the file's contents are stored in bytes for subsequent
        usage to program a device or to perform a crc check.
        """
        self._crc32 = None

    def crc32(self):
        """
        Return the crc32 checksum of the firmware image

        Return:
            The firmware's CRC32, ready for comparison with the CRC
            returned by the ROM bootloader's COMMAND_CRC32
        """
        if self._crc32 is None:
            self._crc32 = binascii.crc32(bytearray(self.bytes)) & 0xffffffff

        return self._crc32


class FirmwareHex(FirmwareFile):
    def __init__(self, path):
        """
        Read a firmware file in hex format and store its data ready for device
        programming.

        Parameters:
            path: A str with the path to the firmware file.

        Attributes:
            bytes: A bytearray with firmware contents ready to send to the
            device
        """
        self.bytes = bytearray(IntelHex(path).tobinarray())
        super(FirmwareHex, self).__init__()


class FirmwareBin(FirmwareFile):
    def __init__(self, path):
        """
        Read a firmware file in binary format and store its data ready for
        device programming.

        Parameters:
            path: A str with the path to the firmware file.

        Attributes:
            bytes: A bytearray with firmware contents ready to send to the
            device
        """
        with open(path, 'rb') as f:
            self.bytes = bytearray(f.read())
        super(FirmwareBin, self).__init__()
