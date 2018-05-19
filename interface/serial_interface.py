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
import sys
from interface.types.interface import Interface
from util.serial_bsl_logging import SerialBSLLogger
from util.exception import SerialBSLException

logger = SerialBSLLogger.get_logger("serial-bsl." + __name__)

PY3 = sys.version_info >= (3, 0)

try:
    import serial
except ImportError:
    print('{} requires the Python serial library'.format(sys.argv[0]))
    print('Please install it with one of the following:')
    print('')
    if PY3:
        print('   Ubuntu:  sudo apt-get install python3-serial')
        print('   Mac:     sudo port install py34-serial')
    else:
        print('   Ubuntu:  sudo apt-get install python-serial')
        print('   Mac:     sudo port install py-serial')
    sys.exit(1)


class SerialInterface(Interface):
    """
    A class that implements communication with the device using the serial
    line (UART).

    This class uses pySerial and specifically the method serial_from_url().
    This means that other methods of communication can be achieved, for example
    over a socket. These methods have not been tested.

    Attributes:
        sp: A serial.Serial object, representation of the serial port to use
    """

    def __init__(self, port=None, baudrate=500000):
        """
        Try to create the SerialInterface using serial_for_url(), or fall back
        to the old serial.Serial() where serial_for_url() is not supported.
        serial_for_url() is a factory class and will return a different
        object based on the URL. For example serial_for_url("/dev/tty.<xyz>")
        will return a serialposix.Serial object.

        For that reason, we need to make sure the port doesn't get opened at
        this stage: We need to set its attributes up depending on what object
        we get.

        Parameters:
            port: A str with the serial port name (e.g. "/dev/ttyUSB0") or URL
            baudrate: A number with the desirable port speed
        """
        try:
            self.sp = serial.serial_for_url(port, do_not_open=True, timeout=10)
        except AttributeError:
            self.sp = serial.Serial(port=None, timeout=10)
            self.sp.port = port

        if isinstance(self.sp, serial.serialposix.Serial):
            self.sp.baudrate = baudrate          # baudrate
            self.sp.bytesize = 8                 # number of data bits
            self.sp.parity = serial.PARITY_NONE  # parity
            self.sp.stopbits = 1                 # stop bits
            self.sp.xonxoff = 0                  # s/w (XON/XOFF) flow control
            self.sp.rtscts = 0                   # h/w (RTS/CTS) flow control
            self.sp.timeout = 0.5                # set the timeout value

    def open(self):
        """
        Opens the port
        """
        self.sp.open()

    def close(self):
        """
        Closes the port
        """
        self.sp.close()

    def flush(self):
        """
        Clears the serial port's input buffers
        """
        self.sp.flushInput()

    def write(self, data, is_retry=False):
        """

        Parameters:
            data: A bytearray object with the data to be written
            is_retry: Retry sending if the first attempt fails
        """
        goal = len(data)
        written = self.sp.write(data)

        if written < goal:
            logger.debug("*** Only wrote {} of target {} bytes"
                         .format(written, goal))
            if is_retry and written == 0:
                raise SerialBSLException("Failed to write data on the serial "
                                         "bus")
            logger.debug("*** Retrying write for remainder")
            if type(data) == int:
                self.write(data, is_retry=True)
            else:
                self.write(data[written:], is_retry=True)

    def read(self, length):
        """
        Read length bytes from the serial port. This call is blocking or
        non-blocking depending on the value of self.sp.timeout

        Parameters:
            length: The number of bytes to read.

        Return:
            A bytearray object
        """
        return bytearray(self.sp.read(length))
