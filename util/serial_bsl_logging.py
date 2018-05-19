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
import logging


class SerialBSLLogger(object):
    """A wrapper to the logging.Logger class. New versions of the logging
    module allow us to change the line terminator. Old ones do not. This
    wrapper allows us to change line terminators (e.g. from '\n' to '\r'
    irrespective of logging version in use.
    """
    console_handler = None

    class StdOutHandler(logging.StreamHandler):
        """A handler that overrides old versions of the StreamHandler, which was
        using '\n' as a hard-coded line terminator. StdOutHandler allows us to
        use different terminators, in a fashion similar to newer versions of the
        logging module."""
        terminator = '\n'

        @staticmethod
        def factory():
            """Factory method that simply returns a StreamHandler object if the
            version of logging allows us to override StreamHandler's terminator.
            If the class does not have this attribute, we instead instantiate
            StdOutHandler"""
            try:
                logging.StreamHandler.terminator
                return logging.StreamHandler()
            except AttributeError:
                return SerialBSLLogger.StdOutHandler()

        def emit(self, record):
            """Emits a log record"""
            try:
                msg = self.format(record)
                stream = self.stream
                stream.write(msg)
                stream.write(self.terminator)
                self.flush()
            except Exception:
                self.handleError(record)

    @staticmethod
    def get_logger(name=None):
        """A method to be used to instantiate all module-level loggers.
        Typically you will do something like

        logger = SerialBSLLogger.get_logger("serial-bsl." + __name__)
        """
        return logging.getLogger(name)

    @classmethod
    def setup(cls, level):
        """Initialises the serial-bsl logging wrapper
        :type level: logging.INFO logging.DEBUG etc
        """
        logger = logging.getLogger("serial-bsl")
        logger.setLevel(level)
        cls.console_handler = SerialBSLLogger.StdOutHandler.factory()
        serial_bsl_formatter = logging.Formatter('%(message)s')
        cls.console_handler.setFormatter(serial_bsl_formatter)
        logger.addHandler(cls.console_handler)
