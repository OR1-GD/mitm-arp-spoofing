"""
author: OR1-GOODAY
additional logging lib based on `logging` python lib in order to make life more easyer

""" 
from datetime import datetime
import sys, colorama
import json
import logging , logging.handlers, logging.config

LOGGER_CONSOLE_FORMAT = "%(color_on)s[%(levelname)s] %(asctime)s %(name)s - %(message)s%(color_off)s"
LOGFILE_FORMAT = "[%(levelname)s] %(name)s %(asctime)s %(message)s"
LOGGER_CONSOLE_FORMAT_ORIGIN = "%(color_on)s[%(created)d] [%(threadName)s] [%(levelname)-8s] %(message)s%(color_off)s"

# Logging formatter supporting colorized output
class LogFormatter(logging.Formatter):
    """ alternative formatter class 
        copyied from https://stackoverflow.com/questions/13733552/logger-configuration-to-log-to-file-and-print-to-stdout

    Args:
        logging (_type_): _description_

    Returns:
        _type_: _description_
    """
    COLOR_CODES = {
        logging.CRITICAL: "\033[1;35m", # bright/bold magenta
        logging.ERROR:    "\033[1;31m", # bright/bold red
        logging.WARNING:  "\033[1;33m", # bright/bold yellow
        logging.INFO:     "\033[0;37m", # white / light gray
        logging.DEBUG:    "\033[1;30m"  # bright/bold black / dark gray
    }

    RESET_CODE = "\033[0m"

    def __init__(self, color, *args, **kwargs):
        super(LogFormatter, self).__init__(*args, **kwargs)
        self.color = color

    def format(self, record, *args, **kwargs):
        if (self.color == True and record.levelno in self.COLOR_CODES):
            record.color_on  = self.COLOR_CODES[record.levelno]
            record.color_off = self.RESET_CODE
        else:
            record.color_on  = ""
            record.color_off = ""
        return super(LogFormatter, self).format(record, *args, **kwargs)

def addHandlers(logger ,*handlers):
    for h in handlers: 
        logger.addHandler(h)

# Setup logging
def setup_logger(name = None, min_level = logging.DEBUG, console_log_output = None, console_log_level=logging.INFO, console_log_color=True, logfile_file = None, logfile_log_level=logging.DEBUG, logfile_log_color=False, log_line_template=LOGGER_CONSOLE_FORMAT):
    """ Create logger
        For simplicity, we use the root logger, i.e. call 'logging.getLogger()'
        without name argument. This way we can simply use module methods for
        for logging throughout the script. An alternative would be exporting
        the logger, i.e. 'global logger; logger = logging.getLogger("<name>")'

    Args:
        name (_type_, optional): _description_. Defaults to None.
        console_log_output (_type_, optional): _description_. Defaults to None.
        console_log_level (_type_, optional): _description_. Defaults to logging.INFO.
        console_log_color (bool, optional): _description_. Defaults to True.
        logfile_file (_type_, optional): _description_. Defaults to None.
        logfile_log_level (_type_, optional): _description_. Defaults to logging.DEBUG.
        logfile_log_color (bool, optional): _description_. Defaults to False.
        log_line_template (_type_, optional): _description_. Defaults to LOGGER_CONSOLE_FORMAT.

    Returns:
        _type_: _description_
    """
  
    logger = logging.getLogger(name)
    # Set global log level to 'debug' (required for handler levels to work)
    logger.setLevel(min_level)

    # Create console handler
    if console_log_output and console_log_output in [sys.stdout, sys.stderr]:
        try:
            console_handler = logging.StreamHandler(console_log_output)
            console_handler.setLevel(console_log_level)
        except:
            raise Exception("Failed to set console log level: invalid level: '%s'" % console_log_level)

    else:
        # raise an Error
        print(f"Failed to set console output: invalid output: '%s'" % console_log_output)
        raise Exception("console_log_output can be only sys.stdout or sys.stderr")
    
    # Create and set formatter, add console handler to logger
    if console_log_output:
        console_formatter = LogFormatter(fmt=log_line_template, color=console_log_color)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # Create log file handler
    if logfile_file:
        try:
            logfile_handler = logging.FileHandler(logfile_file)
        except Exception as exception:
            print("Failed to set up log file: %s" % str(exception))
            return False

        # Set log file log level
        try:
            logfile_handler.setLevel(logfile_log_level.upper()) # only accepts uppercase level names
        except:
            print("Failed to set log file log level: invalid level: '%s'" % logfile_log_level)
            return False

        # Create and set formatter, add log file handler to logger
        logfile_formatter = LogFormatter(fmt=log_line_template, color=logfile_log_color)
        logfile_handler.setFormatter(logfile_formatter)
        logger.addHandler(logfile_handler)

    # Success
    return logger


def upload_logger_conf(conf_file):
    # configure logging via config dict/json file
    try:
        logging.config.dictConfig(json.load(open(conf_file)))
    except Exception as e:
        raise Exception(e)

# Main function
def test():
    print(f"------------ {datetime.now()} - LOGGER TEST START ------------")
    colorama.init() # for using cmd window
    # dummy trick https://stackoverflow.com/questions/42936810/python-logging-module-set-formatter-dynamically
    upload_logger_conf(conf_file="logger_conf.json")
    try:
        logger = logging.getLogger()
        # test
        print("before change")
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")
        # for every handler lets convert basic formatter to the new colorful `LogFormatter`
        for h in logger.handlers: 
            h.setFormatter(LogFormatter(True, fmt=f"%(color_on)s{h.formatter._fmt}%(color_off)s"))
    except Exception as e: 
        print(e)
        return 1

    print()
    logger.info("loggig configured successfuly")
    print("\nafter change\n")

    # Log some messages
    try:
        logger.debug("Debug message")
        logger.info("Info message")
        logger.warning("Warning message")
        logger.error("Error message")
        logger.critical("Critical message")
    except Exception as e:
        print(e)
        return 1

    print()
    logging.info("logging is working")

# Call main function
if (__name__ == "__main__"):
    test()
    print(f"------------ {datetime.now()} - LOGGER TEST Finshed ------------")