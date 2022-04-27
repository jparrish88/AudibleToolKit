import os
import sys
import datetime
import logging
import glob
import json

from aud_metadata import aud_metadata

from optparse import OptionParser
from pathlib import Path

class aud_decryptor:
    debug = False
    data_path = ''
    one_file = ''

    unprocessed_path = ''
    metadata_path = ''

    def __init__(self, **kwargs):
        if 'debug' in kwargs.keys():
            self.debug = kwargs['debug']
        if 'data_path' in kwargs.keys():
            self.data_path = kwargs['data_path']
        if 'one_file' in kwargs.keys():
            self.one_file = kwargs['one_file']

        if os.getenv("DEBUG"):
            self.debug = True

        if self.data_path:
            # Convert path to abspath (creates path Chrome can use on Windows)
            # Must happen before we add separator
            self.data_path = os.path.abspath(self.data_path)

            # if not self.data_path.endswith(os.path.sep):
            #     self.data_path += os.path.sep

            self.__create_dir(self.data_path)

            self.metadata_path = os.path.join(self.data_path, 'metadata')
            self.__create_dir(self.metadata_path)

            self.unprocessed_path = os.path.join(self.data_path, 'unprocessed')
            self.__create_dir(self.unprocessed_path)

            self.processed_path = os.path.join(self.data_path, 'processed')
            self.__create_dir(self.processed_path)

            logging.info('data_path: '+self.data_path)
        else:
            logging.error('Missing data_path arg')
            sys.exit(1)

    def __create_dir(self, path):
        if not os.path.exists(path):
            logging.warning("directory doesn't exist, creating " + path)
            os.makedirs(path)

        if not os.access(path, os.W_OK):
            logging.error("directory " + path + " not writable")
            sys.exit(1)

    # Decrypt all the audio books
    def run(self, **kwargs):
        logging.info("Starting decryptor")

        ffmpeg_path = "ffmpeg"

        my_file = Path(self.one_file)
        if my_file.is_file():
            file_list = [self.one_file]
        else:
            file_list = glob.glob(os.path.join(self.metadata_path, '*.json'))

        for metadata_file in file_list:
            logging.info(metadata_file)

            meta = aud_metadata(filename = metadata_file)

            if not meta.get('encrypted_verified'):
                logging.warning('verified is not true, skipping...')
                continue

            # File already decrypted and exists, skipping
            if meta.get('decrypted'):
                logging.info('Book already decrypted, skipping...')
                continue

            # Check if source file exists
            input_file = os.path.join(self.unprocessed_path, meta.get('encrypted_file_name'))
            if not os.path.isfile(input_file):
                logging.error('encrypted file is missing, skipping...')
                continue

            # Check if dest file doesnt exist, delete if needed
            meta.set('decrypted_file_name', meta.get('encrypted_file_name').replace('aax', 'm4b'))
            output_file = os.path.join(self.processed_path, meta.get('decrypted_file_name'))
            if os.path.isfile(output_file):
                logging.warning("decrypted file '"+meta.get('decrypted_file_name')+"' already exists, deleting")
                os.remove(output_file)

            # Decrypt file
            return_value = os.system(ffmpeg_path+" -activation_bytes "+meta.get('activation_bytes')+" -i "+input_file+" -c copy "+output_file)

            if return_value != 0:
                logging.warning("Something may have gone wrong, recvived non-zero return value: "+str(return_value))
                meta.set('encrypted_verified', False)
                meta.save(metadata_file)

            # Check if output file exists and is a good size
            if os.path.isfile(output_file):
                output_file_size = os.path.getsize(output_file)
                if output_file_size > 10:
                    meta.set('decrypted', True)
                    meta.set('decrypted_file_size', output_file_size)

                    meta.save(metadata_file)

                    logging.info('Book verified decrypted')


if __name__ == "__main__":
    def main():
        parser = OptionParser(usage="Usage: %prog [options]", version="%prog 0.2")
        parser.add_option("-d", "--debug",
                        action="store_true",
                        dest="debug",
                        default=False,
                        help="run program in debug mode, enable this for 2FA enabled accounts or for authentication debugging")
        parser.add_option("--data-path",
                        action="store",
                        dest="data_path",
                        default="/mnt/media/downloads/audibletoolkit",
                        help="data directory",)
        parser.add_option("--log-path",
                        action="store",
                        dest="log_path",
                        default="/mnt/media/downloads/audibletoolkit/logs",
                        help="log directory",)
        parser.add_option("--one-file",
                        action="store",
                        dest="one_file",
                        default="",
                        help="",)
        (options, args) = parser.parse_args()

        dt = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        basepath = os.path.dirname(os.path.realpath(__file__))
        os.chdir(basepath)

        data_path = options.data_path
        log_path = options.log_path

        one_file = options.one_file

        # Make log dir if needed
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        log_level = logging.INFO
        if options.debug:
            log_level = logging.DEBUG

        logging.basicConfig(
            format='%(levelname)s(#%(lineno)d):%(message)s',
            level=log_level,
            filename=log_path+"/aud-decryptor-%s.log" % (dt)
        )
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        dc = aud_decryptor(
            data_path = data_path,
            one_file = one_file,
        )
        dc.run()

    main()
