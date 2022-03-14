import os
import sys
import datetime
import logging
import glob
import json

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

        for item_metadata_file in file_list:
            logging.info(item_metadata_file)
            with open(item_metadata_file, "r") as f:
                try:
                    meta = json.load(f)

                    #logging.debug(meta)
                    # Check for needed meta data
                    meta_data_error = False
                    if not 'verified' in meta:
                        meta_data_error = True
                        logging.error('verified value missing')
                    else:
                        if meta['verified'] != True:
                            logging.warning('verified is not true, skipping')

                    if not 'decrypted' in meta:
                        meta_data_error = True
                        logging.error('decrypted value missing')

                    if not 'activation_bytes' in meta:
                        meta_data_error = True
                        logging.error('activation_bytes value missing')

                    if not 'encrypted_file_name' in meta:
                        meta_data_error = True
                        logging.error('encrypted_file_name value missing')

                    if meta_data_error:
                        logging.debug(meta)

                        # Delete invalid json file
                        logging.warning('Deleting invalid json file')
                        f.close()
                        os.remove(item_metadata_file)
                        continue

                    # File already decrypted and exists, skipping
                    if 'decrypted' in meta and meta['decrypted'] == True:
                        self.__save_metadata(item_metadata_file, meta)
                        logging.info('Book already decrypted, skipping...')
                        continue

                    # Check if source file exists
                    input_file = os.path.join(self.unprocessed_path, meta['encrypted_file_name'])
                    if not os.path.isfile(input_file):
                        logging.error('encrypted file is missing, skipping...')
                        continue

                    # Check if dest file doesnt exist, delete if needed
                    meta['decrypted_file_name'] = meta['encrypted_file_name'].replace('aax', 'm4b')
                    output_file = os.path.join(self.processed_path, meta['decrypted_file_name'])
                    if os.path.isfile(output_file):
                        logging.warning("decrypted file '"+meta['decrypted_file_name']+"' already exists, deleting")
                        os.remove(output_file)

                    # Decrypt file
                    return_value = os.system(ffmpeg_path+" -activation_bytes "+meta['activation_bytes']+" -i "+input_file+" -c copy "+output_file)

                    if return_value != 0:
                        logging.warning("Something may have gone wrong, recvived non-zero return value: "+str(return_value))
                        meta['verified'] = False
                        self.__save_metadata(item_metadata_file, meta)

                    # Check if output file exists and is a good size
                    if os.path.isfile(output_file):
                        output_file_size = os.path.getsize(output_file)
                        if output_file_size > 10:
                            meta['decrypted'] = True
                            meta['decrypted_file_size'] = output_file_size

                            self.__save_metadata(item_metadata_file, meta)

                            logging.info('Book verified decrypted')

                except ValueError:  # includes simplejson.decoder.JSONDecodeError
                    logging.warning("Decoding JSON file '"+item_metadata_file+"' has failed")

    def __save_metadata(self, full_file_path, meta):
        full_metadata_path = os.path.abspath(full_file_path)

        with open(full_metadata_path, "w") as f:
            json.dump(meta, f, indent=4, sort_keys=True)
            logging.info('writing metadata')


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
