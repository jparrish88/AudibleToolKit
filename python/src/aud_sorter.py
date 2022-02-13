import os
import sys
import datetime
import logging
import glob
import json
import re

from optparse import OptionParser

class aud_sorter:
    debug = False
    data_path = ''
    media_path = ''

    unprocessed_path = ''
    metadata_path = ''

    def __init__(self, **kwargs):
        if 'debug' in kwargs.keys():
            self.debug = kwargs['debug']
        if 'data_path' in kwargs.keys():
            self.data_path = kwargs['data_path']
        if 'media_path' in kwargs.keys():
            self.media_path = kwargs['media_path']

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
        logging.info("Starting sorter")

        count = 0

        for item_metadata_file in glob.glob(os.path.join(self.metadata_path, '*.json')):
            #logging.info(item_metadata_file)
            with open(item_metadata_file, "r") as f:
                try:
                    meta = json.load(f)
                except ValueError:  # includes simplejson.decoder.JSONDecodeError
                    logging.warning("Decoding JSON file '"+item_metadata_file+"' has failed")
                    continue

                #logging.debug(meta)
                # Check for needed meta data
                meta_data_error = False
                if not 'verified' in meta:
                    meta_data_error = True
                    logging.error('verified value missing '+item_metadata_file)
                    continue
                else:
                    if meta['verified'] != True:
                        logging.warning('verified is not true, skipping '+item_metadata_file)
                        continue

                if not 'decrypted' in meta:
                    meta_data_error = True
                    logging.error('decrypted value missing')

                if meta_data_error:
                    logging.debug(meta)

                    # Delete invalid json file
                    logging.warning('invalid json file')
                    f.close()
                    continue

                # File not decrypted, skipping
                if meta['decrypted'] == False:
                    logging.info('Book not decrypted, skipping... '+item_metadata_file)
                    continue

                # Check if decrypted file exists
                source_file = os.path.join(self.processed_path, meta['decrypted_file_name'])
                if not os.path.isfile(source_file):
                    logging.error('decrypted file is missing, skipping... '+item_metadata_file)
                    continue

                #print(source_file)

                author = meta['author']
                author = author.replace("- editor", "")
                author = author.strip()

                # Check if book is in a series
                if meta['book_num'] == -1:
                    title = meta['title']

                    dest_name = os.path.join(
                        self.media_path,
                        author,
                        title,
                        meta['decrypted_file_name']
                        )
                else:
                    series_name = meta['series']
                    series_name = series_name.replace("(Unabridged)", "")
                    series_name = re.sub('^%s' % "The", "", series_name)
                    series_name = series_name.strip()

                    if not series_name.lower().endswith("trilogy") and \
                        not series_name.lower().endswith("novels") and \
                        not series_name.lower().endswith("series"):
                        series_name = series_name+" Series"

                    book_num = meta['book_num']
                    #book_num = book_num.split(',')[0]
                    if len(book_num) == 1:
                        book_num = '0'+book_num

                    title = meta['title']
                    #title = ("Book {:02f} - "+meta['title']).format(float(meta['book_num']))

                    if len(book_num) > 3:
                        count = count + 1
                        #print(book_num+"      "+item_metadata_file)

                    dest_name = os.path.join(
                        self.media_path,
                        author,
                        series_name,
                        title,
                        meta['decrypted_file_name']
                        )

                    #print(dest_name)
        print(count)

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
        parser.add_option("--media-path",
                        action="store",
                        dest="media_path",
                        default="/mnt/media/audiobooks",
                        help="data directory",)
        parser.add_option("--log-path",
                        action="store",
                        dest="log_path",
                        default="/mnt/media/downloads/audibletoolkit/logs",
                        help="log directory",)
        (options, args) = parser.parse_args()

        dt = datetime.datetime.now().strftime("%Y-%m-%dT%H-%M-%S")

        basepath = os.path.dirname(os.path.realpath(__file__))
        os.chdir(basepath)

        data_path = options.data_path
        media_path = options.media_path
        log_path = options.log_path

        # Make log dir if needed
        if not os.path.exists(log_path):
            os.makedirs(log_path)

        log_level = logging.INFO
        if options.debug:
            log_level = logging.DEBUG

        logging.basicConfig(
            format='%(levelname)s(#%(lineno)d):%(message)s',
            level=log_level,
            filename=log_path+"/aud-sorter-%s.log" % (dt)
        )
        logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

        sorter = aud_sorter(
            data_path = data_path,
            media_path = media_path,
        )
        sorter.run()

    main()
