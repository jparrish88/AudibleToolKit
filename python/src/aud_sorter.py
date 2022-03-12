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

    def __valid_filepath(self, path):
        #path = path.replace("&", "and")
        path = path.replace(":", "-")

        # Replace these chars
        # /, :, *, ?, ", <, >, |
        chars = '\:*?"<>|'
        path = re.sub('['+chars+']', '', path)

        return path

    def __clean_string(self, s):
        s = s.replace("/", " ")
        s = s.replace("®", "")
        s = s.strip()

        return s

    def __isascii(self, s):
        """Check if the characters in string s are in ASCII, U+0-U+7F."""
        return len(s) == len(s.encode())

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

                count = count + 1

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

                author = self.__clean_string(meta['author'])
                author = author.replace("- editor", "")
                author = author.replace("- translator", "")
                author = author.strip()

                series_name = ""

                title = self.__clean_string(meta['title'])

                # Remove A Novel from the end
                title = title.removesuffix(': A Novel')
                #re.sub('%s$' % ": A Novel", "", title)


                # Check if book is in a series
                if meta['book_num'] == -1:
                    dest_name = os.path.join(
                        self.media_path,
                        author,
                        title,
                        meta['decrypted_file_name']
                        )
                else:
                    series_name = self.__clean_string(meta['series'])
                    series_name = series_name.replace("(Unabridged)", "")
                    series_name = series_name.removeprefix("The ").strip()
                    series_name = series_name.strip()

                    if not series_name.lower().endswith("trilogy") and \
                        not series_name.lower().endswith("novels") and \
                        not series_name.lower().endswith("series"):
                        series_name = series_name+" Series"

                    book_num = self.__clean_string(meta['book_num'])

                    if len(book_num) == 1:
                        book_num = '0'+book_num

                    # Remove series from title
                    base_series = meta['series'].strip()
                    title = title.removesuffix(": "+base_series)
                    title = title.removesuffix(": The "+base_series)
                    title = title.removesuffix(": "+base_series.removeprefix("The ").strip())

                    # Add book number to title
                    title = ("Book {0} - "+title).format(book_num)

                    dest_name = os.path.join(
                        self.media_path,
                        author,
                        series_name,
                        title,
                        meta['decrypted_file_name']
                        )

                print("author: "+author)
                print("series: "+series_name)
                print("title:  "+title)
                print(self.__valid_filepath(dest_name))
                print("")
        print("Total Book Count: "+str(count))

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
