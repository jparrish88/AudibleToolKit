# AudibleToolKit

These are a set of scripts to automate the download, decrypting and sorting of books from audible

## todo
* upgrade activator to python 3 and put it in a class
* work on the full_sync script to do the whole batch
* fix the docker-compose file to use full_sync script
* much better docs


# aud_activator.py / old_activator.py
Script to register a "player" to get the activation_bytes needed to decrypt audio book files

# aud_downloader.py
Script to scrape your library folder and download any books it can

# aud_decryptor.py
Script to decrypt downloaded books

# aud_sorter.py
Script to move decrypted files in to there final resting place
