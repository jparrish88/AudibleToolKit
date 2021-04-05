import os

ffmpeg_path = "C:\\bin\\ffmpeg\\bin\\ffmpeg.exe"
input_file = "C:\\bin\\AudibleToolKit\\python\\files\\unprocessed\\059316735X-false_value_rivers_of_lon.aax"
output_file = "C:\\bin\\AudibleToolKit\\python\\files\\processed\\059316735X-false_value_rivers_of_lon.m4b"



os.system(ffmpeg_path+" -activation_bytes 938a5801 -i "+input_file+" -c copy "+output_file)
