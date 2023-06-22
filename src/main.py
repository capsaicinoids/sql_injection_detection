#!/usr/bin/python

import os
import csv
import datetime
import threading
import pyshark as pys

from utils.helper import *

def main():
    try:
        # Make load_vec() non-blocking
        tensorflow_thread = threading.Thread(target=load_vec)
        tensorflow_thread.start()

        # Start capturing
        capture = pys.LiveCapture(interface=select_interface(), display_filter='http.request.method == GET')
        log_data = []
        capture.apply_on_packets(lambda packet: packet_processing(packet, log_data))
    except KeyboardInterrupt:
        # Prepare log file
        folder_name = 'logs'
        if not os.path.exists(folder_name):
            os.makedirs(folder_name)
        current_time = datetime.datetime.now()
        date_time_str = current_time.strftime("%Y-%m-%d_%H-%M-%S")
        filename = os.path.join(folder_name, "{}.csv".format(date_time_str))

        # Write log data to file
        if log_data:
            with open(filename, 'w', newline='') as csvfile:
                log_writer = csv.writer(csvfile)
                log_writer.writerow(['no.', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'payload_length', 'payload'])
                log_writer.writerows(log_data)
            print(f'There have been {len(log_data)} suspicious packets recorded')
            print(f'Log {date_time_str} have been saved in the "{os.path.abspath("logs")}" folder')
        else:
            print('No malicious packets found.')
        print('\nKeyboard interrupt detected. Exiting...')
        print('Sniffing has stopped by user')

if __name__ == '__main__':
    main()