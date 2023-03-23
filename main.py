#!/usr/bin/python

import threading
import func
import pyshark as pys

# |%%--%%| <wCEgwpOxvG|KLoPb9b0Xa>


try:
    # Make load_vec() non blocking
    tensorflow_thread = threading.Thread(target=func.load_vec)
    tensorflow_thread.start()

    # Start Capturing
    capture = pys.LiveCapture(interface=func.select_interface(), display_filter='http.request.method == GET')
    capture.apply_on_packets(func.packet_processing)
except KeyboardInterrupt:
    print('\nKeyboard interrupt detected. Exiting...')
    print('Sniffing has stopped by user')

    # |%%--%%| <KLoPb9b0Xa|GBfB53oBTP>

# Unsolved Tasks

"""
    - Might change the learning algorithm
    - Might change it to OOP
    - Add Log Features (Store Suspicious Packet Information)
    - Find a better way to display the message!
"""


# |%%--%%| <GBfB53oBTP|wSdniQla0W>

# Perhaps You Need This Function Latter

# print(model.predict(vectorizer.transform([payload]), verbose=0))

# |%%--%%| <wSdniQla0W|uppP3N3cWN>
