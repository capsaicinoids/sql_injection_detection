# SQL Injection Scanner

This is a Python-based SQL injection scanner that uses machine learning to detect SQL injection attacks on network traffic. It uses the PyShark library to capture network packets, and TensorFlow to classify the packets as malicious or not.

## Getting Started

To get started, you need to install the required dependencies listed in the `requirements.txt` file. You can do this by running the following command:

To run the scanner, simply run the following command:

`pip install -r requirements.txt` 

We will also need to use machine learning model and vectorizer files in the same directory as the script.

To sniff, simply run the following command:

`python main.py` 

You will be prompted to select a network interface to listen on. Once selected, the scanner will start capturing network packets and classify them as malicious or not. Any detected SQL injection attacks will be displayed on the console, and logged to a CSV file in the `logs` folder.

To stop sniffing, simply press `Ctrl+C` in the console.

## Dependencies

The following Python packages are required to run the SQL injection scanner:

- PyShark
- netifaces
- TensorFlow

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.

## Acknowledgments

"Coming Soon"
