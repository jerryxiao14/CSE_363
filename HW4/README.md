# README

## Setup

To run this program, install the required dependency using:

pip install -r requirements.txt

The only external dependency required is the `cryptography` library.

---

## Program Overview

This project consists of two Python components: `tmp363.py`, which acts as the client-side collection and transmission program, and `server.py`, which receives, decrypts, and stores the transmitted data.

`tmp363.py` functions as a filesystem collection utility that recursively traverses the `/home` directory of a Linux system. It searches for specific user-related configuration and credential storage locations such as `.ssh`, `.config`, `.aws`, `.gcloud`, and `.azure`, as well as shell history files identified through a regular expression matching pattern ending in `_history`. When matching files or directories are found, they are collected and added into an in-memory ZIP archive using Python’s `zipfile` module and `BytesIO`, avoiding intermediate disk writes.

During collection, the program attempts to handle permission-restricted files by modifying file permissions using `chmod` where possible, allowing broader access to otherwise restricted data. Once file aggregation is complete, the ZIP archive is encrypted using AES-GCM from the `cryptography` library. A fixed 256-bit key is used for encryption, and a randomly generated nonce ensures semantic security for each execution.

After encryption, the program establishes a TCP connection to a user-specified IP address and port. It first transmits the size of the encrypted payload as an unsigned 64-bit integer, followed by the encrypted data itself.

---

## Server Behavior

The server component listens on a specified IP and port and waits for incoming connections. When a client connects, the server first reads an 8-byte length header to determine the size of the incoming encrypted payload. It then receives the full encrypted blob accordingly.

Once the full payload is received, the server stores it in a newly created directory named using a timestamp and the client’s IP address. This ensures that each session is isolated and traceable. The encrypted archive is first written to disk as a raw `.enc` file for preservation. The server then decrypts the payload using the same AES-GCM key and nonce extraction method used by the client.

After decryption, the resulting ZIP archive is reconstructed and saved to disk. The server writes the decrypted archive into the same session directory, effectively restoring the original file structure contained within the ZIP. This allows the recovered data to be inspected in its original hierarchical form.

---

## Design Summary

The system is designed around in-memory data aggregation, authenticated encryption, and simple TCP-based transmission. The client focuses on efficient collection and secure packaging of filesystem data, while the server focuses on reliable reception, decryption, and reconstruction of the original archive into a structured directory format for later analysis.