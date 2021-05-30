## Overview
This example demonstrates some of the cryptographic capabilities of the system.
It consists of an OpenTitan server program and a Python 3 module with client
classes implementing a simple protocol on top of UART for exchanging
cryptographic requests and data.

## Features
* Usage of the AES peripheral for encryption and decryption in ECB, CBC or CTR
  modes with a compiled-in 256 bit key
* Usage of the HMAC peripheral for SHA256 hashes or MACs using a second
  compiled-in 256 bit key

## Keys
The keys used by the OpenTitan server can be configured in `key.h`.

## Usage
The Python client module depends on a module generated from the server's C
headers with [`SWIG`](http://www.swig.org/). Install a sufficiently recent
version (4.0.2 is recommended) with your package manager or from the [project
website](http://www.swig.org/download.html). Refer to the documentation for [installation instructions](http://www.swig.org/Doc4.0/Preface.html#Preface_installation).

To generate the required module, run:

```
$ cd $REPO_TOP/sw/device/examples/crypto
$ swig -python -py3 -builtin -castmode crypto.i
$ gcc -fpic -c crypto_wrap.c -I /usr/include/python3.X # your version
$ gcc -shared crypto_wrap.o -o _titan_crypto.so
```

Once the OpenTitan system running the server program is connected via UART and
the assigned serial port (e.g. ``/dev/ttyUSB0``) has been identified, the client
module can then be comfortably used e.g. from an interactive python session:

```
$ cd $REPO_TOP/sw/device/examples/crypto
$ python3
[...]
```
```pycon
>>> import titan_client, serial
>>> from titan_crypto import *
>>> s = serial.Serial('/dev/ttyUSB0', 115200)
>>> opentitan = titan_client.OpenTitan(s)
>>> opentitan.hmac.hash(b'test')
b'\x9f\x86\xd0\x81\x88L}e\x9a/\xea\xa0\xc5Z\xd0\x15\xa3\xbfO\x1b+\x0b\x82,\xd1]l\x15\xb0\xf0\n\x08'
>>> ciphertext = opentitan.aes.encrypt(b'secret')
>>> opentitan.aes.decrypt(ciphertext)
b'secret'
>>> opentitan.aes.cipher_mode = cipherModeCtr
>>> opentitan.aes.iv = b'0123456789ABCDEF'
>>> opentitan.aes.decrypt(opentitan.aes.encrypt(b'secret')
b'secret'
```
