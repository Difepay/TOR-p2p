# Project: TOR-P2P
## Developers: Dmitry Zaguliaev

___


## Introduction

I've figured out how to combine two topics of information security and networks in one project - and came up with the idea of ​​the project: TOR-P2P. This project is useful not only from the point of view of deep investigation. Project is useful even as a finished product, our project is able to pass messages between users protected way.



## Import project

- [ ] You can import yor project by download it or using these commands:
```
cd <directory_you_want>
git clone https://gitlab.com/tor6243037/jerusalem-503-tor.git
```



## Getting started
##### Step 1
- [ ] You should first of all run the directory server file [_exec.bat](https://github.com/Difepay/TOR-p2p/blob/main/DirectoryServer/_exec.bat) that will open console for the directory server


##### Step 2
- [ ] You can start the project by using execute file [_exec.bat](https://github.com/Difepay/TOR-p2p/blob/main/TOR/_exec.bat) that will open 5 GUI applications

- [ ] Or you able to execute one specific user from [GUI.py](https://github.com/Difepay/TOR-p2p/blob/main/TOR/GUI.py)
```
python GUI.py
```


## Libraries
- [ ] You project using libraries that user have to install before using project in case if they aren't. The list of the libraries: `Crypto`, `hashlib`, `random`, `socket`, `threading`, `sys`, `os`, `sqlite3`, `time`
* [Crypto](https://pypi.org/project/crypto/) - library is used for generating strong prime numbers
* [hashlib](https://pypi.org/project/hashlib/) - library is used for hash functions
    * [MD5 hash function](https://en.wikipedia.org/wiki/MD5) to compress big numbers to numbers that satisfy AES key standart 
    * [SHA256 hash function](https://en.wikipedia.org/wiki/SHA-2) to make sure that session key was created correctly
* [random](https://docs.python.org/3/library/random.html) - library is used for generate pseudo-random numbers, for example to give thee random nodes from the server
* [socket](https://docs.python.org/3/library/socket.html) - library of low-level networking interface
* [threading](https://docs.python.org/3/library/threading.html) - library constructs higher-level threading interfaces
* [sqlite3](https://docs.python.org/3/library/sqlite3.html) - library that give database API, working with sqlite databases
