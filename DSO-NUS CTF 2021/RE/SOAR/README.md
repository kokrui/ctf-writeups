# SOAR [300 pts] (Assigned Writeup)
>Looking for a scholarship?
Help us find the secret hidden in this one!

>Files (Any of the links are fine):
https://nusdsoctf2.s3-ap-southeast-1.amazonaws.com/S3/SOAR/SOAR-challenge.pdf

## TL;DR
* binwalk reveals a password-protected .zip file inside provided PDF
* Crack zip password via alphanumeric bruteforce / wordlist from PDF / guessing.
* Zip file contains a binary, reversing reveals interesting calls retrieving current system minute and hour
* Dynamic analysis reveals it tries to read a “SOAR” file and actual SOAR brochure url
* Download SOAR pdf into same directory, bruteforce system time, binary outputs flag when time is 7:11pm

## Writeup
_Note: this challenge has the least elegant / most stupid solution out of all the challenges I solved... and then I got assigned this challenge for one of my mandatory writeups LOL. pls don’t judge, I am bad but slightly less bad than this writeup may bring across_

We are given a SOAR-Challenge.pdf that is open-able and displays this DSO Mid-Term Scholarship advertisement:

![image](./screenshots/ss1.png)

#### Stage 1 - File Forensics
Opening the pdf in [peepdf](https://github.com/jesparza/peepdf) reveals a bunch of objects and streams!

``` console
root@kali:~/Desktop/dso/soar# peepdf SOAR-challenge.pdf
File: SOAR-challenge.pdf
MD5: 4104a9572d9161eb990a3ae10a43198f
SHA1: 51035622adecb8ddc7600f9866b3dce1e6e39c09
SHA256: ec04d8574074854d4f839ec80e71df6b32765851222eecd82446a018f71cc95a
Size: 41611 bytes
Version: 1.4
Binary: True
Linearized: False
Encrypted: False
Updates: 0
Objects: 34
Streams: 15
URIs: 0
Comments: 0
Errors: 0

Version 0:
        Catalog: 5
        Info: 3
        Objects (34): [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34]
        Streams (15): [1, 6, 7, 8, 9, 10, 11, 12, 13, 19, 22, 25, 28, 32, 34]
                Encoded (15): [1, 6, 7, 8, 9, 10, 11, 12, 13, 19, 22, 25, 28, 32, 34]
                Decoding errors (15): [1, 6, 7, 8, 9, 10, 11, 12, 13, 19, 22, 25, 28, 32, 34]
```

Many of the objects contain nothing more than a stream of length 1000+. When I try to print the corresponding streams, there is no printable output. Weird.

``` console
PPDF> object 9

<< /Length 1952
/Filter /FlateDecode >>
stream

endstream

PPDF> object 10

<< /Length 2065
/Filter /FlateDecode >>
stream

endstream

PPDF> object 11

<< /Length 1584
/Filter /FlateDecode >>
stream

endstream
```

It seems like the PDF could be hiding some data! We can run binwalk to extract hidden files, if any.
