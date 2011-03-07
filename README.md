Secure Password Encryption
==========================

Implementation of a secure SHA512-based password salting and hashing algorithm.

Safe against following attacks
-----------------------------
* code exposure
* encrpyted password exposure
* dictionary/rainbow attacks
* timing attacks (not done yet)

Safety against brute force attacks must be implemented at the app level. 

Goal
------
* encryption results identical to a modern linux system (glibc 2.7)
* hence encryption results are as secure as those of a modern linux system