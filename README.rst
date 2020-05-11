============
Github crypt
============

A tool to encrypt things (for humans, primarily of the developer type) using keys that
already exist (connected to nearly everyones personal github account to do things like
checkout and clone and such).

**Warning:** not nuke proof, not recommended for extremely secure things so don't
whine if the NSA or other agency/country is still able to break the encryption
applied here.

How to use
~~~~~~~~~~

1. Copy ghcrypt.ini to ~/.ghcrypt.ini (skip if already done).
2. Fill in values in ~/.ghcrypt.ini (skip if already done).
3. Create and install this folder into a
   virtualenv (skip if already done) or ``pip install ghcrypt`` (whichever works for you).
4. Use ``$ ghcrypt`` to send and read things.
5. Profit!
