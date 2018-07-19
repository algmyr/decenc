decenc
======

Tools for working with DEC_ENC files from the (very enjoyable) game Hacknet,
written for python3 but compatible with python2.  DEC_ENC is a quite simple
encryption scheme that allows password protected storage while still allowing a
header to be read without a password.

The tools include replacements for the in-game programs Decypher and DECHead,
as well as a new encoding tool (Encypher).

The Decypher tool has been extended with a brute-force cracker!

Compatability
-------------

These tools are compatible with the in-game format, i.e. you can open your
in-game .dec files with this program. This was done by disassembling the source
of the code to find the hashing method used by the mono runtime bundled with
Hacknet and reproducing it in python.

Brute force cracking
--------------------

The major new feature of cracking a file, along with producing a valid password, is possible due to a weakness in the encryption scheme. Passwords are hashed into one of only 65536 possible values, and successful decryption can easily be checked by design.

By brute forcing over combinations of characters a rainbow table can be computing mapping hashes to some corresponding password. It turns out that 4 character passwords is plenty enough for this, and this table can be seen in `rainbow.py`.

Usage
-----

The three subcommands can be executed through

    python decenc.py decypher
    python decenc.py dechead
    python decenc.py encypher

Help can be gotten through any of

    python decenc.py -h
    python decenc.py decypher -h
    python decenc.py dechead -h
    python decenc.py encypher -h

Sample usage of decypher

    # Brute force solver that outputs decrypted content to stdout
    python decenc.py decypher kenobi.dec --brute
    cat kenobi.dec | python decypher decenc.py --brute

    # Solve given password, output to kenobi.txt
    python decenc.py decypher kenobi.dec <redacted> -o kenobi
    cat kenobi.dec | python decenc.py decypher - <redacted> -o kenobi

    # Decrypt a double layer encrypted file with no password
    python decenc.py decypher twolayer.dec -n2
    
    # Brute force decrypt in verbose mode, showing header and a valid password
    python decenc.py -v decypher kenobi.dec --brute

Sample usage of dechead

    python decenc.py dechead kenobi.dec
    python decenc.py dechead < kenobi.dec
    python decenc.py dechead - < kenobi.dec

Sample usage of encypher
    
    # Encrypt rainbow.py into rainbow.dec with comment, signature and password
    python decenc.py encypher rainbow.py secret \
           --comment hi --signature here -o rainbow.dec
    # Same with short options
    python decenc.py encypher rainbow.py secret \
           -c hi -s here -o rainbow.dec
    # Encrypt from stdin with no header info or password, output to stdout
    echo 'Hello, Hacknet!' | python decenc.py encypher

Notes
-----

I wrote this for my own sake after playing the game and being frustrated at not finding passwords for all encrypted files. It was quite a fun challenge and was greatly helped by the helpful C# code scraps left around by the developer, along with C# being pretty easy to decompile. As this is just a project for fun I didn't put too much care into the design of the command line interface, but it should be fine enough.
