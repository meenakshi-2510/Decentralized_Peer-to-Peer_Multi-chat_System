Decentralized P2P Multi-Chat System

A secure peer-to-peer chat application built as a second-year micro-project as a group of four. Peers discover each other on the local network and exchange encrypted messages and files directly(no central server involved).

Features:
1.Peer discovery over UDP broadcast — peers announce themselves and their public key on the local network
2.Hybrid encryption — RSA (2048-bit) for secure session key exchange, AES for encrypting the actual messages/files
3.Digital signatures (RSA with SHA-256) — verifies that messages actually came from the claimed sender and weren't tampered with
4.Encrypted file sharing between connected peers
5.Persistent chat logs saved locally
6.GUI built with Tkinter — username broadcasting, live peer list, connect/disconnect controls, chat window

How it works:
1.Each peer generates an RSA key pair on startup.
2.Peers broadcast their username, IP, and public key over UDP every few seconds; other peers on the network pick this up and populate their peer list.
3.When a peer connects to another, they exchange a randomly generated AES session key, encrypted with the recipient's RSA public key.
4.All further messages and files in that session are encrypted with AES and signed with RSA, so both confidentiality and authenticity are covered.

Tech Stack:
Python, Tkinter (GUI), cryptography library (RSA, AES, digital signatures), raw sockets (UDP for discovery, TCP for messaging).
