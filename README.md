# V-Banker

## Security regarding passwords
V-Banker regars user safety over all, and therefore uses the following protocol:

```
CLIENT           Hashes password into SHA256
--------------------------------------------------------
SERVER           Hashes the SHA256 password with Argon2
--------------------------------------------------------
DATABASE         Stores the Argon2 password
```

The plaintext password never leaves the user's laptop.

### Details

This is what happens during registeration:
1. The user enters a plaintext password into the password bar.
2. The frontend hashes this password into SHA256, and sends the SHA256 hash to the server.
3. The server recieves the SHA256 hash and further hashes it using Argon2.
4. The server sends the Argon2 hash to the database, where it is stored.


This is what happens during logon:
1. The user enters a plaintext password into the password bar.
2. The frontend hashes this password into SHA256, and sends the SHA256 hash to the server.
3. The server recieves the SHA256 hash, and:
    - The server calls the Argon2 hash from the database
    - The server uses the Argon2 password verification method on the SHA256 hash and the Argon2 hash.
    - If it is valid, the server allows the user to be "logged in".
    - Otherwise, the password is marked wrong in the frontend.
