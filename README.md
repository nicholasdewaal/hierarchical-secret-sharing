# hierarchical-secret-sharing

This tool is experimental, and may or may not be a secure method of encryption.
Use at your own risk.

Additionally, this tool is a work-in-progress, and may not yet be functional, although it should be functional soon.


Usage:

```python
import hierarchical_secret_sharing as hss
```
Then create the secret you would like to encrypt, along with some hierarchy structure required for secret recovery.
The secret could be a password, pin code to a safe, cryptocurrency private keys, etc.

```python
my_secret = "put secret text here"
hierarchy_structure = `define a hierarchy`
```

Then run the following to save the secret share that should be given to each individual defined in your hierarchy.

```python
hierarchical_ssss_to_files(my_secret, hierarchy_structure)
```

Distribute the secret key file shares, and Required_hierarchy_structure.txt to those friends or trusted secret holders along with the hierarchy required of them to recover your secret.


In order to recover the secret, put at least the minimum required paths to files of secret key shares in a list called file_paths to recover the secret as dictated by the required hierarchy in the Required_hierarchy_structure.txt produced when encrypting the secret.
Then call recover_secret_from_files(file_paths)
