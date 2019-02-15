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

Then run the following function that will create the secret shares saved as files that should be given to each individual defined in your hierarchy.

```python
hss.hierarchical_ssss_to_files(my_secret, hierarchy_structure)
```

Distribute the secret key file shares created above to those respective friends or trusted secret holders along with the hierarchy description file Required_hierarchy_structure.txt which describes the social hierarchy required of them to recover your secret.


In order to recover the secret, put at least the minimum required paths to files of secret key shares in a list called file_paths to recover the secret as dictated by the required hierarchy in the Required_hierarchy_structure.txt produced when encrypting the secret.
Then call

```python
hss.recover_secret_from_files(file_paths)
```

Examples:

```python
import hierarchical_secret_sharing as hss

secret = "My super secret text"

hierarchy_structure = (2, 3, 'CEO', 'CEO2',
       (3, 5, ('CFO',
               'CTO',
               'COO',
               (1, 3, ('Liz', 'Alex', 'Ana')),
               (3, 3, ('Mike', 'Stephanie', 'Andy'))
              )
       )
)

```

Create the secret file shares:

```python

hss.hierarchical_ssss_to_files(my_secret, hierarchy_structure)
```

Distribute the corresponding files to CFO, CTO, COO, CEO, CEO2, Liz, Alex, Ana, Mike, Stephanie, and Nick.

The CEO and CEO2, then decide they must access the secret.  Since the hierarchy only requires 2 of 3 at that level, their keys will be enough to unlock the secret by doing the following with their private share files:


```python

file_paths = ['/path/to/CEO_Secret_Share.txt' 'path/to/CEO2_Secret_Share.txt']
secret = hss.recover_secret_from_files(file_paths)
print(secret)

```

Additionally, if CEO2, CTO, CFO, and Liz agree that the secret needs to be recovered, the hierarchy_structure would allow them to combine their secret shares to recover the secret.


```python

file_paths = ['path/to/CEO2_Secret_Share.txt', 'path/to/Liz_Secret_Share.txt', 
'path/to/CTO_Secret_Share.txt', 'path/to/CFO_Secret_Share.txt']
secret = hss.recover_secret_from_files(file_paths)
print(secret)

```

