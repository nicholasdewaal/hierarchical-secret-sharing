# hierarchical-secret-sharing

This tool is experimental, and may or may not be a secure method of encryption.
Use at your own risk.

Additionally, this tool is a work-in-progress, and may not yet be functional, although it should be functional soon.


This tool is run in Python 3, and uses secretsharing installed by calling:

pip install secretsharing

If that causes errors, or fails to work, uninstall it, and install the working version using:

pip install --user git+https://github.com/blockstack/secret-sharing

Usage:

```python
import hierarchical_secret_sharing as hss
```
Then create the secret you would like to encrypt, along with some hierarchy structure as described below required for secret recovery.
The secret could be a password, pin code to a safe, cryptocurrency private keys, etc.

```python
my_secret = "put secret text here"
hierarchy_structure = `define a hierarchy`
```

A hierarchy structure is a tuple beginning with two numbers: n, then m,
with n <= m, then followed by m tuples and/or strings.
Each contained tuple also must be a hierarchy structure type thus having to
follow the same conventions.

A few examples of a hierarchy structure:


```python
(2, 3, ('Nick', 'Alice', 'Bob'))

(3, 4, ('Nick', 'Alice', 'Bob', (1, 3, ('Liz', 'Alex', 'Ana'))
       )
)
```

A company has 2 CEO's (weird), a CFO, CTO, COO, engineers named Liz, Alex, and Ana, and in marketing are Mike, Stephanie, and Andy. You want to require a consensus of 2 out of 3 groups/individuals consisting of the 2 CEO's, and a third group with a more sophisticated consensus structure. This structure requiring at least 3 of 5 from either the 3 remaining CTO, CFO, or COO, or 1 of 3 from engineering or 3 of 3 from marketing. This is solved using the following hierarchy structure:

```python
(2, 3, 'CEO', 'CEO2',
       (3, 5, ('CFO',
               'CTO',
               'COO',
               (1, 3, ('Liz', 'Alex', 'Ana')),
               (3, 3, ('Mike', 'Stephanie', 'Andy'))
              )
       )
)

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

