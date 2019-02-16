
import pickle
from secretsharing import SecretSharer
from ipdb import set_trace

'''
hierarchy_structure is a tuple beginning with two numbers: n, then m,
with n <= m, then followed by m tuples and/or strings.
Each contained tuple also must be a hierarchy_structure type thus having to
follow the same conventions.

A few examples:

(2, 3, ('Nick', 'Alice', 'Bob'))

(3, 4, ('Nick', 'Alice', 'Bob', (1, 3, ('Liz', 'Alex', 'Ana'))
       )
)

A company has 2 CEO's (weird), a CFO, CTO, COO, engineers named Liz, Alex, and
Ana, and in marketing are Mike, Stephanie, and Andy. You want to require a
consensus of 2 out of 3 groups/individuals consisting of the 2 CEO's, and a
third group with a more sophisticated consensus structure.
This structure requiring at least 3 of 5 from either the 3 remaining C-suite,
or 1 of 3 from development or 3 of 3 from marketing. This is solved using the
following hierarchy_structure:

(2, 3, 'CEO', 'CEO2',
       (3, 5, ('CFO',
               'CTO',
               'COO',
               (1, 3, ('Liz', 'Alex', 'Ana')),
               (3, 3, ('Mike', 'Stephanie', 'Andy'))
              )
       )
)
'''

def is_well_defined_hierarchy(hierarchy_structure):
    '''
    This function recursively checks to see if a hierarchy_structure is well
    defined.
    '''

    _empty_set = set()
    all_names = set()
    if isinstance(hierarchy_structure, str):
        if hierarchy_structure in all_names:
            print('You cannot have the same person in two parts of the hierarchy_structure')
            return False
        all_names.add(hierarchy_structure)
        return True, all_names

    else:
        try:
            n, m, hierarchy = hierarchy_structure
        except:
            return False, all_names

        if n > m or len(hierarchy) != m:  # best n out of m, so n <= m
            return False, all_names

        for sub_hierarchy in hierarchy:
            well_def, new_names = is_well_defined_hierarchy(sub_hierarchy)
            if not well_def and new_names.intersetion(all_names) != _empty_set:
                return False, all_names
            else:
                all_names = all_names.union(new_names)

    return True, all_names


def secret_is_recoverable(shares, hierarchy_structure):
    '''
    This function recursively checks to see if the shares provided combined
    with the given hierarchy_structure is enough to recover the secret.
    '''

    n, m, hierarchy = hierarchy_structure
    num_shares_available = 0
    for ii, sub_hierarchy in enumerate(hierarchy):
        if isinstance(sub_hierarchy, str):
            if shares[sub_hierarchy] != '':
                num_shares_available += 1
        elif secret_is_recoverable(shares, sub_hierarchy):
            num_shares_available += 1

    return num_shares_available > n


def bytes_to_hex(bytes):
    '''
    convert a utf-8 string to hexidecimal without the 0x prefix
    '''

    bytes = bytes.encode('utf-8')

    return ''.join('{:x}'.format(b) for b in bytes)


def hex_to_utf8(in_hex):
    '''
    convert hexidecimal without the 0x prefix to a utf-8  string
    '''

    n = int(in_hex, 16)
    bytes_ints = []
    while n:
        n, r = divmod(n, 256)
        bytes_ints.append(r)

    return bytes(bytes_ints[::-1]).decode('utf-8')


def hex_ssss_encrypt(n, m, hex_secret):
    '''
    takes a secret in hexidecimal, and converts it into m shares where only n
    of the m shares are required to recover hex_secret, the secret in
    hexidecimal.
    '''

    assert n <= m
    assert n > 0
    assert m > 0

    try:
        int(hex_secret, 16)
    except ValueError:
        print('not a valid hexidecimal value.')
    # There's no need to encrypt if only one of m needs to provide the share
    if n == 1:
        shares = [hex_secret] * m
    else:
        shares = SecretSharer.split_secret(hex_secret, n, m)
    # SecretSharer prepends numbering, and you can only return raw hex values.
    return [x[2:] for x in shares]


def recursive_ss_encrypt_hex(hex_to_encrypt, hierarchy_structure):
    '''
    This function takes in the hex_to_encrypt which is the secret you want
    to encrypt such that the hierarchy_structure provided is required for
    collecting the shared secrets to recover the initial secret
    hex_to_encrypt.

    This returns a dictionary of people and their associated shares to
    distribute to each that they will need to provide for recovering the
    secret represented in hexidecimal as hex_to_encrypt.
    '''

    assigned_shares = dict()
    n, m, hierarchy = hierarchy_structure
    shares = hex_ssss_encrypt(n, m, hex_to_encrypt)

    for ii, sub_hierarchy in enumerate(hierarchy):
        if isinstance(sub_hierarchy, str):
            assigned_shares[sub_hierarchy] = shares[ii]
        else:
            sub_shares = recursive_ss_encrypt_hex(shares[ii], sub_hierarchy)
            assigned_shares.update(sub_shares)
    return assigned_shares


def hierarchical_secret_share_encrypt(string_to_encrypt, hierarchy_structure):

    '''
    Generate hierarchical secret shares after checking if hierarchy_structure
    is well defined.
    '''

    try:
        well_def, _ = is_well_defined_hierarchy(hierarchy_structure)
        assert well_def
        # can't have parent of hierarchy_structure be 1 out of a group.
        if hierarchy_structure[0] <= 1 or isinstance(hierarchy_structure, str):
            raise AssertionError
    except AssertionError:
        print('hierarchy structure of encryption scheme is not well defined!')

    hex_secret = bytes_to_hex(string_to_encrypt)

    return recursive_ss_encrypt_hex(hex_secret, hierarchy_structure)


def hex_ssss_decrypt(in_shares):
    '''
    takes shares in hexidecimal without the 0x prefix, and recovers the secret
    in hexidecimal without the 0x prefix.
    '''

    try:
        for hex_val in in_shares:
            int(hex_val, 16)
    except ValueError:
        print('not a valid hexidecimal value.')
    # SecretSharer requires prepended numbering
    shares = [str(ii + 1) + '-' + x for ii, x in enumerate(in_shares)]

    return SecretSharer.recover_secret(shares)


def recover_secret_ss_hex(user_shares, hierarchy_structure):
    '''
    user_shares is a dict of shares with {user_name: secret_share, ...}. The
    user_names should match the strings of users in the hierarchy_structure.
    '''

    n, m, hierarchy = hierarchy_structure
    recovery_shares = list()
    user_names = user_shares.keys()

    for ii, sub_hierarchy in enumerate(hierarchy):
        if isinstance(sub_hierarchy, str):
            if sub_hierarchy in user_names:
                recovery_shares.append(user_shares[sub_hierarchy])
        else:
            recovery_sub_shares = recover_secret_ss_hex(user_shares,
                                                        sub_hierarchy)
            recovery_shares.extend(recovery_sub_shares)

    # if only one share is required to recover, then that is the result
    if n == 1:
        return user_shares[0]
    else:
        return hex_ssss_decrypt(recovery_shares)


def recover_secret_hierarchical_ss(shares, hierarchy_structure):
    '''
    Recover a secret from a sufficient list of shares that were created
    according to the associated hierarchy_structure.

    This returns the original secret.
    '''

    try:
        well_def, _ = is_well_defined_hierarchy(hierarchy_structure)
        assert well_def
        assert secret_is_recoverable(shares, hierarchy_structure)
    except AssertionError:
        print('hierarchy structure of encryption scheme is not well defined!')

    set_trace()
    hex_secret = recover_secret_ss_hex(shares, hierarchy_structure)
    return hex_to_utf8(hex_secret)


def hierarchical_ssss_to_files(string_to_encrypt, hierarchy_structure):
    '''
    Takes a string intended to be secret, string_to_encrypt, and generates
    secret shares that follow the given hierarchy structure in the
    hierarchy_structure tuple you provide. Then the shares are saved in files
    that are intended to be distributed by the user to those defined in the
    hierarchy_structure.
    '''
    shares = hierarchical_secret_share_encrypt(string_to_encrypt,
                                               hierarchy_structure)
    with open('Required_hierarchy_structure.txt', 'w') as f:
        f.write("Use the share files for the individuals that satisfy the " +
                "following hierarchy structure to recover the secret\n\n")
        f.write(str(hierarchy_structure))

    for user_name in shares:
        with open(user_name + '_Secret_Share.txt', 'wb') as f:
            pickle.dump((user_name, shares[user_name], hierarchy_structure), f)


def recover_secret_from_files(file_paths_list):
    '''
    Takes a list of paths to secret share files created to originally encrypt a
    secret put in file_paths_list which must be sufficient shares to recover
    the secret as specified in the hierarchy_structure defined when the shares
    were created.

    This returns the original secret.
    '''
    shares = dict()
    for file_nm in file_paths_list:
        with open(file_nm, "rb") as f:
            u_name, share, hierarchy_structure = pickle.load(f)
        shares[u_name] = share
    secret = recover_secret_hierarchical_ss(shares, hierarchy_structure)
    return secret
