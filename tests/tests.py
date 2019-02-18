
import hierarchical_secret_sharing as hss


def file_names(in_names):
    return [x + '_Secret_Share.txt' for x in in_names]


secret_combos = [["put 1st secret here", "put 2nd secret here", "...etc"],
    ["site: somewebsite.com, username: johndoe, password: UbQFJB2jLhiud4X9",
     "L56KDn86uWDG5YrxdtDY3NRMrM4Ljvenow1VoaEgBR1ZzU6CGjgt"],
    ["hello"]
    ]


def check_encrypt_decrypt(secret_combos, hierarchy_structure, file_shares):
    '''
    Checks if each list of secrets in secret_combos given a hierarchy_structure
    and list of shares of files to recover secrets, recovers those secrets
    properly.
    '''
    for secrets in secret_combos:
        hss.hierarchical_ssss_to_files(secrets, hierarchy_structure)
        rec_secrets = hss.recover_secrets_from_files(file_shares)
        truth_val = rec_secrets == secrets
        if not(truth_val):
            return False
    return True


def test_deep_hierarchy():

    hierarchy_structure = (2, 3, ('CEO', 'CEO2',
                                (3, 5, ('CFO',
                                        'CTO',
                                        'COO',
                                        (1, 3, ('Liz', 'Alex', 'Ana')),
                                        (3, 3, ('Mike', 'Stephanie', 'Andy'))
                                        )
                                )
                                )
                        )

    file_share_combos = [file_names(['CEO2', 'CTO', 'Liz', 'CFO']),
                        file_names(['CEO', 'Ana', 'CTO', 'CFO']),
                        file_names(['CEO', 'Alex', 'CTO', 'CFO']),
                        file_names(['CEO', 'CEO2', 'Alex', 'Liz']),
                        file_names(['CEO', 'CEO2']),
                        file_names(['CEO', 'CTO', 'CFO', 'COO']),
                        file_names(['CEO2', 'Alex', 'CFO', 'Mike', 'Stephanie',
                                    'Andy'])]

    for combo in file_share_combos:
        assert check_encrypt_decrypt(secret_combos, hierarchy_structure, combo)


def test_shallow_hierarchy():
    hierarchy_structure = (2, 3, ('Nick', 'Alice', 'Bob'))

    file_share_combos = [file_names(['Nick', 'Alice', 'Bob']),
                         file_names(['Nick', 'Alice']),
                         file_names(['Bob', 'Alice'])]

    for combo in file_share_combos:
        assert check_encrypt_decrypt(secret_combos, hierarchy_structure, combo)
