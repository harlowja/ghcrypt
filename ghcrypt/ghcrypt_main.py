import argparse
import base64
import functools
import getpass
import os

from github3 import enterprise_login as e_login
from github3 import login

import munch
import six
import yaml

from six.moves import configparser
from six.moves.urllib.parse import urlparse

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

import cryptography.hazmat.backends.openssl.backend as openssl_backend

OK_KEY_TYPES = tuple(['ssh-rsa', 'ssh-dsa'])

if six.PY3:
    raw_input = input


def pick_key(keys, user):
    while True:
        print("Please select which public key of %s to use:" % user)
        for i, k in enumerate(keys):
            print("  %s. %s [%s]" % (i + 1, k.value, k.kind))
        tmp_idx = raw_input("Which one do you want to use? ")
        idx = tmp_idx.strip()
        if not idx:
            idx = -1
        try:
            idx = int(idx)
        except ValueError:
            idx = -1
        if idx <= 0 or idx > len(keys):
            print("Invalid selection, try again.")
            continue
        return idx - 1


def find_conf():
    maybes = [
        os.path.join(os.getcwd(), 'ghcrypt.ini'),
        os.path.expanduser("~/.ghcrypt.ini"),
        "/etc/ghcrypt/ghcrypt.ini",
    ]
    for f in maybes:
        if os.path.isfile(f):
            return f
    return None


def find_default_private_key():
    maybes = [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.ssh/id_dsa"),
        '/root/.ssh/id_rsa',
        '/root/.ssh/id_dsa',
    ]
    for f in maybes:
        if os.path.isfile(f):
            return f
    return None


def encrypt_ssh(prefix, blob, user_key):
    # See: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    real_user_key_value = user_key.value
    if not real_user_key_value.startswith(prefix):
        real_user_key_value = prefix + " " + real_user_key_value
    pub_key = serialization.load_ssh_public_key(real_user_key_value,
                                                openssl_backend)
    if not isinstance(blob, six.binary_type):
        blob = blob.encode("utf8")
    raw = pub_key.encrypt(
        blob, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                           algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(raw)


def encrypt(parser, args):
    if not args.config or not os.path.isfile(args.config):
        parser.error("Unable to find any valid"
                     " configuration file. Please provide one.")
    user_keys = []
    cfg = configparser.RawConfigParser()
    with open(args.config, 'r') as fh:
        cfg.readfp(fh, fh.name)
    sect = args.section
    sect_kind = cfg.get(sect, 'kind')
    if sect_kind == 'file':
        source = cfg.get(sect, 'path')
        if source.startswith("file://"):
            source = source[len("file://"):]
        source = os.path.expanduser(source)
        with open(source, 'rb') as fh:
            keys = yaml.safe_load(fh.read())
            keys = munch.munchify(keys)
        user_keys = []
        for k in keys:
            if k.user == args.user and k.kind == args.kind:
                user_keys.append(k)
    elif sect_kind == 'github':
        try:
            gh_enterprise = cfg.getboolean(sect, 'enterprise')
        except configparser.NoOptionError:
            gh_enterprise = False
        if gh_enterprise:
            hub_base_url = cfg.get(sect, 'base_url')
            if (not (hub_base_url.startswith("http://") or
                     hub_base_url.startswith("https://"))):
                hub_base_url = 'https://' + hub_base_url
            hub_base = urlparse(hub_base_url).netloc
        else:
            hub_base = 'github.com'
        try:
            gh_user = cfg.get(sect, 'user')
        except configparser.NoOptionError:
            gh_user = raw_input("Your [%s] user: " % hub_base)
        gh_pass = getpass.getpass("Your [%s] personal access"
                                  " token (or password): " % hub_base)
        if gh_enterprise:
            gh = e_login(username=gh_user, password=gh_pass, url=hub_base_url)
        else:
            gh = login(username=gh_user, password=gh_pass)
        user = gh.user(args.user)
        if user:
            for uk in user.keys():
                k = uk.key
                if k:
                    kind, v = k.split()
                    if kind not in OK_KEY_TYPES:
                        continue
                    if kind == args.kind:
                        user_keys.append(munch.Munch({
                            'kind': kind,
                            'value': v,
                        }))
    else:
        raise RuntimeError("Unknown section"
                           " '%s' kind '%s'" % (sect, sect_kind))
    if not user_keys:
        raise RuntimeError("Can not find any keys"
                           " for user '%s' with"
                           " kind '%s'" % (args.user, args.kind))
    if len(user_keys) > 1:
        user_key = user_keys[pick_key(user_keys, args.user)]
    else:
        user_key = user_keys[0]
    encryptor_func = functools.partial(encrypt_ssh, user_key.kind)
    blob = getpass.getpass("Value to encrypt: ")
    print("Copy and paste the following and"
          " send it (via some mechanism) to '%s':" % args.user)
    print(encryptor_func(blob, user_key))


def decrypt(parser, args):
    if not args.private_key or not os.path.isfile(args.private_key):
        parser.error("Unable to find any valid private"
                     " key. Please provide one.")
    if args.prompt_password:
        password = getpass.getpass("Private key password: ")
    else:
        password = None
    with open(args.private_key, "rb") as fh:
        private_key = serialization.load_pem_private_key(
            fh.read(), password=password,
            backend=openssl_backend)
    blob = raw_input("Value to decrypt: ")
    if not isinstance(blob, six.binary_type):
        blob = blob.encode("utf8")
    blob = base64.b64decode(blob)
    print("The secret you received is:")
    print(
        private_key.decrypt(
            blob,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )))


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-c", "--config",
                        help="ghcrypt configuration"
                             " file (default=%(default)s)",
                        default=find_conf())

    subparsers = parser.add_subparsers(help='sub-command help')

    parser_enc = subparsers.add_parser('encrypt', help='encrypt help')
    parser_enc.add_argument("-s", "--section",
                            help=("section name in ghcrypt configuration"
                                  " defining source of"
                                  " public keys (default=%(default)s)"),
                            default="DEFAULT")
    parser_enc.add_argument("-u", "--user",
                            help="user name of public key owner",
                            required=True)
    parser_enc.add_argument("--kind",
                            help="key kind to select (default=%(default)s)",
                            default='ssh-rsa', metavar='KEY_TYPE')
    parser_enc.set_defaults(func=encrypt)

    parser_dec = subparsers.add_parser('decrypt', help='decrypt help')
    parser_dec.add_argument("--private-key",
                            help="private key file to use for decrypting"
                                 " (default=%(default)s)",
                            default=find_default_private_key(),
                            metavar='FILE')
    parser_dec.add_argument("--prompt-password",
                            help="prompt for private key password",
                            default=False, action='store_true')

    parser_dec.set_defaults(func=decrypt)

    args = parser.parse_args()

    if hasattr(args, 'func'):
        args.func(parser, args)


if __name__ == '__main__':
    main()
