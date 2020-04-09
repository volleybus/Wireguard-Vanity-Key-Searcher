#!/usr/bin/env python
"""
wgvanitykey -- generate Curve25519 sk/pk keypairs
and search for a given string in the base64 encoding of the public key

Usage::

    wgvanitykey -h
    wgvanitykey -c 1 test  # search for a pk that starts with 'test'
    wgvanitykey -c 1 test -m contains  # search for a pk that contains 'test'
"""
import functools
import logging
import sys
import unittest
from base64 import b64encode
from multiprocessing import Pool, Process, cpu_count, Value, Queue
from string import ascii_uppercase, ascii_lowercase, digits

from nacl.public import PrivateKey

version = "0.1.0"


def keygen():
    private = PrivateKey.generate()
    return (
        b64encode(bytes(private)).decode("ascii"),
        b64encode(bytes(private.public_key)).decode("ascii"),
    )


def generate_keys(counter, stopafter, matchfunc, outputq=None):
    while counter.value < stopafter:
        private, public = keygen()
        if matchfunc(public.lower()):
            with counter.get_lock():
                counter.value += 1
            outputstr = (
                f"[{counter.value}]\tPrivate: {private}\t|\tPublic: {public}"
            )
            print(outputstr)
            if outputq is not None:
                outputq.put(
                    dict(n=counter.value, private=private, public=public)
                )


def create_workers(worker_count, counter, stopafter, matchfunc, outputq):
    processes = [
        Process(
            target=generate_keys,
            args=(counter, stopafter, matchfunc, outputq),
            daemon=True,
        )
        for n in range(worker_count)
    ]
    for p in processes:
        p.start()
    for p in processes:
        p.join()


def generate_keys_pool(stopafter, worker_n):
    global counter
    global outputq
    global matchfunc
    return generate_keys(counter, stopafter, matchfunc, outputq)


def create_workers_pool(workercount, counter, stopafter, matchfunc, outputq):
    def init_globals(_counter, _matchfunc, _outputq):
        global counter
        counter = _counter
        global outputq
        outputq = _outputq
        global matchfunc
        matchfunc = _matchfunc

    func = functools.partial(generate_keys_pool, stopafter)
    with Pool(
        initializer=init_globals,
        initargs=(counter, matchfunc, outputq),
        processes=workercount,
    ) as pool:
        pool.map(func, range(workercount))


def sanity_check(target):
    lexicon = ascii_uppercase + ascii_lowercase + digits + "+/"
    if len(target) > 43:
        raise Exception("Target string is longer than 43 chars.")
    if target != "":
        for char in target:
            if char in lexicon:
                continue
            else:
                raise Exception(
                    "Target string must constitute of b64 alphabet."
                )
    else:
        raise Exception("Target string is empty.")


def wgvanitykey(targetstring, targetcount, matchfunc, workercount=None):
    """search for wireguard private/publickey combinations where
    ``publickey.lower().startswith(targetstring)``
    or ``targetstring in publickey.lower()``

    Arguments:
        targetstring (str): ...
        targetcount (str): ...
        matchfunc (callable): ...

    Keyword Arguments:
        workercount (str): ...

    Returns:
        list: list of {n:int, private:str, public:str} dicts

    Raises:
        Exception: "Error: No keys were found!"
    """
    sanity_check(targetstring)
    counter = Value("h", 0)
    outputq = Queue()
    workercount = workercount if workercount else cpu_count() - 1

    # create_workers(workercount, counter, targetAmount, matchfunc, outputq)
    create_workers_pool(workercount, counter, targetcount, matchfunc, outputq)
    if outputq.empty():
        raise Exception("Error: No keys were found!")
    keys = []
    while not outputq.empty():
        keys.append(outputq.get())
    return keys


def build_matchfunc(matchmethod, targetstring):
    if matchmethod == "startswith":
        matchdesc = "at the beginning of the public key"

        def matchfunc(str_):
            return str_.startswith(targetstring)

    elif matchmethod == "contains":
        matchdesc = "in the public key"

        def matchfunc(str_):
            return targetstring in str_

    else:
        matchdesc, matchfunc = None, None
    return matchdesc, matchfunc


class Test_wgvanitykey(unittest.TestCase):
    def test_wgvanitykey__startswith00(self):
        targetstring = "00"
        targetcount = 2
        sys.stdout.flush()
        _, matchfunc = build_matchfunc("startswith", targetstring)
        keys = wgvanitykey(targetstring, targetcount, matchfunc)
        assert keys[0]["public"].startswith(targetstring)

    def test_wgvanitykey__contains000(self):
        targetstring = "000"
        targetcount = 2
        sys.stdout.flush()
        _, matchfunc = build_matchfunc("contains", targetstring)
        keys = wgvanitykey(targetstring, targetcount, matchfunc)
        assert targetstring in keys[0]["public"]

    def test_wgvanitykey__main__targetcount_2(self):
        retval = main(["0", "--targetcount=2"])
        assert retval == 0

    def test_wgvanitykey__main__targetcount_2_contains(self):
        retval = main(["00", "--targetcount=2", "-m", "contains"])
        assert retval == 0


def main(argv=None):
    """
    wgvanitykey main() function

    Keyword Arguments:
        argv (list): commandline arguments (e.g. sys.argv[1:])
    Returns:
        int:
    """
    import optparse

    class OptionParser(optparse.OptionParser):
        def format_description(self, formatter):
            return self.expand_prog_name(
                self.description.replace("wgvanitykey", "%prog")
            )

    prs = OptionParser(
        usage="%prog [-c <n>] [-m <startswith|contains>] <string>",
        description=__doc__.lstrip(),
    )

    prs.add_option(
        "-c",
        "--targetcount",
        dest="targetcount",
        default=5,
        type="int",
        help="Generate this many keys before stopping (default: 5)",
    )
    prs.add_option(
        "-m",
        "--matchmethod",
        dest="matchmethod",
        default="startswith",
        type="string",
        help="Method for selecting keys: startswith | contains"
        " (default: startswith)",
    )
    prs.add_option(
        "-w",
        "--workercount",
        dest="workercount",
        default=cpu_count() - 1,
        type="int",
        help="Number of workers to run. Setting this to greater than "
        "the default cpu_count()-1 may cause the system to be unresponsive",
    )

    prs.add_option(
        "-v", "--verbose", dest="verbose", action="store_true",
    )
    prs.add_option(
        "-q", "--quiet", dest="quiet", action="store_true",
    )
    prs.add_option(
        "-t", "--test", dest="run_tests", action="store_true",
    )

    argv = list(argv) if argv else None
    (opts, args) = prs.parse_args(args=argv)
    loglevel = logging.INFO
    if opts.verbose:
        loglevel = logging.DEBUG
    elif opts.quiet:
        loglevel = logging.ERROR
    logging.basicConfig(level=loglevel)
    log = logging.getLogger("main")
    log.debug("argv: %r", argv)
    log.debug("opts: %r", opts)
    log.debug("args: %r", args)

    if opts.run_tests:
        sys.argv = [sys.argv[0]] + args
        return unittest.main()
        # return subprocess.call(['pytest', '-v'] + args)

    if not len(args):
        prs.print_help()
        prs.error("A string to search for must be specified")

    target_string = args[0]

    targetstring = target_string.lower()

    matchdesc, matchfunc = build_matchfunc(opts.matchmethod, targetstring)
    if matchdesc is None:
        prs.error("--matchmethod must be either 'startswith' or 'contains'")

    wc = opts.workercount if opts.workercount else cpu_count() - 1
    print(
        f"Starting {wc} workers to search for {opts.targetcount} "
        f"{'key pairs' if opts.targetcount > 1 else 'key pair'} "
        f"where {targetstring!r} is {matchdesc}.\n"
    )

    EX_OK = 0
    output = wgvanitykey(
        targetstring=targetstring,
        targetcount=opts.targetcount,
        matchfunc=matchfunc,
        workercount=opts.workercount,
    )
    for _key in output:
        log.debug(_key)
    return EX_OK


if __name__ == "__main__":
    sys.exit(main(argv=sys.argv[1:]))
