#!/usr/bin/env python
import functools
from base64 import b64encode
from multiprocessing import Process, cpu_count, Value
from string import ascii_uppercase, ascii_lowercase, digits

from nacl.public import PrivateKey

### Vars.
# parallel worker count. setting it to a value higher than cpu_count - 1 will cause system to be very unresponsive.
workerCount = 0

# target string to iterate for.
targetString = "test"

# do you want it to start with your target? if False, anywhere in the key will hit.
# warning: keeping this True will result in a longer computation time.
_startsWith = True

# The amount of keys to be generated before the script exits.
targetAmount = 5


### End of vars.


def keygen():
    private = PrivateKey.generate()
    return (
        b64encode(bytes(private)).decode("ascii"),
        b64encode(bytes(private.public_key)).decode("ascii"),
    )


def generate_keys(counter, matchfunc):
    while True:
        private, public = keygen()
        if matchfunc(public.lower()):
            with counter.get_lock():
                counter.value += 1
                print(
                    f"[{counter.value}]\tPrivate: {private}\t|\tPublic: {public}"
                )


def create_workers(worker_count, counter, matchfunc):
    targetfunc = functools.partial(generate_keys, matchfunc=matchfunc)
    for index in range(worker_count):
        x = Process(target=targetfunc, args=(counter,), daemon=True)
        x.start()


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


def main():
    sanity_check(targetString)
    counter = Value("h", 0)
    wc = workerCount if workerCount else cpu_count() - 1

    targetstring = targetString.lower()
    if _startsWith:
        def matchfunc(str_):
            return str_.lower().startswith(targetstring)
    else:
        def matchfunc(str_):
            return targetstring in str_.lower()

    create_workers(wc, counter, matchfunc)
    print(
        f"\n{wc} thread(s) started in search for {targetString},"
        f" {'in the beginning of keys' if _startsWith else 'in the keys'}.\n"
    )

    while counter.value < targetAmount:
        pass


if __name__ == "__main__":
    main()
