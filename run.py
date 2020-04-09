#!/usr/bin/env python
import functools
from base64 import b64encode
from multiprocessing import Pool, Process, cpu_count, Value, Queue
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


def create_workers_pool(worker_count, counter, stopafter, matchfunc, outputq):
    def init_globals(_counter, _matchfunc, _outputq):
        global counter
        counter = _counter
        global outputq
        outputq = _outputq
        global matchfunc
        matchfunc = _matchfunc

    func = functools.partial(
        generate_keys_pool, stopafter
    )
    with Pool(
        initializer=init_globals,
        initargs=(counter, matchfunc, outputq),
        processes=worker_count
    ) as pool:
        pool.map(func, range(worker_count))


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
    outputq = Queue()

    targetstring = targetString.lower()
    if _startsWith:

        def matchfunc(str_):
            return str_.startswith(targetstring)

    else:

        def matchfunc(str_):
            return targetstring in str_

    print(
        f"Starting {wc} workers in search for {targetString!r},"
        f" {'in the beginning of public keys' if _startsWith else 'in the public key'}.\n"
    )
    # create_workers(wc, counter, targetAmount, matchfunc, outputq)
    create_workers_pool(wc, counter, targetAmount, matchfunc, outputq)
    if outputq.empty():
        raise Exception("Error: No keys were found!")
    keys = []
    while not outputq.empty():
        keys.append(outputq.get())
    for _key in keys:
        print(_key)


if __name__ == "__main__":
    main()
