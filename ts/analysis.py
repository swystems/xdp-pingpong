import sys

def next(*files):
    res = []
    for file in files:
        line = file.readline()
        if line:
            res.append(int(line))
        else:
            res.append(0)
    return res

def _open(*files):
    return tuple(map(lambda filename: open(filename, 'r'), files))

def _close(*files):
    for file in files:
        file.close()

def main():
    if len(sys.argv) < 5:
        print("Provide filenames for: timestamp 1, timestamp 2, timestamp 3, timestamp 4")
        return
    ts1, ts2, ts3, ts4 = _open(*sys.argv[1:])
    out = open("res.out", "w")
    ok = True
    while ok:
        t1, t2, t3, t4 = next(ts1,ts2,ts3,ts4)
        if t1 == 0 or t2 == 0 or t3 == 0 or t4 == 0:
            ok = False
            break
        diff1 = t4-t1
        diff2 = t3-t2
        res = (max(diff1, diff2) - min(diff1, diff2))/2
        out.write(f"{res}\n")
    _close(ts1,ts2,ts3,ts4,out)

if __name__ == "__main__":
    main()
