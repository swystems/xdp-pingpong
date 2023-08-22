import sys

CPU_NAME = "cpu1"

def format(filename):
    infile = open(filename, 'r')
    outfile = open(f"{filename}.out", 'w')

    while 1:
        line = infile.readline()
        if not line:
            break

        if CPU_NAME in line:
            _, value = line.split(":")
            value = int(value)
            outfile.write(f"{value}\n");


def main():
    for fname in sys.argv[1:]:
        format(fname)


if __name__ == "__main__":
    if len(sys.argv) == 0:
        print("A filename is required as a first argument")
    else:
        main()
