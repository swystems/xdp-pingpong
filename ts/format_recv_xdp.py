import sys
import os

def compute_latency(ts_list):
    # ts[0] is round number
    return (( float(ts_list[4]) - float(ts_list[1])) - (float(ts_list[3]) - float(ts_list[2])))/2

def format(path):
    _, filename = os.path.split(path)
    infile = open(path, 'r')
    tsfile = open(f"./ts.out", 'w')
    latfile = open(f"./lat.out", 'w')
    
    while 1:
        line = infile.readline()
        if not line:
            break

        
        l = line.split(":")

        if len(l) > 1: #filter first 2 warning lines
            csv_list = l[1][2:-3] # remove space and brackets
            tsfile.write(f"{csv_list}\n");
            latfile.write(f"{compute_latency(csv_list.split(','))}\n")


def main():
    for fname in sys.argv[1:]:
        format(fname)


if __name__ == "__main__":
    if len(sys.argv) == 0:
        print("A filename is required as a first argument")
    else:
        main()
