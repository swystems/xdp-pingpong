import sys
import matplotlib.pyplot as plt

def main():
    if len(sys.argv) < 2:
        print("Provide a file with the values to plot")
        return

    filename = sys.argv[1]
    yvals = []
    with open(filename, 'r') as file:
        while 1:
            line = file.readline()
            if not line:
                break

            if float(line) < 1000000:
                yvals.append(float(line))
    xvals = list(range(1, len(yvals)+1))
    plt.scatter(xvals, yvals, s=4)
    plt.show()

if __name__ == "__main__":
    main()
