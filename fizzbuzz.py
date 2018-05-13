#!/usr/bin/python 

import argparse
import sys

# CS 352 Fizzbuzz Assignment Skeleton
#
# (c) 2018 R. P. Martin under the GPL version 2 license 

def main():
    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 FizzBuzz')
    parser.add_argument('-s','--start', help='Starting Value', required=True)
    parser.add_argument('-e','--end', help='Ending Value', required=True)

    # parse the input 
    args = vars(parser.parse_args())
    start = int(args['start'])
    end = int(args['end'])

    print("CS 352 fizzbuzz, start at %d, end at %d " % (start,end) )

    # For every number from the start to the end (inclusive):
    n = 0
    for i in range (start, end+1):
        if i % 15 == 0:
            print "FizzBuzz"
        elif i % 3 == 0:
            print "Fizz"
        elif i % 5 == 0:
            print "Buzz"
        else:
            print n
            n = n+i 
            
# create a main function in Python
if __name__ == "__main__":
    main()
