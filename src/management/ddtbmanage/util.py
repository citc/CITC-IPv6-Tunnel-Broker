#!/usr/bin/python
# -*- coding: utf-8 -*-

#
# Shamelessly taken from http://refactormycode.com/codes/1541-secure-password-generation-using-python#refactor_550196
#

# Import required modules
import random
import sys
import string

# Create a new class
class PasswordGenerator():
    # Define a char_table
    char_table = [1,2,3,4,5,6,7,8,9,0,'a','b','c','d','e','f',
                  'g','h','i','j','k','l','m','n','o','p','q',
                  'r','s','t','u','v','w','x','y','z','A','B',
                  'C','D','E','F','G','H','I','J','K','L','M',
                  'N','O','P','Q','R','S','T','U','V','W','X',
                 'Y','Z','!']

    # Define __init__ function for the class
    def __init__(self, password_length=6):
        # Randomize the char_table
        random.shuffle(self.char_table)

        # Check to see if we have a password_length defined
        if password_length < 6:
            self.password_length = 6
        else:
            self.password_length = password_length

    # Define our generate function for the class
    def generate(self):
        d = [random.choice(''.join(list( (set(string.ascii_letters) | set(string.digits)) - set( ('I', 'l')) ))) for x in xrange(self.password_length)]
        password = "".join(d)
        return password
                # set our counter to zero
#                count = 0

                # Define our local password variable as a list container
#                password = []

                # Generate the password
#                while count < self.password_length:
#                        count = count + 1
#                        password.append(str(self.char_table[random.randint(0, len(self.char_table) -1)]))

                # Return the generated password
#                return str("".join(password))


# For class testing purposes
if __name__ == "__main__":
    # Define a default length for the test
    length = 10

    # If we supplied an argument when executed this script use that value
    if len(sys.argv) > 1:
        if sys.argv[1].isdigit():
            length = int(sys.argv[1])

    # Fire away a test using the defined length above
    pg = PasswordGenerator(int(length))
    print "Generated an " + str(length) + " char password:\t" + pg.generate()

    # Try it with out a pre-defined length, should default to 6 chars
    pg = PasswordGenerator()
    print "Generated an 6 char password:\t" + pg.generate()
