import readline

def input_loop():
    line = ''
    while line != 'stop':
        line = raw_input('Prompt ("stop" to quit): ')
        print 'User input is : %s' % line

# Prompt the user for text
input_loop()
