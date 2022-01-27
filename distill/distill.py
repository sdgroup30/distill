#!/usr/bin/env python3

def getopts(argv):
    opts = {}  # Empty dictionary to store key-value pairs.
    while argv:  # While there are arguments left to parse...
        if argv[0][0] == '-':  # Found a "-name value" pair.
            opts[argv[0]] = argv[1]  # Add key and value to the dictionary.
        argv = argv[1:]  # Reduce the argument list by copying it starting from index 1.
    return opts

def help():
    print("List of commands: \n")
    print("Distill -m \'model\' -d \'diagram\':\n")
    print("Pulls down information regarding the network diagram that was inputted in 'model' and 'diagram'. \n")
    print("Distill -n \'list of files\':\n")
    print("Executes a Nessus Vulnerability Scan on the Devices gives in the list.\n")
    print("Distill -h: \n")
    print("Pulls up Help Menu\n")

if __name__ == '__main__':
    from sys import argv
    import json
    import os
    import trivium

    os.environ['TRV_API_KEY_ID'] = 'phenrickson1997@knights.ucf.edu'
    os.environ['TRV_API_SECRET'] = 'SeniorDesign1!'

    if len(argv) == 1:
        help()
        quit()
    elif argv[1] == '-h':
        help()
        quit()
    myargs = getopts(argv)
    if '-m' in myargs and '-d' in myargs:  # Example usage.
        ALLOWED_NODE_TYPES = ['td.cyber.node', 'td.cyber.database', 'td.model.block', 'td.cyber.lan', 'td.systems.actor']
        ALLOWED_EDGE_TYPES = ['td.edge']

        model = argv[2]

        params = {
            "custom.isNetworkDiagram" : "true"
        }

        # This doesn't find any elements if the params are passed in. 
        # diagrams = trivium.api.element.get(model, params=params)

        diagrams = trivium.api.element.get(model)
        diagrams = [e for e in diagrams if 'diagramContents' in e['custom']]
        print(json.dumps([e['custom'] for e in diagrams], indent=4))