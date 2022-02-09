import argparse
import json
import trivium

def main():
    # initialize parser
    parser = argparse.ArgumentParser()

    # display landing screen for command-line tool
    parser.add_argument("-m", "--model", type=str, help="Model Name", required=True)
    parser.add_argument("-d", "--diagram", type=str, help="Diagram Name", required=True)
    parser.add_argument("-n", "--nessus", nargs='+', type=str, help="Nessus Files", required=True)

    args = parser.parse_args()

    if args.model and args.diagram and args.nessus:
        print('Perform and Output Nessus Scan of the desired Network model.')

    elif args.model and args.diagram:
        model_name = args.model_name
        diagram_name = args.diagram_name
        
        ALLOWED_NODE_TYPES = ['td.cyber.node', 'td.cyber.database', 'td.model.block', 'td.cyber.lan', 'td.systems.actor']
        ALLOWED_EDGE_TYPES = ['td.edge']

        params = {
            "custom.isNetworkDiagram" : "true"
        }

        diagrams = trivium.api.element.get(model_name, element=diagram_name)
        ids = list(diagrams["custom"]["diagramContents"].keys())
        print(json.dumps(diagrams,indent=4))