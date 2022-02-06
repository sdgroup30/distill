import argparse
import json
import trivium

def main():
    parser = argparse.ArgumentParser(description='''Distill tool for Trivium\n
    Required Input: Distill -m -d [model_name] [diagram_name] --> pulls down network model\n
    Optional Input: Distill -m -d -n [model_name] [diagram_name] [nessus_list] --> performs and outputs Nessus Scan''', formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("-m", "--model", help="Model", action="store_true")
    parser.add_argument("model_name", type=str, help="Model ID")
    parser.add_argument("-d", "--diagram", help="Diagram in the Trivium model", action="store_true")
    parser.add_argument("diagram_name", type=str, help="Diagram ID")
    parser.add_argument("-n", "--nessus", help="Performs a nessus scan with a list of files containing IP addresses", action="store_true")
    parser.add_argument("nessus_list", nargs='?', type=str, help="List of Files containing IP addresses")
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