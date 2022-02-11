#initialize dependencies
import argparse
import json
import random
import trivium
import networkx as nx

# returns a random value between 1-10 (not true random)
def rand_scores():
    return random.randint(1,10)

# helper function to retrieve a list of nodes
def get_nodes(model_name, diagram_name):
    # set allowed types
    #todo: why does this break properties? -> no field -> separate dictlist for start/end
    ALLOWED_NODE_TYPES = ['td.cyber.node'] #, 'td.cyber.database', 'td.systems.actor']
    # ALLOWED_EDGE_TYPES = ['td.edge']

    # set params
    params = {
            "custom.isNetworkDiagram" : "true"
    }

    diagrams = trivium.api.element.get(model_name, element=diagram_name)
    ids = list(diagrams["custom"]["diagramContents"].keys())
    params = {'ids' : ','.join(ids)}
    elements = trivium.api.element.get(model_name, params=params)
    nodes = [e for e in elements if e['type'] in ALLOWED_NODE_TYPES]
    return nodes

def get_edges(model_name, diagram_name):
    ALLOWED_NODE_TYPES = ['td.cyber.node'] #, 'td.cyber.database', 'td.systems.actor']
    ALLOWED_EDGE_TYPES = ['td.edge']

    # set params
    params = {
            "custom.isNetworkDiagram" : "true"
    }

    diagrams = trivium.api.element.get(model_name, element=diagram_name)
    ids = list(diagrams["custom"]["diagramContents"].keys())
    params = {'ids' : ','.join(ids)}
    elements = trivium.api.element.get(model_name, params=params)
    nodes = [e for e in elements if e['type'] in ALLOWED_NODE_TYPES]
    node_ids = [e['id'] for e in nodes]
    edges = [e for e in elements if e['type'] in ALLOWED_EDGE_TYPES and e['source'] in node_ids and e['target'] in node_ids]
    return edges

# Output networkX graph object with properties of IP and distill_score / 
def create_graph(nodelist, edgelist):
    G = nx.Graph()

    for i in range(len(nodelist)):
        G.add_node(nodelist[i]['id'], ip=nodelist[i]['ip'], distill_score=nodelist[i]['score'])

    for i in range(len(edgelist)):
        G.add_edge(edgelist[i]['source'], edgelist[i]['target'], id=edgelist[i]['id'])
    
    return G
    
def main():
    # initialize parser
    parser = argparse.ArgumentParser()

    # display landing screen for command-line tool
    parser.add_argument("-m", "--model", type=str, help="Model Name", required=True)
    parser.add_argument("-d", "--diagram", type=str, help="Diagram Name", required=True)
    parser.add_argument("-n", "--nessus", nargs='+', type=str, help="Nessus Files", required=True)
    args = parser.parse_args()

    # initialization from user's command-line input
    model = args.model
    diagram = args.diagram

    # retrieve nodes and edges from user's Trivium diagram
    nodes = get_nodes(model, diagram)
    edges = get_edges(model, diagram)

    # contains ids for only the nodes
    node_ids = [ e['id'] for e in nodes]
    # contains ids for only the edges
    edge_ids = [ e['id'] for e in edges]

    # parses through trivium and pulls the node/IP Address from properties.
    custom = [ e['custom'] for e in nodes]
    # print(json.dumps(custom, indent=4))
    prop = [ e['properties'] for e in custom]
    ip = [ e['ip'] for e in prop]
    ip_val = [ e['value'] for e in ip]

    # parses through trivium and pulls the edge/source/target from properties.
    source = [ e['source'] for e in edges]
    target = [ e['target'] for e in edges]

    # creates an arraylist of dictionaries with node_id as the key and IP Address/Distill score as values
    dictlist_nodes = [dict() for x in range(len(node_ids))]
    dictlist_edges = [dict() for x in range(len(edge_ids))]

    # todo: add another dictionary for start/end nodes
    # prints the contents of the previously created arraylist of dictionaries
    for i in range(len(node_ids)):
        dictlist_nodes[i] = {'id':node_ids[i], 'ip':ip_val[i], 'score':rand_scores()}

    for i in range(len(edge_ids)):
        dictlist_edges[i] = {'id':edge_ids[i], 'source':source[i], 'target':target[i]}

    print(json.dumps(nx.readwrite.node_link_data(create_graph(dictlist_nodes, dictlist_edges)), indent=4))
    print(create_graph(dictlist_nodes, dictlist_edges))