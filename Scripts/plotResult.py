from pyvis.network import Network
import pandas as pd
def plotResult(file_in, file_out):
    got_net = Network(height="100%", width="100%", bgcolor="white", font_color="black")

    got_net.barnes_hut()
    got_data = pd.read_csv(file_in)

    sources = got_data['From']
    targets = got_data['To']
    weights = got_data['Weight']
    x_array = got_data['x']
    y_array = got_data['y']
    highlight = got_data['Highlight']

    edge_data = zip(sources, targets, weights, x_array, y_array, highlight)

    for e in edge_data:
        src = e[0]
        dst = e[1]
        w = e[2]
        x_array = e[3]
        y_array = e[4]
        h = e[5]
        v_color_dst = "#ADFF2F" #Green color
        image_url = 'cat.png'
        v_shape = 'dot'




        if(dst in ['central_concentrator'] or h==1):
            image_url = 'cat.png'
            v_shape = 'circle'


        got_net.add_node(src, shape = v_shape, title=src, x=x_array, y=y_array, color = "#ADFF2F") #Green color
        got_net.add_node(dst, shape = v_shape, title=dst, x = x_array, y = y_array, color = v_color_dst)
        got_net.add_edge(src, dst, value=h)

    neighbor_map = got_net.get_adj_list()

    # add neighbor data to node hover data
    for node in got_net.nodes:
        node["title"] += " Neighbors:<br>" + "<br>".join(neighbor_map[node["id"]])
        node["value"] = len(neighbor_map[node["id"]])




    got_net.set_options('var options = { "edges": { "arrows": { "middle": { "enabled": true } }, "color": { "inherit": "false"}, "smooth": false},"physics": {"enabled": true, "forceAtlas2Based":{  "gravitationalConstant": -500, "springLength": 100, "avoidOverlap": 1}, "minVelocity": 0.75, "solver": "forceAtlas2Based"}}')


    got_net.show(file_out)
