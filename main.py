from graphviz import Digraph
from parser import *

# 定义Graphviz绘图类
class IptablesVisualizer:
    def __init__(self, tables):
        self.tables = tables

    def generate_graph(self, output_file='iptables_graph'):
        dot = Digraph(comment='Iptables Visualization', format='png')
        dot.attr(rankdir='LR')

        for table, chains in self.tables.items():
            with dot.subgraph(name=f'cluster_{table}') as sub:
                sub.attr(label=table)
                sub.attr(style='filled', color='lightgrey')

                for chain in chains:
                    if chain.name in ["ACCEPT", "DROP", "REJECT", "LOG", "RETURN", "MASQUERADE", "AUDIT","CT"]:
                        continue
                    chain_node_id = f'{table}_{chain.name}'
                    sub.node(chain_node_id, chain.name, shape='box')

                    for rule in chain.rules:
                        if rule.target in ["ACCEPT", "DROP", "REJECT", "LOG", "RETURN", "MASQUERADE", "AUDIT","CT"]:
                            continue
                        target_node_id = f'{table}_{rule.target}'
                        edge_label = f'{rule.condition}\n{rule.comment}'
                        dot.edge(chain_node_id, target_node_id, label=edge_label)

        # 渲染图像
        dot.render(output_file)
        print(f'Graph generated and saved as {output_file}.png')

# 示例代码，解析iptables-save并生成图形
if __name__ == "__main__":
    iptables_output = """
    # iptables-save output
    *raw
    :PREROUTING ACCEPT [0:0]
    :OUTPUT ACCEPT [0:0]
    :zone_VPN_helper - [0:0]
    :zone_lan_helper - [0:0]
    -A PREROUTING -i br-lan -m comment --comment "lan CT helper assignment" -j zone_lan_helper
    -A PREROUTING -i ipsec0 -m comment --comment "VPN CT helper assignment" -j zone_VPN_helper
    -A zone_VPN_helper -p tcp --dport 21 -m comment --comment "FTP passive connection tracking" -j CT
    """

    import sys
    import os
    
    # 获取用户输入的配置文件路径，默认为当前路径下的iptables-save.txt
    file_path = input("请输入iptables配置文件的路径（默认：iptables-save.txt）：").strip()
    if not file_path:
        file_path = 'iptables-save.txt'
    
    if not os.path.isfile(file_path):
        print(f"文件 '{file_path}' 不存在。")
        sys.exit(1)
    
    # 读取配置文件内容
    with open(file_path, 'r') as file:
        iptables_output = file.read()

    # 解析配置文件
    parser = IptablesParser(iptables_output)
    parser.parse()
    
    # 获取结构化数据
    tables = parser.get_tables()
    
    # 可视化
    IptablesVisualizer(tables).generate_graph()
