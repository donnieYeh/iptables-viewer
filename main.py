from graphviz import Digraph
from parser import *

# 定义Graphviz绘图类
class IptablesVisualizer:
    def __init__(self, tables):
        self.tables = tables

    def generate_graph(self, output_file='iptables_graph', keyword: str | None = None, show_build_in=None):
        dot = Digraph(comment='Iptables Visualization', format='png')
        dot.attr(rankdir='LR')

        # 先收集全部边与节点，便于按关键字做联通子图过滤
        all_edges = []  # (src, dst, label)
        all_nodes = set()

        builtin_targets = {"ACCEPT", "DROP", "REJECT", "LOG", "RETURN", "MASQUERADE", "AUDIT", "CT"}

        def builtin_allowed(name: str) -> bool:
            upper = name.upper()
            if upper not in builtin_targets:
                return True  # 非内置，一律展示
            # show_build_in 语义：
            # - None: 隐藏所有内置
            # - "__ALL__": 展示所有内置
            # - set([...]): 仅展示集合内指定的内置
            if show_build_in is None:
                return False
            if show_build_in == "__ALL__":
                return True
            if isinstance(show_build_in, set):
                return upper in show_build_in
            return False

        for table, chains in self.tables.items():
            for chain in chains:
                if not builtin_allowed(chain.name):
                    continue
                chain_node_id = f'{table}_{chain.name}'
                all_nodes.add(chain_node_id)

                for rule in chain.rules:
                    if not builtin_allowed(rule.target):
                        continue
                    target_node_id = f'{table}_{rule.target}'
                    all_nodes.add(target_node_id)
                    # 构造最多三行标签：条件、注释、目标动作参数（以 "--> " 前缀）
                    parts = [
                        (rule.condition or '').strip(),
                        ('' if (rule.comment or '').strip() in ('', '[]') else (rule.comment or '').strip()),
                        ('' if not getattr(rule, 'target_params', None) or not rule.target_params.strip() else f"--> {rule.target_params.strip()}")
                    ]
                    edge_label = '\n'.join(p for p in parts if p)
                    all_edges.append((chain_node_id, target_node_id, edge_label, table, chain.name))

        # 关键字过滤：仅保留“与关键字在同一条有向链路上的节点”
        # = 命中节点 ∪ 其所有祖先（能到达命中）∪ 其所有子孙（命中能到达）
        keep_nodes = None  # None 表示不过滤；set() 表示过滤且为空
        if keyword:
            kw = keyword.lower()
            seed = {n for n in all_nodes if kw in n.lower()}
            if seed:
                # 正向与反向邻接
                fwd, rev = {}, {}
                for src, dst, _label, _table, _cname in all_edges:
                    fwd.setdefault(src, set()).add(dst)
                    rev.setdefault(dst, set()).add(src)

                # 祖先（反向回溯）
                ancestors = set(seed)
                q = list(seed)
                while q:
                    cur = q.pop()
                    for prev in rev.get(cur, ()):  # 直接前驱
                        if prev not in ancestors:
                            ancestors.add(prev)
                            q.append(prev)

                # 子孙（正向扩展）
                descendants = set(seed)
                q = list(seed)
                while q:
                    cur = q.pop()
                    for nxt in fwd.get(cur, ()):  # 直接后继
                        if nxt not in descendants:
                            descendants.add(nxt)
                            q.append(nxt)

                keep_nodes = ancestors | descendants
            else:
                keep_nodes = set()

        # 绘制：仅输出两端都在 keep_nodes 的边；节点按所属表分组
        # 为了维持原有布局，仍然逐表创建子图并放置链节点
        for table, chains in self.tables.items():
            sub = Digraph(name=f'cluster_{table}')
            sub.attr(label=table)
            sub.attr(style='filled', color='lightgrey')

            for chain in chains:
                if not builtin_allowed(chain.name):
                    continue
                chain_node_id = f'{table}_{chain.name}'
                if keep_nodes is None or chain_node_id in keep_nodes:
                    sub.node(chain_node_id, chain.name, shape='box')

            dot.subgraph(sub)

        for src, dst, label, _table, _cname in all_edges:
            if keep_nodes is None or (src in keep_nodes and dst in keep_nodes):
                dot.edge(src, dst, label=label)

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
    import argparse
    
    # 命令行参数：支持关键字过滤 -k/--keyword；内置节点显示控制 -S/--show-build-in
    argp = argparse.ArgumentParser(add_help=False)
    argp.add_argument('-k', '--keyword', dest='keyword', default=None)
    # -S 可选参数：
    #   - 不带值：展示所有内置
    #   - 带逗号分隔列表：只展示指定的内置（大小写不敏感，如: -S accept,reject）
    #   - 不提供 -S：隐藏所有内置
    argp.add_argument(
        '-S', '--show-build-in', dest='show_build_in', nargs='?', const='__ALL__', default=None,
        help='Show built-ins (ACCEPT,DROP,REJECT,LOG,RETURN,MASQUERADE,AUDIT,CT). Without value: show all; with comma list: only those; omit: hide all.')
    # 解析已知参数，保留兼容 stdin 输入文件路径
    args, _unknown = argp.parse_known_args()

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
    
    # 解析 -S 参数到内部表示
    builtin_set = None
    if args.show_build_in is None:
        builtin_set = None  # 隐藏所有内置
    elif args.show_build_in == '__ALL__':
        builtin_set = '__ALL__'  # 展示所有内置
    else:
        allowed = {s.strip().upper() for s in str(args.show_build_in).split(',') if s.strip()}
        # 仅保留合法内置名
        valid = {"ACCEPT", "DROP", "REJECT", "LOG", "RETURN", "MASQUERADE", "AUDIT", "CT"}
        builtin_set = allowed & valid

    # 可视化
    IptablesVisualizer(tables).generate_graph(keyword=args.keyword, show_build_in=builtin_set)
