import re
from collections import defaultdict

# 定义表的枚举
class Table:
    FILTER = 'filter'
    NAT = 'nat'
    MANGLE = 'mangle'
    RAW = 'raw'

# 定义ReferenceChain类
class ReferenceChain:
    def __init__(self, target, protocol, opt, source, destination, comment, condition):
        self.target = target  # 目标链
        self.protocol = protocol  # 协议
        self.opt = opt  # 选项
        self.source = source  # 源地址
        self.destination = destination  # 目标地址
        self.comment = comment  # 注释
        self.condition = condition  # 条件

    def __repr__(self):
        return (f"ReferenceChain(target={self.target}, protocol={self.protocol}, "
                f"opt={self.opt}, source={self.source}, destination={self.destination}, "
                f"comment={self.comment}, condition={self.condition})")

# 定义Chain类
class Chain:
    def __init__(self, name, belong):
        self.name = name  # 链的名字
        self.belong = belong  # 所属表
        self.rules = []  # 引用链的规则

    def add_rule(self, ref_chain):
        """添加规则到链中"""
        self.rules.append(ref_chain)

    def __repr__(self):
        return f"Chain(name={self.name}, belong={self.belong}, rules={self.rules})"

# 定义一个解析器来处理iptables-save的输出
class IptablesParser:
    def __init__(self, iptables_output):
        self.iptables_output = iptables_output.splitlines()
        self.tables = defaultdict(list)  # 存储表和对应的链
        self.chains = {}  # 存储属于表+链名唯一标识的所有链

    def parse(self):
        chain_re = re.compile(r'^:([A-Za-z0-9_]+)')  # 匹配链的正则表达式
        rule_re = re.compile(r'^-A (\S+) (.+?) -j (\S+)(.*)')  # 匹配规则的正则表达式

        current_table = None

        for line in self.iptables_output:
            line = line.strip()
            if line.startswith('*'):  # 表的定义
                current_table = line[1:]
            elif line.startswith(':'):  # 链的定义
                match = chain_re.match(line)
                if match:
                    chain_name = match.group(1)
                    self.add_chain(chain_name, current_table)
            elif line.startswith('-A'):  # 链的规则
                match = rule_re.match(line)
                if match:
                    chain_name, rule_details, target, rest = match.groups()
                    protocol, opt, source, destination, comment, condition = self.extract_rule_details(rule_details + rest)
                    ref_chain = ReferenceChain(target, protocol, opt, source, destination, comment, condition)

                    # 使用完整的链名作为键来添加规则
                    full_chain_key = f'{current_table}_{chain_name}'
                    if full_chain_key in self.chains:
                        self.chains[full_chain_key].add_rule(ref_chain)

                    # 确保目标链存在
                    full_target_key = f'{current_table}_{target}'
                    if full_target_key not in self.chains:
                        self.add_chain(target, current_table)

    def add_chain(self, chain_name, table):
        """添加链到表，如果链已存在，则不覆盖它的table和name，只更新它的规则"""
        chain_key = f'{table}_{chain_name}'
        if chain_key not in self.chains:
            new_chain = Chain(chain_name, table)
            self.chains[chain_key] = new_chain
            self.tables[table].append(new_chain)

    def extract_rule_details(self, rule_details):
        """
        提取规则详情中的协议、选项、源、目标、注释和条件。
        """
        protocol = "any"
        opt = ""
        source = "anywhere"
        destination = "anywhere"
        comment = ""
        condition = ""

        # 提取注释
        comment_match = re.search(r'--comment\s+"([^"]*)"', rule_details)
        if comment_match:
            comment = comment_match.group(1)
            # 去除注释部分，以便正确提取其他字段
            rule_details = re.sub(r'--comment\s+"[^"]*"', '', rule_details).strip()

        # 提取协议（通常是 -p <protocol>）
        protocol_match = re.search(r'-p (\S+)', rule_details)
        if protocol_match:
            protocol = protocol_match.group(1)

        # 提取源地址（通常是 -s <source>）
        source_match = re.search(r'-s (\S+)', rule_details)
        if source_match:
            source = source_match.group(1)

        # 提取目标地址（通常是 -d <destination>）
        destination_match = re.search(r'-d (\S+)', rule_details)
        if destination_match:
            destination = destination_match.group(1)

        # 提取条件（包括所有非注释部分）
        # 条件包括 -m 模块及其参数，除了注释外的所有内容都算作条件
        condition_match = re.search(r'-m (\S+)(.*?)\s*(-j|\Z)', rule_details)
        if condition_match:
            condition = condition_match.group(2).strip()

        # 如果条件为空，将剩余的规则部分作为条件
        if not condition:
            condition = rule_details.strip()

        return protocol, opt, source, destination, comment, condition

    def get_tables(self):
        return self.tables
        
    def print_structure(self):
        # 打印解析后的结构
        for table, chains in self.tables.items():
            print(f"Table: {table}")
            for chain in chains:
                print(f"  Chain: {chain.name}")
                for rule in chain.rules:
                    print(f"    Rule: {rule}")

# 示例代码，解析iptables-save并打印结构化数据
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

    parser = IptablesParser(iptables_output)
    parser.parse()
    parser.print_structure()
