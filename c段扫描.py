import socket
import sys

def parse_ip_range(ip):
    """
    将传入的ip进行处理，传入有两种情况：
    1. 192.168.10.10 返回base_ip:192.168.10 start=end:10
    2. 192.168.10.10-20 返回base_ip:192.168.10 start:10 end:20
    """

    # 将ip以点分割为列表
    parts = ip.split('.')
    # 判断是否为正确IP
    if len(parts) != 4:
        print("请输入正确的IP")
        return False

    # 取base_ip
    base_ip = ".".join(parts[:3])
    # 取c段值
    range_part = parts[3]
    print(f'开始扫描:{base_ip}.{range_part}中{range_part}段的存活ip')

    # 判断是否为范围地址
    if '-' in range_part:
        start_str, end_str = range_part.split('-')
        start = int(start_str)
        end = int(end_str)
    # 如果是单个地址
    else:
        start = end = int(range_part)

    # 判断地址是否合法
    if not (0 <= start <= 254 and 0 <= end <= 254 and start <= end):
        print("IP地址必须在0-254之间 且开始值小于等于结束值")
        return False

    return base_ip, start, end


def scan_port(ip,ports,timeout=2):
    open_ports = []
    for i in ports:
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, i))
            open_ports.append(i)
        except socket.timeout:
            print(f"连接{ip}:{i}超时")
        except socket.error as e:
            print(f"连接 {ip}:{i} 时发生错误: {e}")
        finally:
            s.close()
    return open_ports

def scan_ip_range(ip,ports,timeout):
    scan_results = {}
    base_ip,start,end = parse_ip_range(ip)
    for i in range(start,end + 1):
        ip = f"{base_ip}.{i}"
        open_port = scan_port(ip,ports,timeout)
        if open_port:
            scan_results[ip] = open_port
        else:
            print("未开放")
    return scan_results




# 程序开始
# 判断命令框输入参数是否达到要求，如没有，则返回提示，并正常退出程序
if len(sys.argv) != 3:
    print("请合法输入：python c段扫描.py 1.1.1.1-154 80,8080")
    sys.exit(1)

# 将ip和端口提取出来，方便后续处理
ip_range_str = sys.argv[1]
ports = [int(i) for i in sys.argv[2].split(',')]

res = scan_ip_range(ip_range_str,ports,2)

for ip,open_port in res.items():
    print(f'发现结果：\n{ip},{open_port}')