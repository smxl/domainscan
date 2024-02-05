import socket
import threading
import time
import os
import sys
import platform

max_thread = 10
timeout = 2
socket.setdefaulttimeout(timeout)
sleep_time = 1

def clear():
    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def get_suffix_nic_whois():
    suffix_list = []
    with open('suffix_nic_whois', 'r') as file:
        for line in file:
            if not line.startswith('#'):
                suffix_list.append(line.strip().split('|'))
    return suffix_list

def whois_query(domain_name, suffix_info):
    retry = 3
    info = ''
    domain = domain_name + '.' + suffix_info[0]
    while not info and retry > 0:
        try:
            with socket.create_connection((suffix_info[1], 43), timeout) as sock:
                sock.send(f'{domain}\r\n'.encode())
                while True:
                    data = sock.recv(1024)
                    if not data:
                        break
                    info += data.decode()
        except socket.error:
            pass
        finally:
            retry -= 1
            time.sleep(sleep_time)
    return info

def get_reginfomation(domain_name, suffix_info):
    info = whois_query(domain_name, suffix_info)
    if not info:
        with open('failure.txt', 'a') as file:
            file.write(f'{domain_name}.{suffix_info[0]} 查询失败\n')
        print(f'域名{domain_name}.{suffix_info[0]}查询失败, 已保存在 failure.txt 文件中')
        return

    if suffix_info[2] in info:
        with open('success.txt', 'a') as file:
            file.write(f'{domain_name}.{suffix_info[0]}\n')
        print(f'域名{domain_name}.{suffix_info[0]} 未注册, 已保存在 success.txt 文件中')
    else:
        print(f'域名{domain_name}.{suffix_info[0]} 已注册')

def input_and_filter_domains(domain_dictionary, domain_name_length):
    domain_list = []
    with open(domain_dictionary, 'r') as file:
        for line in file:
            if line and len(line.strip()) < domain_name_length:
                domain_list.append(line.strip())
    return domain_list

def input_suffix_and_dict():
    suffix = input("输入域名后缀 (com,de,ee...):")
    dictionary = input("输入字典名 (2c,3c,3wd...):")
    length = int(input("输入过滤长度 (2,3,4...):"))
    return suffix, dictionary, length

def save_raw_data(domain, info):
    with open('raw.txt', 'a') as file:
        file.write(f'--- {domain} ---\n{info}\n\n')

def manual_query(suffix_list):
    full_domain = input("输入完整域名 (example.com):")
    domain_parts = full_domain.split('.')
    domain_name = '.'.join(domain_parts[:-1])
    suffix = domain_parts[-1]

    suffix_info = next((item for item in suffix_list if item[0] == suffix), None)
    if not suffix_info:
        print(f"未找到后缀 '{suffix}' 的WHOIS服务器信息。")
        return

    info = whois_query(domain_name, suffix_info)
    save_raw_data(full_domain, info)
    if info:
        print(f'域名{full_domain}的查询结果已保存在 raw.txt 中')
    else:
        print(f'无法查询域名{full_domain}')

def process_domains(domain, suffix_list):
    for suffix_info in suffix_list:
        while threading.active_count() > max_thread:
            time.sleep(sleep_time)
        threading.Thread(target=get_reginfomation, args=(domain, suffix_info)).start()

def main_menu():
    print('菜单''\n\n'
          + '1. 输入 域名 检测所有后缀能否注册\n'
          + '2. 指定 字典 检测所有后缀能否注册\n'
          + '3. 指定 后缀 和 字典 检测能否注册\n'
          + '4. 手动输入域名和后缀进行查询\n'
          + '0. 结束' + '\n'
          + '请输入:', end="")
    return input()

if __name__ == '__main__':
    clear()
    choice = main_menu()
    suffix_list = get_suffix_nic_whois()

    if choice == "0":
        clear()
        sys.exit()

    if choice == "1":
        domain = input("输入域名, 无需后缀:")
        process_domains(domain, suffix_list)

    elif choice == "2":
        dictionary = input("输入字典名 (2c,3c,3wd...):")
        length = int(input("输入过滤长度 (2,3,4...)"))
        domains = input_and_filter_domains(dictionary, length)
        for domain in domains:
            process_domains(domain, suffix_list)

    elif choice == "3":
        suffix, dictionary, length = input_suffix_and_dict()
        if suffix in [s[0] for s in suffix_list]:
            domains = input_and_filter_domains(dictionary, length)
            suffix_info = next(s for s in suffix_list if s[0] == suffix)
            for domain in domains:
                process_domains(domain, [suffix_info])
        else:
            print(f'域名后缀 {suffix} 未在 suffix_nic_whois 中配置')

    elif choice == "4":
        manual_query(suffix_list)

    else:
        print("\n输入值未列出 👋\n ")