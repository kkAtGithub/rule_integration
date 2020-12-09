import os
import shutil
from urllib.request import Request, urlopen

FILTER_RESULT = {}
REWRITE_RESULT = {}

SPECIAL_RULE = []


def read_list(url_list_2b, file_name_2b='', src_mark_flag=True):
    global FILTER_RESULT, REWRITE_RESULT
    result = {}
    hostname = {}
    for list_url in url_list_2b:
        list_url = list_url.strip()
        if list_url.startswith('http'):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                                  ' AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/86.0.4240.111 Safari/537.36'}
                req = Request(list_url, headers=headers)
                response_list = urlopen(req).read()
                response_list = str(response_list, encoding='UTF-8').split('\n')
                if src_mark_flag:
                    result[f'# {list_url}'] = None
                for line_list in response_list:
                    useless = False
                    line_list = line_list.encode('ascii', errors='ignore').decode('ascii').strip()
                    if not line_list.startswith('#'):
                        if file_name_2b.endswith('Filter_2B.url'):
                            line_list = line_list.replace('AdBlock', 'REJECT').replace(' ', '')
                            line_list = line_list.replace('reject', 'REJECT').replace(' ', '')
                            if not (line_list.startswith('DOMAIN')
                                    or line_list.startswith('DOMAIN-KEYWORD')
                                    or line_list.startswith('USER-AGENT')
                                    or line_list.startswith('IP-CIDR')
                                    or line_list.startswith('HOST')
                                    or line_list.startswith('HOST-SUFFIX')
                                    or line_list.startswith('HOST-KEYWORD')
                                    or line_list.startswith('SRC-IP-CIDR')
                                    or line_list.startswith('GEOIP')
                                    or line_list.startswith('PROCESS-NAME')
                                    or line_list.startswith('DST-PORT')
                                    or line_list.startswith('SRC-PORT')
                                    or line_list.startswith('MATCH')):
                                continue
                            if line_list in FILTER_RESULT:
                                continue
                            else:
                                FILTER_RESULT[line_list] = None
                        if file_name_2b.endswith('Rewrite_2B.url'):
                            if line_list.startswith('hostname = '):
                                line_hostname = line_list[10:line_list.__len__()]
                                line_hostname_list = line_hostname.split(',')
                                for entry_hostname in line_hostname_list:
                                    useless_hostname = False
                                    for special_rule in SPECIAL_RULE:
                                        if (not (special_rule in list_url)) and (special_rule in entry_hostname):
                                            useless_hostname = True
                                            break
                                    if not useless_hostname:
                                        hostname[entry_hostname.strip()] = None
                                continue
                            for special_rule in SPECIAL_RULE:
                                if (not (special_rule in list_url)) and (special_rule in line_list):
                                    useless = True
                                    break
                            if line_list in REWRITE_RESULT:
                                continue
                            else:
                                REWRITE_RESULT[line_list] = None
                        if useless:
                            continue
                        else:
                            result[line_list] = None
            except Exception as e:
                print(f'Error: Fail to get rule from {list_url} \n {e} ')
    if len(hostname) > 0:
        result_hostname = 'hostname = '
        for entry_hostname in hostname.keys():
            result_hostname = f'{result_hostname}{entry_hostname},'
        result_hostname = result_hostname.rstrip(',')
        result[result_hostname] = None
    return result


def read_qx_sr_list(qx_sr_dir_path, qx_sr_dir):
    qx_sr_2b_dir_input = os.walk(f'{qx_sr_dir_path}/{qx_sr_dir}')
    qx_sr_url_list = []
    for qx_sr_path, qx_sr_dir_list, qx_sr_file_list in qx_sr_2b_dir_input:
        for qx_sr_file_name in qx_sr_file_list:
            os.system(f'echo {qx_sr_file_name}')
            if not qx_sr_file_name.endswith('_2B.url'):
                SPECIAL_RULE.append(qx_sr_file_name)
                with open(f'{qx_sr_dir_path}/{qx_sr_dir}/{qx_sr_file_name}', mode='r', encoding='UTF-8') as qx_sr_file_content:
                    for qx_sr_url_list_entry in qx_sr_file_content.readlines():
                        qx_sr_url_list.append(qx_sr_url_list_entry)
        qx_sr_file_name_new = f'{qx_sr_dir}_integrated.list'
        if not os.path.exists('result/qx'):
            os.mkdir('result/qx')
        with open(f'result/qx/{qx_sr_file_name_new}', mode='w', encoding='UTF-8') as qx_sr_results:
            qx_sr_dic_results = read_list(qx_sr_url_list, 'Rewrite_2B.url')
            for qx_sr_key in qx_sr_dic_results.keys():
                qx_sr_results.write(f'{qx_sr_key}\n')
            qx_sr_results.flush()


def read_sc_list(sc_dir_path, sc_dir):
    sc_2b_dir_input = os.walk(f'{sc_dir_path}/{sc_dir}')
    for sc_path, sc_dir_list, sc_file_list in sc_2b_dir_input:
        for sc_file_name in sc_file_list:
            os.system(f'echo {sc_file_name}')
            if not sc_file_name.endswith('_2B.url'):
                sc_url_list = []
                with open(f'{sc_dir_path}/{sc_dir}/{sc_file_name}', mode='r', encoding='UTF-8') as sc_file_content:
                    for sc_url_list_entry in sc_file_content.readlines():
                        sc_url_list.append(sc_url_list_entry)
                    if not os.path.exists('result/rules'):
                        os.mkdir('result/rules')
                    if not os.path.exists('result/clash'):
                        os.mkdir('result/clash')
                    with open(f'result/rules/{sc_file_name}_integrated.list', mode='w', encoding='UTF-8') as sc_results:
                        with open(f'result/clash/{sc_file_name}_converted.yaml', mode='w', encoding='UTF-8') as scd_results:
                            scd_results.write(f'payload:\n  # > {sc_file_name}\n')
                            sc_dic_results = read_list(sc_url_list, src_mark_flag=False)
                            for sc_key in sc_dic_results.keys():
                                sc_results.write(f'{sc_key}\n')
                                if (sc_key.startswith('DOMAIN')
                                        or sc_key.startswith('DOMAIN-KEYWORD')
                                        or sc_key.startswith('DOMAIN-SUFFIX')
                                        or sc_key.startswith('IP-CIDR')
                                        or sc_key.startswith('SRC-IP-CIDR')
                                        or sc_key.startswith('GEOIP')
                                        or sc_key.startswith('PROCESS-NAME')
                                        or sc_key.startswith('DST-PORT')
                                        or sc_key.startswith('SRC-PORT')
                                        or sc_key.startswith('MATCH')):
                                    scd_results.write(f'  - {sc_key}\n')
                            scd_results.flush()
                        sc_results.flush()


special_dir_switch = {
    'QX_SPECIAL_RULE': read_qx_sr_list,
    'SCRIPT_CONVERSION': read_sc_list,
}

if __name__ == '__main__':
    list_2b_dir_input = os.walk('list_2B')
    if not os.path.exists('result'):
        os.mkdir('result')
    for path, dir_list, file_list in list_2b_dir_input:
        for special_dir in dir_list:
            special_dir_switch[special_dir](path, special_dir)
        for file_name in file_list:
            os.system(f'echo {file_name}')
            if file_name.endswith('_2B.url'):
                url_list = []
                with open(f'{path}/{file_name}', mode='r', encoding='UTF-8') as file_content:
                    for url_list_entry in file_content.readlines():
                        url_list.append(url_list_entry)
                    file_name_new = file_name[0:file_name.index('_2B.url')] + '_integrated.list'
                    if not os.path.exists('result/qx'):
                        os.mkdir('result/qx')
                    with open(f'result/qx/{file_name_new}', mode='w', encoding='UTF-8') as results:
                        dic_results = read_list(url_list, file_name)
                        for key in dic_results.keys():
                            results.write(f'{key}\n')
                        results.flush()
