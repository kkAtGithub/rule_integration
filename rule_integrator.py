import os
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
                                    or line_list.startswith('HOST-KEYWORD')):
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
            except Exception as get_fail:
                print(f'Error: Fail to get rule from {list_url} \n {get_fail} ')
    if len(hostname) > 0:
        result_hostname = 'hostname = '
        for entry_hostname in hostname.keys():
            result_hostname = f'{result_hostname}{entry_hostname},'
        result_hostname = result_hostname.rstrip(',')
        result[result_hostname] = None
    return result


def read_qx_sr_list(qx_sr_dir_path, qx_sr_dir):
    qx_sr_url_list = []
    qx_sr_results_path = path_processor(qx_sr_dir_path)
    qx_sr_2b_dir_input = os.walk(f'{qx_sr_dir_path}/{qx_sr_dir}')
    for qx_sr_path, qx_sr_dir_list, qx_sr_file_list in qx_sr_2b_dir_input:
        for qx_sr_file_name in qx_sr_file_list:
            os.system(f'echo {qx_sr_file_name}')
            if not qx_sr_file_name.endswith('_2B.url'):
                SPECIAL_RULE.append(qx_sr_file_name)
                with open(f'{qx_sr_dir_path}/{qx_sr_dir}/{qx_sr_file_name}', mode='r', encoding='UTF-8') as qx_sr_file_content:
                    for qx_sr_url_list_entry in qx_sr_file_content.readlines():
                        qx_sr_url_list.append(qx_sr_url_list_entry)
        qx_sr_file_name_new = f'{qx_sr_dir}_integrated.list'
        if not os.path.exists(f'result{qx_sr_results_path}/qx'):
            os.makedirs(f'result{qx_sr_results_path}/qx')
        with open(f'result{qx_sr_results_path}/qx/{qx_sr_file_name_new}', mode='w', encoding='UTF-8') as qx_sr_results:
            qx_sr_dic_results = read_list(qx_sr_url_list, 'Rewrite_2B.url')
            for qx_sr_key in qx_sr_dic_results.keys():
                qx_sr_results.write(f'{qx_sr_key}\n')
            qx_sr_results.flush()


def read_rs_list(rs_dir_path, rs_dir):
    ex_list = []
    rs_results_path = path_processor(rs_dir_path)
    if not os.path.exists(f'result{rs_results_path}/rules'):
        os.makedirs(f'result{rs_results_path}/rules')
    if not os.path.exists(f'result{rs_results_path}/clash'):
        os.makedirs(f'result{rs_results_path}/clash')
    if os.path.exists(f'{rs_dir_path}/{rs_dir}/EXCLUDE'):
        with open(f'{rs_dir_path}/{rs_dir}/EXCLUDE', mode='r', encoding='UTF-8') as ex_file_content:
            for ex_url_list_entry in ex_file_content.readlines():
                ex_list.append(ex_url_list_entry)
    rs_2b_dir_input = os.walk(f'{rs_dir_path}/{rs_dir}')
    for rs_path, rs_dir_list, rs_file_list in rs_2b_dir_input:
        for rs_file_name in rs_file_list:
            os.system(f'echo {rs_file_name}')
            if not (rs_file_name.endswith('_2B.url') or rs_file_name == 'EXCLUDE'):
                rs_url_list = []
                with open(f'{rs_dir_path}/{rs_dir}/{rs_file_name}', mode='r', encoding='UTF-8') as rs_file_content:
                    for rs_url_list_entry in rs_file_content.readlines():
                        rs_url_list.append(rs_url_list_entry)
                    with open(f'result{rs_results_path}/rules/{rs_file_name}_integrated.list', mode='w', encoding='UTF-8') as rs_results:
                        with open(f'result{rs_results_path}/clash/{rs_file_name}_converted.yaml', mode='w', encoding='UTF-8') as scd_results:
                            scd_results.write(f'payload:\n  # > {rs_file_name}\n')
                            rs_dic_results = read_list(rs_url_list, src_mark_flag=False)
                            for rs_key in rs_dic_results.keys():
                                ex_flag = False
                                for ex_list_entry in ex_list:
                                    if ex_list_entry in rs_key:
                                        ex_flag = True
                                        break
                                if not ex_flag:
                                    if (rs_key.startswith('DOMAIN')
                                            or rs_key.startswith('DOMAIN-KEYWORD')
                                            or rs_key.startswith('USER-AGENT')
                                            or rs_key.startswith('IP-CIDR')
                                            or rs_key.startswith('HOST')
                                            or rs_key.startswith('HOST-SUFFIX')
                                            or rs_key.startswith('HOST-KEYWORD')
                                            or rs_key.startswith('SRC-IP-CIDR')
                                            or rs_key.startswith('GEOIP')
                                            or rs_key.startswith('PROCESS-NAME')
                                            or rs_key.startswith('DST-PORT')
                                            or rs_key.startswith('SRC-PORT')
                                            or rs_key.startswith('MATCH')):
                                        rs_results.write(f'{rs_key}\n')
                                        if (rs_key.startswith('DOMAIN')
                                                or rs_key.startswith('DOMAIN-KEYWORD')
                                                or rs_key.startswith('DOMAIN-SUFFIX')
                                                or rs_key.startswith('IP-CIDR')
                                                or rs_key.startswith('SRC-IP-CIDR')
                                                or rs_key.startswith('GEOIP')
                                                or rs_key.startswith('PROCESS-NAME')
                                                or rs_key.startswith('DST-PORT')
                                                or rs_key.startswith('SRC-PORT')
                                                or rs_key.startswith('MATCH')):
                                            scd_results.write(f'  - {rs_key}\n')
                            scd_results.flush()
                        rs_results.flush()


special_dir_switch = {
    'QX_SR': read_qx_sr_list,
    'RULE_SET': read_rs_list,
}


def path_processor(src_path):
    print(src_path)
    if '/' in src_path:
        return src_path[src_path.index('/'):src_path.__len__()]
    if '\\' in src_path:
        return src_path[src_path.index('\\'):src_path.__len__()].replace('\\', '/')
    return ''


if __name__ == '__main__':
    list_2b_dir_input = os.walk('list_2B')
    if not os.path.exists('result'):
        os.makedirs('result')
    for path, dir_list, file_list in list_2b_dir_input:
        print(path, dir_list, file_list)
        results_path = path_processor(path)
        for special_dir in dir_list:
            try:
                special_dir_switch[special_dir](path, special_dir)
            except Exception as dir_error:
                continue
        for file_name in file_list:
            os.system(f'echo {file_name}')
            if file_name.endswith('_2B.url'):
                url_list = []
                with open(f'{path}/{file_name}', mode='r', encoding='UTF-8') as file_content:
                    for url_list_entry in file_content.readlines():
                        url_list.append(url_list_entry)
                    file_name_new = file_name[0:file_name.index('_2B.url')] + '_integrated.list'
                    if not os.path.exists(f'result{results_path}/qx'):
                        os.makedirs(f'result{results_path}/qx')
                    with open(f'result{results_path}/qx/{file_name_new}', mode='w', encoding='UTF-8') as results:
                        dic_results = read_list(url_list, file_name)
                        for key in dic_results.keys():
                            results.write(f'{key}\n')
                        results.flush()
