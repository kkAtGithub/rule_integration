import os
from urllib.request import Request, urlopen

FILE_NAME_DELIMITER = '_'
FILE_NAME_SUFFIX = '_TBD.url'
FILTER_FILE_NAME_SUFFIX = 'Filter_TBD.url'
REWRITE_FILE_NAME_SUFFIX = 'Rewrite_TBD.url'
RULE_SET_FILE_NAME_SUFFIX = 'RuleSet_TBD.url'
RESULTS_DIR = 'results'
RESULT_FILE_NAME_SUFFIX = 'Integrated.list'
PROVIDER_FILE_NAME_SUFFIX = 'Provider.yaml'

FILTER_RESULT = {}
REWRITE_RESULT = {}

FILTER_SR = []
REWRITE_SR = []
EXCLUDE_LIST = []


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
                    line_list = line_list.encode('ascii', errors='ignore').decode('ascii').strip()
                    if line_list.__len__() > 0 and (not line_list.startswith('#')):
                        ex_flag = False
                        qx_sr_flag = False
                        for ex_list_entry in EXCLUDE_LIST:
                            if ex_list_entry in line_list:
                                ex_flag = True
                                break
                        if ex_flag:
                            continue
                        if file_name_2b.endswith(FILTER_FILE_NAME_SUFFIX):
                            if (line_list.startswith('DOMAIN')
                                    or line_list.startswith('DOMAIN-KEYWORD')
                                    or line_list.startswith('USER-AGENT')
                                    or line_list.startswith('IP-CIDR')
                                    or line_list.startswith('HOST')
                                    or line_list.startswith('HOST-SUFFIX')
                                    or line_list.startswith('HOST-KEYWORD')):
                                if file_name_2b.startswith('Anti_AD'):
                                    line_list = rule_processor(line_list, action='REJECT')
                                for special_rule in FILTER_SR:
                                    if (not (special_rule in list_url)) and (special_rule in line_list):
                                        qx_sr_flag = True
                                        break
                                if line_list in FILTER_RESULT:
                                    continue
                                else:
                                    FILTER_RESULT[line_list] = None
                            else:
                                continue
                        elif file_name_2b.endswith(REWRITE_FILE_NAME_SUFFIX):
                            if line_list.startswith('hostname ='):
                                line_hostname = line_list[10:line_list.__len__()]
                                line_hostname_list = line_hostname.split(',')
                                for entry_hostname in line_hostname_list:
                                    useless_hostname = False
                                    for special_rule in REWRITE_SR:
                                        if (not (special_rule in list_url)) and (special_rule in entry_hostname):
                                            useless_hostname = True
                                            break
                                    if not useless_hostname:
                                        hostname[entry_hostname.strip()] = None
                                continue
                            for special_rule in REWRITE_SR:
                                if (not (special_rule in list_url)) and (special_rule in line_list):
                                    qx_sr_flag = True
                                    break
                            snippet = line_list.split(maxsplit=1)
                            if snippet[0] in REWRITE_RESULT:
                                if snippet[1].__len__() < REWRITE_RESULT[snippet[0]].__len__():
                                    continue
                            REWRITE_RESULT[snippet[0]] = snippet[1]
                        elif file_name_2b.endswith(RULE_SET_FILE_NAME_SUFFIX):
                            line_list = rule_processor(line_list)
                        if qx_sr_flag:
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
    qx_sr_filter_url_list = []
    qx_sr_rewrite_url_list = []
    qx_sr_results_path = path_processor(qx_sr_dir_path)
    if not os.path.exists(f'{RESULTS_DIR}{qx_sr_results_path}/qx'):
        os.makedirs(f'{RESULTS_DIR}{qx_sr_results_path}/qx')
    qx_sr_2b_dir_input = os.walk(f'{qx_sr_dir_path}/{qx_sr_dir}')
    for qx_sr_path, qx_sr_dir_list, qx_sr_file_list in qx_sr_2b_dir_input:
        for qx_sr_file_name in qx_sr_file_list:
            os.system(f'echo {qx_sr_file_name}')
            if qx_sr_file_name.endswith(FILE_NAME_SUFFIX):
                qx_sr_url_list = []
                with open(f'{qx_sr_dir_path}/{qx_sr_dir}/{qx_sr_file_name}', mode='r', encoding='UTF-8') as qx_sr_file_content:
                    for qx_sr_url_list_entry in qx_sr_file_content.readlines():
                        qx_sr_url_list.append(qx_sr_url_list_entry)
                if qx_sr_file_name.endswith(REWRITE_FILE_NAME_SUFFIX):
                    REWRITE_SR.append(qx_sr_file_name[0:qx_sr_file_name.index(FILE_NAME_DELIMITER)])
                    qx_sr_rewrite_url_list = qx_sr_rewrite_url_list + qx_sr_url_list
                elif qx_sr_file_name.endswith(FILTER_FILE_NAME_SUFFIX):
                    FILTER_SR.append(qx_sr_file_name[0:qx_sr_file_name.index(FILE_NAME_DELIMITER)])
                    qx_sr_filter_url_list = qx_sr_filter_url_list + qx_sr_url_list
    if qx_sr_rewrite_url_list.__len__() > 0:
        with open(f'{RESULTS_DIR}{qx_sr_results_path}/qx/QX_SR_Rewrite_{RESULT_FILE_NAME_SUFFIX}', mode='w', encoding='UTF-8') as qx_sr_results:
            qx_sr_dic_results = read_list(qx_sr_rewrite_url_list, REWRITE_FILE_NAME_SUFFIX)
            for qx_sr_key in qx_sr_dic_results.keys():
                qx_sr_results.write(f'{qx_sr_key}\n')
            qx_sr_results.flush()
    if qx_sr_filter_url_list.__len__() > 0:
        with open(f'{RESULTS_DIR}{qx_sr_results_path}/qx/QX_SR_Filter_{RESULT_FILE_NAME_SUFFIX}', mode='w', encoding='UTF-8') as qx_sr_results:
            qx_sr_dic_results = read_list(qx_sr_filter_url_list, FILTER_FILE_NAME_SUFFIX)
            for qx_sr_key in qx_sr_dic_results.keys():
                qx_sr_results.write(f'{qx_sr_key}\n')
            qx_sr_results.flush()
    return


def read_qx_nr_list(qx_nr_dir_path, qx_nr_dir):
    qx_nr_results_path = path_processor(qx_nr_dir_path)
    if not os.path.exists(f'{RESULTS_DIR}{qx_nr_results_path}/qx'):
        os.makedirs(f'{RESULTS_DIR}{qx_nr_results_path}/qx')
    qx_nr_2b_dir_input = os.walk(f'{qx_nr_dir_path}/{qx_nr_dir}')
    for qx_nr_path, qx_nr_dir_list, qx_nr_file_list in qx_nr_2b_dir_input:
        for qx_nr_file_name in qx_nr_file_list:
            os.system(f'echo {qx_nr_file_name}')
            if qx_nr_file_name.endswith(FILE_NAME_SUFFIX):
                qx_nr_url_list = []
                with open(f'{qx_nr_path}/{qx_nr_file_name}', mode='r', encoding='UTF-8') as qx_nr_file_content:
                    for qx_nr_url_list_entry in qx_nr_file_content.readlines():
                        qx_nr_url_list.append(qx_nr_url_list_entry)
                qx_nr_file_name_new = f'{qx_nr_file_name[0:qx_nr_file_name.index(FILE_NAME_SUFFIX)]}_{RESULT_FILE_NAME_SUFFIX}'
                with open(f'{RESULTS_DIR}{qx_nr_results_path}/qx/{qx_nr_file_name_new}', mode='w', encoding='UTF-8') as qx_nr_results:
                    qx_nr_dic_results = read_list(qx_nr_url_list, file_name_2b=qx_nr_file_name)
                    for qx_nr_key in qx_nr_dic_results.keys():
                        qx_nr_results.write(f'{qx_nr_key}\n')
                    qx_nr_results.flush()
    return


def read_rs_list(rs_dir_path, rs_dir):
    rs_results_path = path_processor(rs_dir_path)
    if not os.path.exists(f'{RESULTS_DIR}{rs_results_path}/rules'):
        os.makedirs(f'{RESULTS_DIR}{rs_results_path}/rules')
    if not os.path.exists(f'{RESULTS_DIR}{rs_results_path}/clash'):
        os.makedirs(f'{RESULTS_DIR}{rs_results_path}/clash')
    rs_2b_dir_input = os.walk(f'{rs_dir_path}/{rs_dir}')
    for rs_path, rs_dir_list, rs_file_list in rs_2b_dir_input:
        for rs_file_name in rs_file_list:
            os.system(f'echo {rs_file_name}')
            if rs_file_name.endswith(RULE_SET_FILE_NAME_SUFFIX):
                rs_url_list = []
                with open(f'{rs_dir_path}/{rs_dir}/{rs_file_name}', mode='r', encoding='UTF-8') as rs_file_content:
                    for rs_url_list_entry in rs_file_content.readlines():
                        rs_url_list.append(rs_url_list_entry)
                    rs_file_name_fragment = rs_file_name[0:rs_file_name.index(FILE_NAME_SUFFIX)]
                    with open(f'{RESULTS_DIR}{rs_results_path}/rules/{rs_file_name_fragment}_{RESULT_FILE_NAME_SUFFIX}', mode='w', encoding='UTF-8') as rs_results:
                        with open(f'{RESULTS_DIR}{rs_results_path}/clash/{rs_file_name_fragment}_{PROVIDER_FILE_NAME_SUFFIX}', mode='w', encoding='UTF-8') as scd_results:
                            scd_results.write(f'payload:\n  # > {rs_file_name}\n')
                            rs_dic_results = read_list(rs_url_list, file_name_2b=rs_file_name, src_mark_flag=False)
                            for rs_key in rs_dic_results.keys():
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
    return


special_dir_switch = {
    'QX_NR': read_qx_nr_list,
    'QX_SR': read_qx_sr_list,
    'RULE_SET': read_rs_list
}


def rule_processor(rule_line, action=''):
    rule_line_fragment = rule_line.split(',')
    if rule_line_fragment.__len__() > 2 and (not rule_line_fragment[2] == 'no-resolve'):
        if action.__len__() > 0:
            rule_line_fragment[2] = action
        else:
            rule_line_fragment.pop(2)
    elif action.__len__() > 0:
        rule_line_fragment.insert(2, action)
    rule_line_new = ''
    for fragment in rule_line_fragment:
        rule_line_new = f'{rule_line_new}{fragment.strip()},'
    return rule_line_new[0:rule_line_new.__len__() - 1]


def path_processor(src_path):
    if '/' in src_path:
        return src_path[src_path.index('/'):src_path.__len__()]
    if '\\' in src_path:
        return src_path[src_path.index('\\'):src_path.__len__()].replace('\\', '/')
    return ''


if __name__ == '__main__':
    list_2b_dir_input = os.walk('url_TBD')
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)
    for path, dir_list, file_list in list_2b_dir_input:
        if os.path.exists(f'{path}/EXCLUDE'):
            with open(f'{path}/EXCLUDE', mode='r', encoding='UTF-8') as ex_file_content:
                for ex_url_list_entry in ex_file_content.readlines():
                    EXCLUDE_LIST.append(ex_url_list_entry.strip())
        dir_list.sort(reverse=True)
        for special_dir in dir_list:
            # noinspection PyBroadException
            try:
                special_dir_switch[special_dir](path, special_dir)
            except Exception as dir_error:
                continue
