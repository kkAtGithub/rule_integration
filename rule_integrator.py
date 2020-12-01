import os
from urllib.request import Request, urlopen

RESULT = ''

SPECIAL_RULE = []


def read_list(file_name_2b, url_list_2b):
    result = ''
    hostname = {}
    for list_url in url_list_2b:
        list_url = list_url.strip()
        if not ((list_url.__len__() == 0) or list_url.startswith('#')):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
                                  ' AppleWebKit/537.36 (KHTML, like Gecko) '
                                  'Chrome/86.0.4240.111 Safari/537.36'}
                req = Request(list_url, headers=headers)
                response_list = urlopen(req).read()
                response_list = str(response_list, encoding='UTF-8').split('\n')
                result = f'{result}\n# {list_url}'
                for line_list in response_list:
                    useless = False
                    line_list = line_list.strip().encode('ascii', errors='ignore').decode('ascii')
                    if not line_list.startswith('#'):
                        if file_name_2b.startswith('Filter_2B'):
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
                        if file_name_2b.startswith('Rewrite_2B'):
                            if line_list.startswith('hostname = '):
                                line_hostname = line_list[10:line_list.__len__()].strip()
                                line_hostname_list = line_hostname.split(',')
                                for entry_hostname in line_hostname_list:
                                    hostname[entry_hostname.strip()] = ','
                                continue
                            for special_rule in SPECIAL_RULE:
                                if (not (special_rule in list_url)) and (special_rule in line_list):
                                    useless = True
                                    break
                        if line_list in result or useless:
                            continue
                        else:
                            result = f'{result}\n{str(line_list)}'
                result = f'{result}\n'
            except Exception as e:
                print(f'Error: Fail to get rule from {list_url} \n {e} ')
    if len(hostname) > 0:
        result_hostname = 'hostname = '
        for entry_hostname in hostname.keys():
            result_hostname = f'{result_hostname}{entry_hostname},'
        result_hostname = result_hostname.rstrip(',')
        result = f'{result_hostname}\n{result}'
    return f'{result}\n'


def read_sr_list(path, sr_dir):
    sr_2b_dir_input = os.walk(f'{path}/{sr_dir}')
    sr_url_list = []
    for sr_path, sr_dir_list, sr_file_list in sr_2b_dir_input:
        for sr_file_name in sr_file_list:
            os.system(f'echo {sr_file_name}')
            if not sr_file_name.endswith('_2B.url'):
                SPECIAL_RULE.append(sr_file_name)
                with open(f'{path}/{sr_dir}/{sr_file_name}', mode='r', encoding='UTF-8') as sr_file_content:
                    for sr_url_list_entry in sr_file_content.readlines():
                        sr_url_list.append(sr_url_list_entry)
        sr_file_name_new = f'{sr_dir}_integrated.list'
        with open(f'result/{sr_file_name_new}', mode='w', encoding='UTF-8') as sr_results:
            sr_results.write(read_list('Rewrite_2B', sr_url_list))
            sr_results.flush()


if __name__ == '__main__':
    list_2b_dir_input = os.walk('list_2B')
    if not os.path.exists('result'):
        os.mkdir('result')
    for path, dir_list, file_list in list_2b_dir_input:
        for special_dir in dir_list:
            read_sr_list(path, special_dir)
        for file_name in file_list:
            os.system(f'echo {file_name}')
            if file_name.endswith('_2B.url'):
                url_list = []
                with open(f'{path}/{file_name}', mode='r', encoding='UTF-8') as file_content:
                    for url_list_entry in file_content.readlines():
                        url_list.append(url_list_entry)
                    file_name_new = file_name[0:file_name.index('_')] + '_integrated.list'
                    with open(f'result/{file_name_new}', mode='w', encoding='UTF-8') as results:
                        results.write(read_list(file_name, url_list))
                        results.flush()
