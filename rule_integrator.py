import os
from urllib.request import Request, urlopen

RESULT = ''

SPECIAL_RULE = ('bilibili', 'zhihu', 'smzdm')


def read_list(file_name_2b):
    result = ''
    hostname = {}

    with open(f'list_2B/{file_name_2b}', mode='r', encoding='UTF-8') as list_2b:
        for list_url in list_2b.readlines():
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
                                if not (line_list.startswith('DOMAIN') or line_list.startswith(
                                        'DOMAIN-SUFFIX') or line_list.startswith(
                                    'DOMAIN-KEYWORD') or line_list.startswith('USER-AGENT') or line_list.startswith(
                                    'IP-CIDR') or line_list.startswith('HOST') or line_list.startswith(
                                    'HOST-SUFFIX') or line_list.startswith('HOST-KEYWORD')):
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
                                        print(list_url)
                                        print(special_rule)
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


if __name__ == '__main__':
    list_2b_dir_input = os.walk(f'list_2B')
    if not os.path.exists(f'result'):
        os.mkdir(f'result')
    for path, dir_list, file_list in list_2b_dir_input:
        for file_name in file_list:
            os.system(f'echo {file_name}')
            if file_name.endswith('.url'):
                RESULT = read_list(file_name)
                file_name_new = file_name[0:file_name.index('_')] + '_integrated.list'
                with open(f'result/{file_name_new}', mode='w', encoding='UTF-8') as results:
                    results.write(RESULT)
                    results.flush()
