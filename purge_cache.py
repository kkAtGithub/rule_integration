import os
import urllib.request

URL_PREFIX = "https://purge.jsdelivr.net/gh/kkAtGithub/rule_integration@main/"


def purge_cache(url):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req) as response:
        print(response.read())


def find_result(list_dir):
    for path, dir_list, file_list in list_dir:
        for file in file_list:
            url = f'{URL_PREFIX}{path}/{file}'.replace('\\', '/')
            purge_cache(url)


if __name__ == '__main__':
    find_result(os.walk('results'))

