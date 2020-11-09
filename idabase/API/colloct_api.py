import csv
file = 'idapython_idc.csv'

f = open(file,'r')

reader = csv.reader(f)
head_row = next(reader)
for row in reader:
    old_api = row[0]
    new_api = row[1]
    if '0' in new_api or '\n' in new_api:
        new_api = ''
    elif 'lambda' in new_api:
        new_api = ''
    elif '.' not in new_api:
        new_api = ''
    elif '.' in new_api:
        if '(' in new_api:
            new_api = new_api[:new_api.index('(')]

        elif len(new_api.split('.')) > 2:
            new_api_module = new_api[:new_api.index(new_api.split('.')[1])]
            new_api_function =  new_api[new_api.index(new_api.split('.')[2]):]
            new_api = f'from {new_api_module} import {new_api_function}'
        elif len(new_api.split('.')) == 2:
            new_api_module = new_api.split('.')[0]
            new_api_function = new_api.split('.')[1]

            new_api = f'from {new_api_module} import {new_api_function}'
     # check old_api

    if '.' not in old_api:
        old_api = ''
    else:
        if '(' in old_api:
            old_api = old_api[:old_api.index('(')]
        if len(old_api.split('.')) > 2:
            old_api_module = old_api[:old_api.index(old_api.split('.')[1])]
            old_api_function = old_api[old_api.index(old_api.split('.')[2]):]
            old_api = f'from {old_api_module} import {old_api_function} as {new_api_function}'
        else:
            old_api_module = old_api.split('.')[0]
            old_api_function = old_api.split('.')[1]
            old_api = f'from {old_api_module} import {old_api_function} as {new_api_function}'

    new_api_list.append(new_api)
    old_api_list.append(old_api)


code = f'''
if idaapi.IDA_SDK_VERSION >= 740:
'''
for api in new_api_list:
    code += '    '
    code += api
    code += '\n'
code += 'else:\n'
for api in old_api_list:
    code += '    '
    code += api
    code += '\n'

with open('idabase_idc.py','w') as f:
    f.write(code)
