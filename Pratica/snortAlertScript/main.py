# -*- coding: utf-8 -*-

def interpretAlert(alert):
    # Esta função deve interpretar os dados do alerta do Snort

    splitted_alert = alert.split(' ')
    time_stamp = splitted_alert[1] + " " + splitted_alert[2] + " " + splitted_alert[3]
    type = ''
    snort_rule = False

    try:
        for part in splitted_alert:
            if part[0] == '{':
                type = part[1:-1]
                snort_rule = True
            else:
                pass
        if type != '':
            pass
        else:
            type = splitted_alert[5][:-1]
    except Exception as e:
        type = 'Not Found'


    print("Time: " + time_stamp)
    print("Type: " + type)

    if snort_rule:
        source = splitted_alert[-3]
        destiny = splitted_alert[-1]

        print("Source: " + source)
        print("Destination: " + destiny)
    print()

    pass

def read_log_file(file):
    log_file = open(file, 'r')
    logs = log_file.readlines()
    messages = []

    for log_line in logs:
        #message = log_line.split(' ')
        if "Msg:" not in log_line:
            pass
        else:
            messages.append(log_line)

    return messages

messages = read_log_file("logSnort2.txt")
for message in messages:
    interpretAlert(message)
