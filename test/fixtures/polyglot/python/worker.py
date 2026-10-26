def interpret_user_payload(payload):
    return eval(payload)


def swallow_shutdown(operation):
    try:
        return operation()
    except:
        return None


def membership_filter(values, allowed):
    result = []
    for value in values:
        if value in allowed:
            result.append(value)
    return result
