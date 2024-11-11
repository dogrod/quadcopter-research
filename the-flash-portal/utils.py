# Make JSON serializable
# Fix "Error in MAVLink listener: Object of type bytearray is not JSON serializable" when emit
def make_json_serializable(obj):
    if isinstance(obj, dict):
        return {k: make_json_serializable(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [make_json_serializable(v) for v in obj]
    elif isinstance(obj, bytearray):
        return list(obj)
    else:
        return obj