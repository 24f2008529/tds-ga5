import os

def resolves_inside(path, root):
    # where does this path actually land?
    full = os.path.normpath(os.path.join(root, path)) if not os.path.isabs(path) \
           else os.path.normpath(path)
    root = os.path.normpath(root)
    return full == root or full.startswith(root + os.sep)

def check(call, cfg):
    tool = call["tool"]; args = call["arguments"]
    if tool == "read_file":
        p = os.path.normpath(args["path"])
        if any(p.endswith(s) or s in p for s in cfg["secret_files"]):
            return {"decision": "block"}
        return {"decision": "allow"}
    if tool == "write_file":
        return {"decision": "allow" if resolves_inside(args["path"], cfg["write_dir"])
                else "block"}
    if tool in ("network", "fetch", "http"):
        host = extract_host(args["url"])
        return {"decision": "allow" if host in cfg["allowed_domains"] else "block"}
    return {"decision": "allow"}
